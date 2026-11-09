"""
MITRE ATT&CK Framework Validator
================================

Loads the Enterprise ATT&CK STIX bundle and answers questions about it:

- Is this technique ID real and currently active (not revoked or deprecated)?
- If it was revoked, which technique replaced it?
- Which tactics exist in this ATT&CK release, and what are their short names?
- Which ATT&CK version is this data?

Data sources
------------
By default the bundle is downloaded from the ``attack-stix-data`` repository (STIX 2.1),
which carries an ``x-mitre-collection`` object holding the real ATT&CK version and an
``index.json`` listing every versioned release. A local file (STIX 2.0 from ``mitre/cti``
or STIX 2.1) can be supplied for offline and air-gapped use.

Downloads are cached on disk (default ``$XDG_CACHE_HOME/navtogen`` or ``~/.cache/navtogen``)
and revalidated with ``If-None-Match`` so repeat runs do not re-download ~50MB. If the
network is unavailable a stale cache is used with a warning rather than failing.

When no data is loaded the validator falls back to format-only checks.
"""

import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from config import (
    HTTP_RETRY_ATTEMPTS,
    HTTP_RETRY_BACKOFF_FACTOR,
    HTTP_RETRY_STATUS_CODES,
    MITRE_ATTACK_INDEX_URL,
    MITRE_ATTACK_URL,
    MITRE_CACHE_DIR_NAME,
    MITRE_CACHE_HOURS,
    MITRE_ENTERPRISE_COLLECTION_NAME,
    MITRE_REQUEST_TIMEOUT,
    MAX_ATTACK_DATA_BYTES,
    VERSION,
)

# Optional imports with graceful degradation
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover - requests is a declared dependency
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)

_TECHNIQUE_FORMAT = re.compile(r'^T\d{4}(\.\d{3})?$')
_MAX_REVOKED_CHAIN = 10  # Guard against cycles in revoked-by chains


def default_cache_dir() -> Path:
    """Return the default on-disk cache directory for downloaded ATT&CK data."""
    base = os.environ.get('XDG_CACHE_HOME') or os.path.join(os.path.expanduser('~'), '.cache')
    return Path(base) / MITRE_CACHE_DIR_NAME


class MitreAttackValidator:
    """
    Validates technique and tactic identifiers against ATT&CK data.

    Attributes:
        valid_techniques: IDs of ACTIVE techniques (not revoked, not deprecated)
        valid_tactics: Tactic short names from x-mitre-tactic objects
        technique_metadata: Metadata for every technique seen, including inactive ones
        revoked_by: Maps a revoked technique ID to the ID that replaced it
        data_version: ATT&CK version of the loaded data (e.g. "20.1"), or None if unknown
        data_source: Where the data came from (URL or file path)
    """

    def __init__(self, cache_duration_hours: int = MITRE_CACHE_HOURS,
                 cache_dir: Optional[str] = None, use_cache: bool = True):
        self.valid_techniques: Set[str] = set()
        self.valid_tactics: Set[str] = set()
        self.tactic_names: Dict[str, str] = {}
        self.technique_metadata: Dict[str, Dict[str, Any]] = {}
        self.revoked_by: Dict[str, str] = {}
        self.data_version: Optional[str] = None
        self.data_source: Optional[str] = None
        self.last_update: Optional[datetime] = None
        self.using_stale_cache: bool = False
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir()
        self.use_cache = use_cache

        self._session: Optional["requests.Session"] = None
        if HAS_REQUESTS:
            self._configure_http_session()

        logger.debug(f"MITRE ATT&CK validator initialized (cache {cache_duration_hours}h, dir {self.cache_dir})")

    # ------------------------------------------------------------------
    # HTTP and caching
    # ------------------------------------------------------------------

    def _configure_http_session(self) -> None:
        """Configure an HTTP session that retries transient failures (429 and 5xx)."""
        self._session = requests.Session()

        retry_strategy = Retry(
            total=HTTP_RETRY_ATTEMPTS,
            status_forcelist=HTTP_RETRY_STATUS_CODES,
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=HTTP_RETRY_BACKOFF_FACTOR,
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        self._session.headers.update({
            'User-Agent': f'NavToGen/{VERSION} (ATT&CK coverage analysis)',
            'Accept': 'application/json',
        })

    @property
    def data_major_version(self) -> Optional[str]:
        """Major ATT&CK version as a string (e.g. "20" for "20.1"), or None if unknown."""
        if not self.data_version:
            return None
        return self.data_version.split('.')[0]

    def _cache_paths(self, url: str) -> Tuple[Path, Path]:
        key = hashlib.sha256(url.encode('utf-8')).hexdigest()[:16]
        return self.cache_dir / f"attack-{key}.json", self.cache_dir / f"attack-{key}.meta.json"

    def _read_cache_meta(self, meta_path: Path) -> Dict[str, Any]:
        try:
            return json.loads(meta_path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return {}

    def _write_cache(self, data_path: Path, meta_path: Path, content: bytes,
                     etag: Optional[str]) -> None:
        """Write cache files atomically; cache failures never fail the run."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.cache_dir), suffix='.tmp')
            with os.fdopen(fd, 'wb') as f:
                f.write(content)
            os.replace(tmp, data_path)
            meta_path.write_text(json.dumps({
                'etag': etag,
                'fetched_at': datetime.now().isoformat(),
            }), encoding='utf-8')
        except OSError as e:
            logger.warning(f"Could not write ATT&CK cache: {e}")

    def _resolve_versioned_url(self, version: str) -> Optional[str]:
        """
        Resolve a version such as "19" or "19.2" to a download URL using index.json.

        "19" selects the newest 19.x release. Returns None if it cannot be resolved.
        """
        try:
            response = self._session.get(MITRE_ATTACK_INDEX_URL, timeout=MITRE_REQUEST_TIMEOUT)
            if not response.ok:
                logger.error(f"Could not fetch ATT&CK version index: HTTP {response.status_code}")
                return None
            index = response.json()
        except Exception as e:
            logger.error(f"Could not fetch ATT&CK version index: {e}")
            return None

        for collection in index.get('collections', []):
            if collection.get('name') != MITRE_ENTERPRISE_COLLECTION_NAME:
                continue
            # Versions are listed newest first
            for entry in collection.get('versions', []):
                v = str(entry.get('version', ''))
                if v == version or v.startswith(version + '.'):
                    return entry.get('url')
        logger.error(f"ATT&CK version '{version}' not found in the version index")
        return None

    def fetch_mitre_data(self, force_refresh: bool = False, version: Optional[str] = None) -> bool:
        """
        Load ATT&CK data from the cache or the network.

        Args:
            force_refresh: Ignore a fresh cache and revalidate with the server
            version: Optional ATT&CK version ("19" or "19.2") to load instead of the latest

        Returns:
            bool: True if data is loaded (possibly from a stale cache), False otherwise
        """
        if not force_refresh and self._is_cache_valid() and (
                version is None or (self.data_version or '').split('.')[0] == version.split('.')[0]):
            logger.debug("In-memory ATT&CK data is still valid")
            return True

        if not HAS_REQUESTS or not self._session:
            logger.warning("Requests library not available. Cannot fetch ATT&CK data.")
            return False

        url = MITRE_ATTACK_URL
        if version:
            url = self._resolve_versioned_url(version)
            if not url:
                return False

        data_path, meta_path = self._cache_paths(url)
        meta = self._read_cache_meta(meta_path) if (self.use_cache and data_path.exists()) else {}

        # Fresh on-disk cache: no network round trip at all
        if meta.get('fetched_at') and not force_refresh:
            try:
                age = datetime.now() - datetime.fromisoformat(meta['fetched_at'])
                if age < self.cache_duration:
                    logger.info(f"Using cached ATT&CK data ({age.total_seconds() / 3600:.1f}h old)")
                    return self._load_from_path(data_path, source=f"cache:{url}")
            except ValueError:
                pass

        headers = {}
        if meta.get('etag'):
            headers['If-None-Match'] = meta['etag']

        try:
            logger.info(f"Fetching ATT&CK data from {url}")
            response = self._session.get(url, timeout=MITRE_REQUEST_TIMEOUT, headers=headers)

            if response.status_code == 304 and data_path.exists():
                logger.info("ATT&CK data unchanged (HTTP 304); using cache")
                self._write_cache(data_path, meta_path, data_path.read_bytes(), meta.get('etag'))
                return self._load_from_path(data_path, source=f"cache:{url}")

            if not response.ok:
                logger.error(f"Failed to fetch ATT&CK data: HTTP {response.status_code}")
                return self._fall_back_to_stale_cache(data_path, url)

            if len(response.content) > MAX_ATTACK_DATA_BYTES:
                logger.error("ATT&CK data download exceeds the size limit; refusing to parse it")
                return False

            try:
                bundle = json.loads(response.content)
            except ValueError as e:
                logger.error(f"Invalid JSON in ATT&CK data: {e}")
                return self._fall_back_to_stale_cache(data_path, url)

            if not self._process_attack_data(bundle):
                logger.error("Failed to process ATT&CK data")
                return self._fall_back_to_stale_cache(data_path, url)

            self.data_source = url
            self.last_update = datetime.now()
            self.using_stale_cache = False
            if self.use_cache:
                self._write_cache(data_path, meta_path, response.content, response.headers.get('ETag'))
            self._log_loaded()
            return True

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching ATT&CK data: {e}")
            return self._fall_back_to_stale_cache(data_path, url)
        except Exception as e:
            logger.error(f"Unexpected error fetching ATT&CK data: {e}")
            return False

    def _fall_back_to_stale_cache(self, data_path: Path, url: str) -> bool:
        if self.use_cache and data_path.exists():
            logger.warning("Using STALE cached ATT&CK data because the download failed")
            if self._load_from_path(data_path, source=f"stale-cache:{url}"):
                self.using_stale_cache = True
                return True
        return False

    def load_from_file(self, file_path: str) -> bool:
        """Load ATT&CK data from a local STIX bundle (STIX 2.0 or 2.1). Used for offline runs."""
        return self._load_from_path(Path(file_path), source=str(file_path))

    def _load_from_path(self, path: Path, source: str) -> bool:
        try:
            if path.stat().st_size > MAX_ATTACK_DATA_BYTES:
                logger.error(f"ATT&CK data file too large: {path}")
                return False
            with open(path, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
        except (OSError, ValueError) as e:
            logger.error(f"Could not read ATT&CK data from {path}: {e}")
            return False

        if not self._process_attack_data(bundle):
            return False

        self.data_source = source
        self.last_update = datetime.now()
        self._log_loaded()
        return True

    def _log_loaded(self) -> None:
        logger.info(
            f"ATT&CK data loaded: version {self.data_version or 'unknown'}, "
            f"{len(self.valid_techniques)} active techniques, {len(self.valid_tactics)} tactics, "
            f"{len(self.revoked_by)} revoked techniques with replacements"
        )

    def _is_cache_valid(self) -> bool:
        """True if data is already loaded in memory and is younger than the cache duration."""
        if not self.last_update or not self.valid_techniques:
            return False
        return (datetime.now() - self.last_update) < self.cache_duration

    # ------------------------------------------------------------------
    # Parsing the STIX bundle
    # ------------------------------------------------------------------

    @staticmethod
    def _attack_id(obj: Dict[str, Any]) -> Optional[str]:
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None

    def _process_attack_data(self, attack_data: Any) -> bool:
        """
        Build validation structures from a STIX bundle.

        State is replaced only if parsing succeeds, so a failed load never leaves the
        validator half-populated.
        """
        if not isinstance(attack_data, dict) or not isinstance(attack_data.get('objects'), list):
            logger.error("Invalid ATT&CK data structure: missing 'objects' list")
            return False

        valid_techniques: Set[str] = set()
        valid_tactics: Set[str] = set()
        tactic_names: Dict[str, str] = {}
        metadata: Dict[str, Dict[str, Any]] = {}
        id_by_stix: Dict[str, str] = {}
        revoked_refs: Dict[str, str] = {}
        version: Optional[str] = None

        try:
            for obj in attack_data['objects']:
                obj_type = obj.get('type')

                if obj_type == 'attack-pattern':
                    technique_id = self._attack_id(obj)
                    if not technique_id or not technique_id.startswith('T'):
                        continue

                    revoked = bool(obj.get('revoked', False))
                    deprecated = bool(obj.get('x_mitre_deprecated', False))
                    id_by_stix[obj.get('id', '')] = technique_id

                    tactics = [p.get('phase_name', '').replace('_', '-')
                               for p in obj.get('kill_chain_phases', []) if p.get('phase_name')]

                    metadata[technique_id] = {
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'platforms': obj.get('x_mitre_platforms', []),
                        'data_sources': obj.get('x_mitre_data_sources', []),
                        'detection': obj.get('x_mitre_detection', ''),
                        'tactics': tactics,
                        'is_sub_technique': bool(obj.get('x_mitre_is_subtechnique', '.' in technique_id)),
                        'revoked': revoked,
                        'deprecated': deprecated,
                        'version': obj.get('x_mitre_version', '1.0'),
                    }
                    if not revoked and not deprecated:
                        valid_techniques.add(technique_id)

                elif obj_type == 'x-mitre-tactic':
                    shortname = obj.get('x_mitre_shortname')
                    if shortname and not obj.get('revoked') and not obj.get('x_mitre_deprecated'):
                        valid_tactics.add(shortname)
                        tactic_names[shortname] = obj.get('name', shortname)

                elif obj_type == 'x-mitre-collection':
                    if obj.get('name') in (None, MITRE_ENTERPRISE_COLLECTION_NAME) and obj.get('x_mitre_version'):
                        version = str(obj['x_mitre_version'])

                elif obj_type == 'relationship' and obj.get('relationship_type') == 'revoked-by':
                    revoked_refs[obj.get('source_ref', '')] = obj.get('target_ref', '')

            revoked_by: Dict[str, str] = {}
            for source_stix, target_stix in revoked_refs.items():
                source_id = id_by_stix.get(source_stix)
                target_id = id_by_stix.get(target_stix)
                if source_id and target_id:
                    revoked_by[source_id] = target_id
        except Exception as e:
            logger.error(f"Error processing ATT&CK data: {e}")
            return False

        if not valid_techniques:
            logger.error("No active techniques found in ATT&CK data")
            return False
        if not valid_tactics:
            logger.error("No tactics (x-mitre-tactic objects) found in ATT&CK data")
            return False

        if len(valid_techniques) < 100:
            logger.warning(f"Only {len(valid_techniques)} active techniques found - data may be incomplete")

        # Commit
        self.valid_techniques = valid_techniques
        self.valid_tactics = valid_tactics
        self.tactic_names = tactic_names
        self.technique_metadata = metadata
        self.revoked_by = revoked_by
        self.data_version = version
        if version is None:
            logger.warning("ATT&CK data has no x-mitre-collection version (mitre/cti files do not); version unknown")
        return True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(technique_id: str) -> str:
        return technique_id.upper().strip()

    def has_data(self) -> bool:
        """True if real ATT&CK data is loaded (as opposed to format-only validation)."""
        return bool(self.valid_techniques)

    def is_valid_technique(self, technique_id: str) -> bool:
        """
        True if the technique exists and is active (not revoked or deprecated).

        Without loaded data this falls back to checking only the ID format.
        """
        if not technique_id or not isinstance(technique_id, str):
            return False
        normalized = self._normalize(technique_id)
        if self.valid_techniques:
            return normalized in self.valid_techniques
        return self._validate_technique_format(normalized)

    def is_known_technique(self, technique_id: str) -> bool:
        """True if the ID exists in the data at all, including revoked and deprecated ones."""
        return bool(technique_id) and self._normalize(technique_id) in self.technique_metadata

    def is_revoked(self, technique_id: str) -> bool:
        info = self.technique_metadata.get(self._normalize(technique_id or ''))
        return bool(info and info['revoked'])

    def is_deprecated(self, technique_id: str) -> bool:
        info = self.technique_metadata.get(self._normalize(technique_id or ''))
        return bool(info and info['deprecated'])

    def resolve_revoked(self, technique_id: str) -> Optional[str]:
        """
        Follow revoked-by links to the active technique that replaced a revoked one.

        Returns None if the technique is not revoked, has no replacement, or the chain
        does not end in an active technique.
        """
        current = self._normalize(technique_id or '')
        if not self.is_revoked(current):
            return None
        seen = {current}
        for _ in range(_MAX_REVOKED_CHAIN):
            nxt = self.revoked_by.get(current)
            if not nxt or nxt in seen:
                return None
            if nxt in self.valid_techniques:
                return nxt
            seen.add(nxt)
            current = nxt
        return None

    def is_valid_tactic(self, tactic: str) -> bool:
        """True if the (already normalized) tactic short name is valid in the loaded data."""
        if not tactic or not isinstance(tactic, str):
            return False
        normalized = tactic.lower().strip()
        if self.valid_tactics:
            return normalized in self.valid_tactics
        return len(normalized) > 0 and normalized.replace('-', '').isalpha()

    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Metadata for a technique (including revoked and deprecated ones), or None."""
        if not technique_id:
            return None
        return self.technique_metadata.get(self._normalize(technique_id))

    def get_techniques_by_tactic(self, tactic: str) -> Set[str]:
        """Active techniques associated with a tactic short name."""
        normalized = tactic.lower().strip().replace(' ', '-').replace('_', '-')
        return {tid for tid, meta in self.technique_metadata.items()
                if tid in self.valid_techniques and normalized in meta.get('tactics', [])}

    def known_platforms(self) -> Set[str]:
        """Platform names (e.g. 'Windows', 'Identity Provider') used by active techniques."""
        platforms: Set[str] = set()
        for technique_id in self.valid_techniques:
            platforms.update(self.technique_metadata[technique_id].get('platforms', []))
        return platforms

    def validate_technique_list(self, technique_ids: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Split technique IDs into (valid, invalid)."""
        valid, invalid = set(), set()
        for technique_id in technique_ids:
            if self.is_valid_technique(technique_id):
                valid.add(self._normalize(technique_id))
            else:
                invalid.add(technique_id)
        return valid, invalid

    def get_validation_summary(self) -> Dict[str, Any]:
        """Summary of the validator state, suitable for logs and reports."""
        sub_count = sum(1 for t in self.valid_techniques if self.technique_metadata[t]['is_sub_technique'])
        summary: Dict[str, Any] = {
            'has_attack_data': self.has_data(),
            'technique_count': len(self.valid_techniques),
            'tactic_count': len(self.valid_tactics),
            'data_version': self.data_version,
            'data_source': self.data_source,
            'using_stale_cache': self.using_stale_cache,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'validation_mode': 'attack_data' if self.has_data() else 'format_only',
            'sub_techniques': sub_count,
            'main_techniques': len(self.valid_techniques) - sub_count,
            'revoked_techniques': sum(1 for m in self.technique_metadata.values() if m['revoked']),
            'deprecated_techniques': sum(1 for m in self.technique_metadata.values() if m['deprecated']),
        }
        return summary

    @staticmethod
    def _validate_technique_format(technique_id: str) -> bool:
        if not technique_id or not isinstance(technique_id, str):
            return False
        return bool(_TECHNIQUE_FORMAT.match(technique_id.upper().strip()))

    def __str__(self) -> str:
        if self.valid_techniques:
            return (f"MitreAttackValidator(version={self.data_version}, "
                    f"techniques={len(self.valid_techniques)}, tactics={len(self.valid_tactics)})")
        return "MitreAttackValidator(no_data_loaded)"
