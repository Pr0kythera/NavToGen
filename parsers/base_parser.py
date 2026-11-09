"""
Base Parser Interface
=====================

Defines the contract all rule parsers follow, plus the shared machinery for reading
and decoding rule files.

Pipeline
--------
1. ``safe_file_read`` reads the file once (size limit, path validation, UTF-8 with BOM).
2. ``decode_structured`` turns the text into a list of *records* (plain dicts):
   - ``.yaml/.yml``: the YAML document (a list of dicts yields several records)
   - ``.json``: the JSON document (a list yields several records)
   - ``.toml``: the TOML document
   - ``.ndjson/.jsonl``: one record per line (Kibana exports contain many rules per file)
3. Each parser's ``score`` rates how likely the records are its format (0 = not mine).
   The repository picks the highest score; nothing is routed by file extension alone.
4. ``parse_records`` converts records into ``DetectionRule`` objects.

Adding a parser: subclass ``BaseRuleParser`` and implement ``get_supported_extensions``,
``score`` and ``parse_records``. ``parse(file_path)`` and ``can_parse(file_path)`` are
provided for convenience and backward compatibility.
"""

import json
import logging
import threading
import tomllib
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from config import ENCODING, MAX_FILE_SIZE
from models.detection_rule import DetectionRule
from validators.security_validator import SecurityValidator

logger = logging.getLogger(__name__)

# The C-accelerated YAML loader is several times faster on large rule sets
_YamlLoader = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)

Records = List[Dict[str, Any]]


def decode_structured(content: str, file_path: str) -> Tuple[Records, List[str]]:
    """
    Decode file text into a list of dict records based on the file extension.

    Returns:
        (records, errors). Records that are not dicts are dropped. Decoding errors are
        returned as messages rather than raised.
    """
    suffix = Path(file_path).suffix.lower()
    errors: List[str] = []
    data: Any = None

    try:
        if suffix in ('.yaml', '.yml'):
            data = yaml.load(content, Loader=_YamlLoader)
        elif suffix == '.json':
            data = json.loads(content)
        elif suffix == '.toml':
            data = tomllib.loads(content)
        elif suffix in ('.ndjson', '.jsonl'):
            data = []
            for line_no, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except ValueError as e:
                    errors.append(f"line {line_no}: invalid JSON ({e})")
        else:
            errors.append(f"unsupported extension '{suffix}'")
    except (yaml.YAMLError, ValueError, tomllib.TOMLDecodeError) as e:
        errors.append(f"{suffix[1:].upper()} parse error: {e}")
        return [], errors

    if isinstance(data, dict):
        records = [data]
    elif isinstance(data, list):
        records = [item for item in data if isinstance(item, dict)]
    else:
        records = []
    return records, errors


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse the timestamp styles seen in rule files; returns None if unparseable."""
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in ('%Y/%m/%d', '%Y-%m-%d', '%Y/%m/%d %H:%M:%S'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def to_bool(value: Any, default: bool = True) -> bool:
    """Interpret booleans written as bools, ints or strings ("false", "no", "0")."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ('false', 'no', 'off', '0', 'disabled'):
        return False
    if text in ('true', 'yes', 'on', '1', 'enabled'):
        return True
    return default


def read_rule_file(file_path: str, allowed_extensions: Optional[Set[str]] = None,
                   max_size: Optional[int] = None) -> Optional[str]:
    """
    Read a rule file with path validation, a size limit and strict UTF-8 decoding.

    A UTF-8 byte-order mark (common in files saved on Windows) is accepted. Files that
    are not valid UTF-8 are rejected with an error instead of being silently altered.
    Returns None (after logging the reason) if the file cannot be read.
    """
    size_limit = max_size or MAX_FILE_SIZE

    is_valid, error_msg = SecurityValidator.validate_file_path(file_path, allowed_extensions)
    if not is_valid:
        logger.error(f"File validation failed for {file_path}: {error_msg}")
        return None

    try:
        file_size = Path(file_path).stat().st_size
        if file_size > size_limit:
            logger.error(f"File too large: {file_size} bytes (limit: {size_limit})")
            return None

        with open(file_path, 'r', encoding=ENCODING) as f:
            content = f.read()

        logger.debug(f"Read {len(content)} characters from {file_path}")
        return content

    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
    except PermissionError:
        logger.error(f"Permission denied reading: {file_path}")
    except UnicodeDecodeError as e:
        logger.error(f"File is not valid UTF-8 ({file_path}): {e}")
    except Exception as e:
        logger.error(f"Unexpected error reading {file_path}: {e}")
    return None


class BaseRuleParser(ABC):
    """
    Abstract base class for all rule parsers.

    Each parser is responsible for recognizing its own format (``score``), converting
    records into ``DetectionRule`` objects (``parse_records``), and reporting errors
    without raising.
    """

    def __init__(self, parser_name: str):
        self.parser_name = parser_name
        self.parse_statistics = self._empty_statistics()
        self._stats_lock = threading.Lock()  # Thread-safe statistics updates
        logger.debug(f"Initialized {parser_name} parser")

    @staticmethod
    def _empty_statistics() -> Dict[str, int]:
        return {
            'files_processed': 0,
            'successful_parses': 0,
            'failed_parses': 0,
            'techniques_extracted': 0,
            'tactics_extracted': 0
        }

    # ------------------------------------------------------------------
    # Interface for subclasses
    # ------------------------------------------------------------------

    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """File extensions this parser supports, including the dot."""

    @abstractmethod
    def score(self, records: Records, file_path: str) -> int:
        """
        Rate how likely the decoded records are this parser's format.

        Returns 0 if the records are not this format. Higher is more confident. The
        repository selects the parser with the highest non-zero score.
        """

    @abstractmethod
    def parse_records(self, records: Records, file_path: str) -> List[DetectionRule]:
        """Convert decoded records into rules. Records that are not rules are skipped."""

    # ------------------------------------------------------------------
    # Convenience API built on the interface above
    # ------------------------------------------------------------------

    def can_parse(self, file_path: str, content: Optional[str] = None) -> bool:
        """True if this parser recognizes the file. Reads the file if content is not given."""
        if Path(file_path).suffix.lower() not in self.get_supported_extensions():
            return False
        if content is None:
            content = self.safe_file_read(file_path)
        if not content:
            return False
        records, _ = decode_structured(content, file_path)
        return self.score(records, file_path) > 0

    def parse(self, file_path: str, content: Optional[str] = None) -> Optional[DetectionRule]:
        """Parse a file and return its first rule, or None. See ``parse_all`` for many."""
        rules = self.parse_all(file_path, content)
        return rules[0] if rules else None

    def parse_all(self, file_path: str, content: Optional[str] = None) -> List[DetectionRule]:
        """Parse every rule in a file (NDJSON exports hold many). Never raises."""
        try:
            if content is None:
                content = self.safe_file_read(file_path)
            if not content:
                self.update_statistics(False)
                return []
            records, errors = decode_structured(content, file_path)
            for message in errors:
                logger.warning(f"{file_path}: {message}")
            if not records:
                self.update_statistics(False)
                return []
            return self.parse_records(records, file_path)
        except Exception as e:  # Parsers must not take the run down
            logger.error(f"Unexpected error parsing {file_path}: {e}")
            self.update_statistics(False)
            return []

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def validate_rule_structure(self, rule_data: Dict[str, Any]) -> bool:
        """Minimum structure check: a dict with a name/title/displayName."""
        if not isinstance(rule_data, dict):
            logger.warning("Rule data is not a dictionary")
            return False
        if not any(rule_data.get(f) for f in ('name', 'title', 'displayName')):
            logger.warning("Rule data missing name/title field")
            return False
        return True

    def extract_basic_metadata(self, rule_data: Dict[str, Any], file_path: str) -> DetectionRule:
        """Extract the fields common to every format into a new DetectionRule."""
        name = (rule_data.get('name') or rule_data.get('title')
                or rule_data.get('displayName') or 'Unknown Rule')
        description = rule_data.get('description') or rule_data.get('summary') or ''

        rule = DetectionRule(
            name=str(name),
            description=str(description),
            rule_type=self.parser_name.lower(),
            source_file=file_path
        )

        if 'id' in rule_data:
            rule.rule_id = str(rule_data['id'])

        if 'author' in rule_data:
            author_data = rule_data['author']
            if isinstance(author_data, list):
                rule.author = ', '.join(str(a) for a in author_data)
            else:
                rule.author = str(author_data)

        # Textual severity only. Numeric risk scores are kept as numbers (risk_score),
        # never stuffed into the severity string.
        for field_name in ('severity', 'priority'):
            if rule_data.get(field_name) is not None:
                rule.severity = str(rule_data[field_name]).lower().strip()
                break

        risk_score = rule_data.get('risk_score')
        if risk_score is not None:
            try:
                rule.risk_score = int(risk_score)
            except (ValueError, TypeError):
                rule.parse_errors.append(f"Invalid risk_score: {risk_score!r}")

        if 'enabled' in rule_data:
            rule.enabled = to_bool(rule_data['enabled'])

        return rule

    def safe_file_read(self, file_path: str, max_size: int = None) -> Optional[str]:
        """Read a rule file safely (see ``read_rule_file``) using this parser's extensions."""
        return read_rule_file(file_path, set(self.get_supported_extensions()), max_size)

    def update_statistics(self, success: bool, techniques_found: int = 0, tactics_found: int = 0):
        """Update parser statistics (thread-safe). Counts one rule record per call."""
        with self._stats_lock:
            self.parse_statistics['files_processed'] += 1

            if success:
                self.parse_statistics['successful_parses'] += 1
                self.parse_statistics['techniques_extracted'] += techniques_found
                self.parse_statistics['tactics_extracted'] += tactics_found
            else:
                self.parse_statistics['failed_parses'] += 1

    def log_statistics(self):
        """Log current parsing statistics."""
        stats = self.get_statistics()
        logger.info(f"{self.parser_name} parser: {stats['files_processed']} records, "
                    f"{stats['success_rate']:.1f}% success, "
                    f"{stats['techniques_extracted']} techniques, {stats['tactics_extracted']} tactics")

    def get_statistics(self) -> Dict[str, Any]:
        """Current parsing statistics (a copy)."""
        with self._stats_lock:
            stats: Dict[str, Any] = dict(self.parse_statistics)
        stats['parser_name'] = self.parser_name
        stats['success_rate'] = (
            stats['successful_parses'] / stats['files_processed'] * 100
            if stats['files_processed'] > 0 else 0
        )
        return stats

    def reset_statistics(self):
        """Reset all parsing statistics to zero."""
        with self._stats_lock:
            self.parse_statistics = self._empty_statistics()
        logger.debug(f"Reset statistics for {self.parser_name} parser")

    def __str__(self) -> str:
        return f"{self.parser_name}Parser(records_processed={self.parse_statistics['files_processed']})"

    def __repr__(self) -> str:
        return (f"{self.__class__.__name__}(parser_name='{self.parser_name}', "
                f"statistics={self.parse_statistics})")
