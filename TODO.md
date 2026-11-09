# NavToGen TODO

Created from the code review of 2026-11-09 plus the owner's feature list.
Review date matters: ATT&CK was at v20 (13 Oct 2026) when this was written.

Legend
- ID prefixes: D = design decision, C = critical bug, H = high, M = medium, L = low, F = feature.
- Evidence tags: [V] reproduced by running code, [R] found by reading code only, [U] upstream fact that must be re-verified before relying on it.
- Line numbers refer to commit d9c8f31 and will drift.
- Checkboxes are for tracking; tick them as items land.

---

## 0. Design decisions needed before the schema work (blockers for Track B)

- [ ] **D1. Field ownership and regeneration semantics.** The per-rule JSON mixes fields this tool derives (regenerated every run) with fields other tools populate (TP/FP counts, BAS results, environment). A naive re-run would overwrite externally supplied data. Decide one of:
  - (a) single file per rule with top-level blocks that each declare an owner, and a merge-by-`detection_id` step that never touches blocks it does not own (recommended), or
  - (b) two files per rule: tool-owned `<id>.detection.json` and externally-owned sidecar `<id>.outcomes.json`.
  Either way, ship a documented merge algorithm and a test that proves externally owned blocks survive regeneration.
- [ ] **D2. Identity.** Define `detection_id` (stable UUID) versus `source_rule_id`. Sentinel templates carry `id`. Elastic has a stable `rule_id` and a random internal `id` [U: Kibana API docs]. Sigma uses `id`. When no GUID exists, synthesize a UUIDv5 from (source repo, relative path) and set `id_synthesized: true`. Decide what happens on rename or move.
- [ ] **D3. Terminology.** Several requested fields are overloaded and need distinct names:
  - `platform` -> `siem_platform` (Elastic/Sentinel) vs `target_platforms` (Windows/Linux/Azure/GCP/...).
  - revision count -> `source_version` (as written in the rule) vs `revision_count` (derived from VCS history). These are not the same thing: Sentinel template `version` is a semver string (observed `1.0.3`), Elastic `version` is an integer that the API auto-increments [U].
  - lookback -> rule-level (`queryPeriod`, Elastic `from`) vs query-internal windows (`ago()`, `bin()`, `make-series`). Store both, normalized to ISO 8601 durations.
  - environment -> an array of environment objects, not a single string (prod/dev/test, per tenant or workspace).
- [ ] **D4. LLM policy.** Rules describe an organization's detection capability (the README itself says they are sensitive). Decide: opt-in only, provider is pluggable (include a local-model option), nothing is sent by default, results are cached by content hash, and every LLM-produced field records model, prompt hash, timestamp and `reviewed: false`. See B5.
- [ ] **D5. Align with existing formats before inventing fields.** Compare with Sigma rule metadata and the MITRE ATT&CK Data Model JSON schemas [U] and reuse names where they fit. Publish our schema as JSON Schema 2020-12 with a `$id` and a `schema_version` (semver).
- [ ] **D6. Sensitivity classification.** Environment names, tenant/workspace IDs and outcome counts are sensitive. Add a `handling` marker to the schema and document that generated files must be treated as confidential. Do not log schema contents at INFO.
- [ ] **D7. Sequencing.** Do not start Track B until C1-C7 are fixed. The schema's `attack` block depends on a working validator, a correct tactic model and revoked-technique handling.

---

## 1. Critical bugs (wrong or silently incomplete results)

- [ ] **C1. `--validate-online` can never succeed [V].** `validators/mitre_validator.py:349-373` `_process_matrix_tactics` is a stub that returns 0, and `_process_attack_data` (line 288) requires `tactics_found > 0`, so it always returns False. Live data log: "Only found 0 tactics". `main.py:156` then continues unvalidated and exits 0.
  - [ ] Derive tactics from `x-mitre-tactic` objects (`x_mitre_shortname`), not the matrix (and `tactic_refs` is a flat string list, not a list of lists).
  - [ ] Make failure explicit: non-zero exit, or a loud summary line, when `--validate-online` was requested and validation did not run.
  - [ ] Add a regression test using a trimmed real-structure STIX fixture (a synthetic bundle reproduced the bug).
- [ ] **C2. Tactic model out of date [V].** ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment (15 tactics); v20 is current. `config.py:43-58` `VALID_TACTICS` has 14 and rejects `stealth` and `defense-impairment`; `config.py:39` default version is 17.
  - [ ] Load valid tactics from the ATT&CK data when available; keep a bundled fallback list (15 tactics, versioned).
  - [ ] Support old and new names (map legacy `defense-evasion` for rules written before v19, record which tactic names were seen).
  - [ ] Bump the default ATT&CK version and make it derived from the loaded data where possible.
- [ ] **C3. Sentinel tactics mostly dropped [V].** `models/detection_rule.py:148` only swaps spaces/underscores, so CamelCase (`CredentialAccess`, `PrivilegeEscalation`, `DefenseEvasion`, `LateralMovement`, `InitialAccess`) is rejected; 2 of about 5 tactics captured on the fixtures.
  - [ ] Normalize CamelCase to hyphenated form (split on capitals) before validation; add an alias table for Sentinel-specific names (e.g. `PreAttack`).
  - [ ] Stop treating Sentinel `tags` as an ATT&CK source (`parsers/sentinel_parser.py:80`); it produces noise such as `Solorigate`, `NOBELIUM`, `DEV-0537`.
- [ ] **C4. Revoked and deprecated techniques accepted as valid [V].** Live data: 149 revoked, 12 deprecated, 157 `revoked-by` relationships. v19 revoked broadly used techniques (e.g. Impair Defenses, Indicator Blocking, Clear Windows Event Logs).
  - [ ] Validator must expose `is_revoked`, `is_deprecated` and `replaced_by`.
  - [ ] Policy flag: warn, remap via `revoked-by`, or drop. Report remaps in the output.
  - [ ] Count rules still mapped to revoked IDs in the report (a useful maintenance metric).
- [ ] **C5. Elastic ingestion limited to hand-written YAML [V].**
  - [ ] Add TOML (the `detection-rules` repo layout [U]) and NDJSON (Kibana export) parsing; extend `SUPPORTED_EXTENSIONS` and discovery.
  - [ ] Content-based routing for `.json` instead of the extension fallback at `core/RuleRepository.py:441-444` (an Elastic-shaped JSON file was silently parsed as Sentinel with zero techniques).
  - [ ] Relax the required-fields check at `parsers/elastic_parser.py:416`.
  - [ ] When no parser matches, report it; never return an empty rule silently.
- [ ] **C6. Report path and JSON serialization [V].**
  - [ ] `main.py:367`: sanitize the filename component only, never the whole path (`output/rep.json` currently becomes `output_rep.json` in the CWD).
  - [ ] `main.py:370`: serialize sets as sorted lists (custom encoder) instead of `default=str`.
  - [ ] Create the output directory when it does not exist (see M3).
- [ ] **C7. Temporal analysis ingests its own outputs [V].** The epilog recommends `--snapshots-directory output/` and the tool writes `executive_summary_*.json` and `time_series_data_*.json` there; the `*.json` glob (`core/temporal_analysis.py:297`) loads them as 0-rule snapshots.
  - [ ] Identify snapshot files by content (required keys) and skip everything else with a debug message.
  - [ ] Write temporal outputs to a separate subdirectory or a distinct filename pattern.
  - [ ] Stop reverse-engineering rule counts from Navigator scores (`temporal_analysis.py:171`); read from the coverage report, or embed counts in layer metadata.
  - [ ] Fix `tactics` metadata key mismatch (line 177) so Navigator-layer snapshots can report tactics.

---

## 2. High priority

- [ ] **H1. Disabled rules counted as coverage [R].** `rule.enabled` is never read outside the parsers. Exclude by default; add `--include-disabled`; report the count.
- [ ] **H2. Parent techniques never emitted [V].** Only `T1003.001` -> no `T1003` entry. `get_parent_techniques()` is unused.
  - [ ] Emit parent entries (without double counting) and/or set layout `showAggregateScores` and `expandedSubtechniques` (`models/navigator_layer_model.py:382-388`) [U: layer format 4.5].
- [ ] **H3. Stale default platform filter [V/R].** `navigator_layer_model.py:303-306` lists `Azure AD`, `Office 365`, `Network`; live data uses `Identity Provider`, `Office Suite`, `Network Devices`, `ESXi`, `Containers`, `IaaS`, `SaaS`, `PRE`. Navigator behavior with unknown names is untested. Default to no platform filter; make it opt-in via a flag; build the list from loaded data.
- [ ] **H4. `--attack-version` ignored outside coverage mode [R].** `generators/layer_generator.py:226,320` use the default. Pass it through; validate against loaded data.
- [ ] **H5. Wrong data version [V].** `mitre_validator.py:261` records STIX `spec_version` ("2.0"). The `mitre/cti` file has no `x-mitre-collection`. Use a source that exposes the real version (e.g. the versioned `attack-stix-data` files [U]) or read it from objects' `x_mitre_attack_spec_version`/release metadata, and record it in every output.
- [ ] **H6. Retry configuration inert [V].** `mitre_validator.py:110`: `Retry(status=[...])` should be `status_forcelist=[...]`.
- [ ] **H7. Tactic-technique pairing lost [R].** Keep the (tactic, technique) pairs from Elastic `threat[]` and emit a Navigator `tactic` field so multi-tactic techniques are not lit under every tactic.
- [ ] **H8. No tests, no CI [V].**
  - [ ] pytest suite with fixtures for Elastic YAML/TOML/NDJSON and Sentinel YAML/ARM JSON.
  - [ ] Regression tests for C1-C7, H1-H6 first.
  - [ ] GitHub Actions: pytest, flake8/ruff, mypy; Python version matrix (see M11).
  - [ ] `pyproject.toml` with dependencies split into runtime and dev extras.

---

## 3. Medium priority

- [ ] **M1.** Forbidden-path check is a substring match (`validators/security_validator.py:118-121`, `config.py:62-70`) and blocks `/home/me/proj/etc/rules/`, `/data/sys/rules/`, and everything under `/root/` [V]. Match on path components of the resolved path, and let the user opt out of `/root/` or configure the list.
- [ ] **M2.** Symlink check is dead code (`security_validator.py:165,185`: `.resolve()` runs before `.is_symlink()`) [V]. Check before resolving; decide the policy (follow, refuse, or refuse when the target escapes the root).
- [ ] **M3.** `-o results/x.json` fails when `results/` does not exist [V]. Create the parent directory.
- [ ] **M4.** Depth calculation uses `root.replace(directory_path, '')` (`core/RuleRepository.py:181`); off by one with a trailing slash, and files at the depth limit are skipped [R]. Use `Path.relative_to`.
- [ ] **M5.** Elastic risk-score to severity thresholds (75/50/25 in `parsers/elastic_parser.py:226-234`) may not match Elastic's documented bands (I recall low <22, medium 22-47, high 48-73, critical >=74) [U]. Verify and fix.
- [ ] **M6.** `risk_score`/`priority` stored as lowercase strings in `parsers/base_parser.py:196` [R]. Keep a numeric `risk_score` separate from the normalized `severity`.
- [ ] **M7.** Performance [R]: each file is read and validated several times (every parser's `can_parse`, then `parse`); parsing stats counters are not locked; `get_statistics()` returns a shallow copy. Read once, pass content through; consider process-based parallelism for CPU-bound YAML; return deep copies.
- [ ] **M8.** `errors='replace'` makes the `UnicodeDecodeError` branch unreachable (`base_parser.py:244,256`) [R]. Decide: strict with an error, or replace and record a parse warning.
- [ ] **M9.** Sentinel parser [R]:
  - [ ] ARM templates with multiple `alertRules` resources return only the first (`sentinel_parser.py:202-207`).
  - [ ] Dead `displayName` fallback (line 304).
  - [ ] Text-scan fallback pulls T-IDs from query text and can create false coverage; make it opt-in and tag the source.
- [ ] **M10.** Temporal analysis [R]: coverage denominator hard-coded at 800 (`temporal_analysis.py:68`; v19 has 222 techniques + 475 sub-techniques [U: v19 release notes]); fixed CSV filenames are overwritten; naive vs timezone-aware timestamps can break sorting.
- [ ] **M11.** README claims Python 3.8+ but `tuple[int, int]` annotations (`sentinel_parser.py:340`, `elastic_parser.py:246`) need 3.9+; 3.8 and 3.9 are end-of-life. Set the minimum to a supported version and say so in the README and CI.
- [ ] **M12.** Online fetch downloads about 49 MB on every run with no on-disk cache [V]. Add a cache directory with ETag/If-Modified-Since or a pinned version; offline mode that uses the cache; `--attack-data-file` for air-gapped use. Decide between `mitre/cti` (STIX 2.0) and `attack-stix-data` (STIX 2.1) [U: both maintained].

---

## 4. Low priority and hygiene

- [ ] **L1.** README documents `MITRE_ANALYZER_*` environment variables that no code reads [V]. Implement or remove.
- [ ] **L2.** Placeholder repo URLs in README and `main.py:668`; README claims streaming/memory behavior that does not exist [V].
- [ ] **L3.** Delete `package_inits.py` (stale, wrong module names). Add real exports to `parsers/__init__.py`.
- [ ] **L4.** Remove tracked `.DS_Store` files (root and `tests/`) and add them to `.gitignore`.
- [ ] **L5.** Label `sample_snapshots/` as synthetic, or generate it from the tool.
- [ ] **L6.** Remove unused imports and placeholder-less f-strings flagged by pyflakes (`config.py`, `core/RuleRepository.py`, `core/temporal_analysis.py`, `main.py`, `parsers/elastic_parser.py`).
- [ ] **L7.** Remove or wire in unused methods: `get_coverage_score`, `has_sub_techniques`, `get_rule_complexity_score`, `validate_technique_list`, `is_valid_tactic`, `get_techniques_by_tactic`, `is_safe_for_logging`, `validate_input_string`. Move the bottom-of-file `Path` import in `base_parser.py` to the top.
- [ ] **L8.** Split dev tools out of `requirements.txt`; drop the redundant `urllib3[secure]` line (could not reproduce a pip warning here, so cosmetic).
- [ ] **L9.** Tone down marketing language ("Enterprise", "CISO") in output text; tie the version string to packaging.

---

## 5. Features

### Track A. ATT&CK detection model: Data Components, Detection Strategies, Analytics (owner request 1)

What the live STIX data (ATT&CK v19/v20 content on `mitre/cti`) contains, checked 2026-11-09:
- `x-mitre-detection-strategy` (708 objects, IDs `DETxxxx`): a `detects` relationship to an `attack-pattern` (706 of 706 active techniques have at least one) and `x_mitre_analytic_refs`.
- `x-mitre-analytic` (1,773 objects): `x_mitre_platforms`, `x_mitre_log_source_references` (data component ref + log source `name` + `channel`), `x_mitre_mutable_elements` (tunable fields such as `TimeWindow`, thresholds), description.
- `x-mitre-data-component` (109 objects): `x_mitre_log_sources` (name and channel). `x-mitre-data-source` (38) still exists.
- Log source names are vendor-neutral-ish strings (e.g. `WinEventLog:Sysmon`, `WinEventLog:Security`, `auditd:SYSCALL`, `AWS:CloudTrail`; 271 distinct). They are not Sentinel table names or Elastic indices.

Tasks
- [ ] **F1. Parse the new object types** in the validator/loader into typed models (`DetectionStrategy`, `Analytic`, `DataComponent`) with the relationships resolved; unit-test against a trimmed fixture. Handle revoked/deprecated objects (see C4).
- [ ] **F2. Per-technique enrichment**: for each covered technique, list its strategies, analytics (by platform), required data components and tunable elements. Add to the layer metadata (bounded size) and the report.
- [ ] **F3. Curated mapping file: SIEM table/index -> ATT&CK data component and log source** (e.g. `DeviceProcessEvents` -> Process Creation; `SecurityEvent` EventID 4688 -> `WinEventLog:Security` `EventCode=4688`; `AzureActivity` -> Cloud/Azure resource logs; Elastic `logs-endpoint.events.process-*`). No canonical mapping exists, so this is a data file in the repo with a contribution guide, a versioning scheme, and a test that every mapped data component exists in the loaded ATT&CK data. Start with the tables used by the bundled fixtures.
- [ ] **F4. Data-component availability analysis (optional input)**: accept a list of tables/log sources the organization actually ingests and report which strategies/analytics for covered or uncovered techniques are feasible vs blocked by missing telemetry.
- [ ] **F5. Rule-to-analytic alignment (heuristic, labeled as such)**: a rule's technique + platform + tables vs an analytic's platform + log sources gives an "alignment" indicator. Be explicit that it is a heuristic: strategies are linked to techniques, not to rules.
- [ ] **F6. New layer modes**: "data-component readiness" (what telemetry would enable more strategies) and "gap" layers (techniques with strategies but no rule).
- [ ] **F7. Version awareness**: record the ATT&CK version used for every strategy/analytic reference. IDs and content change between releases (v19 deprecated two Impair Defenses strategies, DET0317 and DET0239 [U]).

### Track B. Per-rule detection record and schema (owner requests 2 and 3)

Goal (per owner): the tool derives what it can and emits a stable JSON Schema plus per-rule JSON files that other tools populate for the rest. The tool does not attempt to produce operational results.

#### B0. Schema design
- [ ] Publish `schemas/detection-record.schema.json` (JSON Schema 2020-12, `$id`, `schema_version`). Version independently from the tool.
- [ ] Top-level blocks, each with a declared `owner` (see D1): `identity`, `source`, `schedule`, `data`, `attack`, `analysis`, `outcomes`, `validation`, `extensions`.
- [ ] Provenance on every non-trivial value: `{source: parser|llm|external, tool, tool_version, timestamp, confidence?, reviewed_by?}`. Allows consumers to trust or discard derived data.
- [ ] `additionalProperties: false` for tool-owned blocks; a namespaced `extensions` object (keys must start with `x_`) for other tools.
- [ ] Output layout: one JSON file per rule named by `detection_id`, plus a JSONL index. Document file naming for synthesized IDs.
- [ ] A `validate` subcommand that checks generated or merged files against the schema; ship example files.

#### B1. Field catalog and derivability

Legend for "Source": P = parsed from structured fields (deterministic), Q = needs query parsing, L = LLM-assisted, X = external tools populate.

| Requested field | Proposed schema field | Source | Notes |
|---|---|---|---|
| Detection GUID | `identity.detection_id`, `identity.source_rule_id`, `identity.id_synthesized` | P | See D2. Sentinel `id`; Elastic `rule_id`. |
| Detection name | `identity.name` | P | |
| Detection description | `identity.description` | P | Keep raw text; stop appending bracketed metadata into the description (today the parsers mutate it, e.g. `[Sentinel Config: ...]`). |
| Tables used | `data.tables[]` | P, Q | Sentinel: `requiredDataConnectors[].dataTypes` is structured. Elastic: `index` patterns / `data_view_id`. KQL query parsing needed for completeness (let-bound functions, ASIM parsers such as `imAuthentication` expand to many tables, `union`, `join`). |
| Fields used (entity / custom detail extraction) | `data.fields.entity_mapped[]`, `data.fields.custom_details[]`, `data.fields.query_referenced[]` | P (first two), Q (third) | Sentinel `entityMappings[].fieldMappings[].columnName` and `customDetails` are structured [U: Microsoft ARM reference]. Elastic `required_fields` (name, type) is informational only [U]. Phase 1 = structured sources only; query-referenced fields come later with a real parser. |
| True positive / benign positive / false positive / undetermined / false negative | `outcomes.by_environment[].by_revision[]` with counts, window, source system | X | These are Sentinel incident classification terms. False negatives are not observable from alert data and come from BAS, purple team or IR. Counts must carry a time window and the rule revision they apply to. |
| Environment | `outcomes.environments[]` (id, name, kind prod/dev/test, tenant/workspace ref) | X | Array, not a string. Sensitive (D6). |
| Breach and attack simulation results | `validation.bas_results[]` | X | Per result: tool, test id, technique, outcome (detected / not detected / partial), date, rule revision tested, environment. |
| Platform (Windows/Linux/Azure/GCP/...) | `data.target_platforms[]` and `source.siem_platform` | P, Q | Derive from tables via a maintained table-to-platform lookup (shares data with F3); mark as inferred. |
| Number of revisions (based on version) | `source.source_version`, `source.source_version_scheme` (`semver`/`integer`/`none`), `source.revision_count` | P, VCS | Parse version as written; derive `revision_count` from git history when the source is a git checkout; never infer a count from a semver string. |
| Lookback time | `schedule.query_period`, `schedule.query_frequency`, `schedule.lookback_internal[]` (ISO 8601 durations) | P, Q | Sentinel `queryPeriod`/`queryFrequency`; Elastic `from` and `interval` (date math, e.g. `now-6m`, `5m`) [U]. Internal windows (`ago()`, `bin()`) need query parsing. |
| Detection intention (LLM: intent and logic text) | `analysis.intention.{intent, logic, provenance}` | L | See B5. |
| Detection method (LLM: thresholds, percentile, stdev, series functions) | `analysis.method.{techniques[], thresholds[], windows[], provenance}` | Q first, L fallback | See B4. |
| (added) Severity, enabled, schedule type, kind | `identity`/`schedule` | P | Already parsed today. |
| (added) ATT&CK mapping | `attack.techniques[]`, `attack.tactics[]`, `attack.validated`, `attack.revoked_remaps[]`, `attack.version` | P | Depends on C1-C4. Keep tactic-technique pairs (H7). |

#### B2. Structured extraction (no query parsing required)
- [ ] Extend `DetectionRule` (or add a sibling `DetectionRecord` model) with the new fields; keep the existing model working for layer generation.
- [ ] Sentinel: `requiredDataConnectors`, `entityMappings`, `customDetails`, `alertDetailsOverride`, `eventGroupingSettings`, `queryPeriod`, `queryFrequency`, `version`, `status`. Note: the public docs I found confirm `entityMappings`, `customDetails`, `alertDetailsOverride` and `queryPeriod`/`queryFrequency`; they did not confirm the YAML `version` field or the `eventGroupingSettings` sub-fields, so base those on the fixtures and the Azure-Sentinel repo, not on docs [U].
- [ ] Elastic: `rule_id`, `index`, `data_view_id`, `required_fields`, `related_integrations`, `from`, `interval`, `version`, `risk_score`, `severity`, `type`, `language`.
- [ ] Duration normalization helper (`5m`, `1h`, `P1D`, `now-6m`, `7d`) with tests.
- [ ] Preserve the raw query text and language (`kql`, `eql`, `esql`, `lucene`) in the record so later analysis stages can use it.

#### B3. Table and field extraction from queries (second phase)
- [ ] Evaluate parser options for KQL in Python (there is no first-party Python KQL parser that I verified; evaluate options and record the decision). Regex is acceptable only for a clearly labeled "best effort" mode.
- [ ] Handle `let` bindings, user functions, ASIM/normalization parsers (map known parser names to the set of underlying tables, data file shared with F3), `union`, `join`, `externaldata`, and watchlists.
- [ ] Mark each extracted table/field with its source (`structured` vs `query_parse`) and confidence.

#### B4. Detection method extraction
- [ ] Deterministic detector first: KQL `summarize`, `count()`/`dcount()` thresholds in `where`, `percentile()`/`percentiles()`, `stdev()`, `avg`, `make-series`, `series_decompose_anomalies`, `series_fit_*`, `bin()`; Elastic `threshold` rules, `new_terms`, ML job references, EQL `sequence ... maxspan`. Output a normalized list of method tags with extracted numeric parameters where present.
- [ ] LLM only for what the deterministic pass cannot classify; never let the LLM overwrite deterministic results (store both, with provenance).
- [ ] Controlled vocabulary for method tags (documented in the schema), so downstream tools can filter on them.

#### B5. LLM analysis: detection intention and method summaries
- [ ] Provider interface (`LLMProvider.analyze(structured_rule) -> text`) with implementations behind optional extras; off by default; a local-model option; a `--llm-dry-run` that prints what would be sent.
- [ ] Input is the parsed structure (identity, tables, entities, query, schedule), not the whole file; apply a redaction step for tenant/workspace identifiers and watchlist contents.
- [ ] Cache by content hash plus prompt version; record model, prompt hash, timestamp, and `reviewed: false` in provenance.
- [ ] Output constraints: schema-validated JSON, bounded length, no free-form fields that other tools will treat as authoritative.
- [ ] Evaluation set: a small hand-labeled set of rules with expected intent/method tags to catch regressions when prompts or models change.

#### B6. Merge and lifecycle
- [ ] `merge` command implementing D1: update tool-owned blocks, preserve foreign-owned blocks, flag conflicts (for example the rule's `source_version` changed since outcomes were recorded, making old outcomes stale).
- [ ] Mark `outcomes` and `validation` entries as stale when their recorded revision differs from the current one; never silently carry them forward as current.
- [ ] Deleted/renamed rules: keep tombstones or archive, per D2.
- [ ] Document the contract for external tools: how to find the schema, which blocks they may write, how to supply provenance.

#### B7. Concerns tracked from the design review
- [ ] Regeneration clobbering externally supplied data -> D1, B6.
- [ ] Sending rule content to an external LLM -> D4, B5.
- [ ] Overloaded terms (platform, revision, environment, lookback) -> D3.
- [ ] Heuristic outputs (tables/fields/platform from query parsing, LLM text) presented as facts -> provenance and confidence on every derived value (B0).
- [ ] Outcome metrics without time window or revision are misleading -> required fields in the schema (B1).
- [ ] Scope creep pulling the coverage tool away from correctness -> D7 sequencing.

### Track C. Other feature gaps from the review
- [ ] **F8. More rule sources**: Sigma (`attack.tXXXX` tags, stable `id` UUIDs) as the first addition, then Splunk ESCU, Chronicle YARA-L, Defender custom detections. Parsers must follow the content-routing design from C5.
- [ ] **F9. Weighted coverage**: severity, enabled state, telemetry availability (F4) and rule maturity (outcomes from Track B when present) instead of raw rule counts. Make the scoring algorithm selectable via CLI (currently `threshold` only is exposed).
- [ ] **F10. Gap and threat-profile layers**: uncovered techniques; coverage versus a supplied technique set (for example a threat actor's techniques from ATT&CK groups).
- [ ] **F11. Navigator bookkeeping**: record Navigator and layer-format versions in output; layer format 4.5 appears current [U]; confirm the latest Navigator release before changing `NAVIGATOR_VERSION = "5.1.1"`.
- [ ] **F12. Packaging**: installable package, `console_scripts` entry point, semantic versioning, changelog.

---

## 6. To verify before relying on them

- Elastic risk-score severity bands (M5).
- Whether Navigator hides techniques when `filters.platforms` contains names that no longer exist (H3).
- Latest Navigator release and whether layer format 4.5 is still current (F11).
- Sentinel template `version` semantics and the `eventGroupingSettings` field list (B2).
- Elastic `from` default and TOML layout in the `detection-rules` repo (C5, B2).
- ATT&CK Data Model JSON schemas and Sigma metadata names for reuse (D5).
- Python parsers available for KQL (B3).

## 7. Suggested order

1. C1, C2, C4, H5, H6, M12 (validator and data model rewrite, version handling, caching).
2. C3, C5, H2, H3, H4 (parsing and layer output).
3. C6, C7, M1-M4 (file and path handling, temporal analysis).
4. H8 in parallel from step 1 (tests and CI), then M5-M11.
5. D1-D6 decisions, then Track B (B0, B1, B2, B6), then F1-F3.
6. B3-B5 (query parsing, method extraction, LLM), F4-F7, then Track C.
7. L-items as opportunistic cleanup.
