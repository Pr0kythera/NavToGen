# NavToGen TODO

Created from the code review of 2026-11-09 plus the owner's feature list.
Review date matters: ATT&CK was at v20 (13 Oct 2026) when this was written.

Status (updated after the first fix pass)
- Sections 1-4 (bugs and hygiene) are done and covered by 187 pytest tests; `[~]` marks a partly done item.
- Not verified in the Navigator UI (cannot be run here): `expandedSubtechniques: annotated` (H2), `--tactic-scoped` behavior when scoped and unscoped entries mix (H7), and platform-filter behavior (H3 removed the default filter, so this no longer affects default output).
- Known caveat: YAML 1.1 reads unquoted `name: Off/No/On/Yes` as a boolean, so such a name is lost before the parser sees it (documented in the README).
- Not done: a mypy pass (CI runs ruff `E9,F` and pytest only).

Legend
- ID prefixes: D = design decision, C = critical bug, H = high, M = medium, L = low, F = feature.
- Evidence tags: [V] reproduced by running code, [R] found by reading code only, [U] upstream fact that must be re-verified before relying on it.
- Line numbers refer to commit d9c8f31 and will drift.
- Checkboxes are for tracking; tick them as items land.

---

## 0. Design decisions (resolved)

- [x] **D1. Two files per detection.** `<detection_id>.detection.json` is owned by this tool and is regenerated on every run. `<detection_id>.enrichment.json` is owned by other tools (LLM analysis, outcomes, BAS results, environment). This tool never overwrites an existing enrichment file; when none exists it may write an empty skeleton so other tools have a template. Staleness is handled by content hash (see D3 and B6).
- [x] **D2. Identity.** Use the rule's own UUID when it has one (Sentinel `id`, Elastic `rule_id`, Sigma `id`); otherwise generate one. Recommendation: generate a deterministic UUIDv5 from (source repository, relative path) rather than a random UUID, so regenerating does not orphan the enrichment file. Record which it was in `id_origin` (`source` or `generated`). Open point: a file rename changes a generated ID; document it.
- [x] **D3. Field names.** Proposal below (section 5, "Naming standard"); needs a final yes from the owner when the example Sentinel schema arrives.
- [x] **D4. LLM output: schema only.** The tool does NOT call any LLM and has no provider interface, redaction layer, cache or evaluation set. It only defines where LLM-produced text goes (`enrichment.analysis`) and the provenance fields describing how it was produced. How or whether organizations use LLMs is up to them.
- [x] **D5. Align with existing formats before inventing fields** (Sigma metadata, ATT&CK Data Model schemas [U]). Publish JSON Schema 2020-12 with `$id` and `schema_version`.
- [x] **D6. Sensitivity field.** `handling.sensitivity` (enum) plus `handling.notes` on both files. Generated files are to be treated as confidential by default; do not log schema contents at INFO.
- [x] **D7. Sequencing.** Bugs first (done), then Track B.

---

## 1. Critical bugs (wrong or silently incomplete results)

- [x] **C1. `--validate-online` can never succeed [V].** `validators/mitre_validator.py:349-373` `_process_matrix_tactics` is a stub that returns 0, and `_process_attack_data` (line 288) requires `tactics_found > 0`, so it always returns False. Live data log: "Only found 0 tactics". `main.py:156` then continues unvalidated and exits 0.
  - [x] Derive tactics from `x-mitre-tactic` objects (`x_mitre_shortname`), not the matrix (and `tactic_refs` is a flat string list, not a list of lists).
  - [x] Make failure explicit: non-zero exit, or a loud summary line, when `--validate-online` was requested and validation did not run.
  - [x] Add a regression test using a trimmed real-structure STIX fixture (a synthetic bundle reproduced the bug).
- [x] **C2. Tactic model out of date [V].** ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment (15 tactics); v20 is current. `config.py:43-58` `VALID_TACTICS` has 14 and rejects `stealth` and `defense-impairment`; `config.py:39` default version is 17.
  - [x] Load valid tactics from the ATT&CK data when available; keep a bundled fallback list (15 tactics, versioned).
  - [x] Support old and new names (map legacy `defense-evasion` for rules written before v19, record which tactic names were seen).
  - [x] Bump the default ATT&CK version and make it derived from the loaded data where possible.
- [x] **C3. Sentinel tactics mostly dropped [V].** `models/detection_rule.py:148` only swaps spaces/underscores, so CamelCase (`CredentialAccess`, `PrivilegeEscalation`, `DefenseEvasion`, `LateralMovement`, `InitialAccess`) is rejected; 2 of about 5 tactics captured on the fixtures.
  - [x] Normalize CamelCase to hyphenated form (split on capitals) before validation; add an alias table for Sentinel-specific names (e.g. `PreAttack`).
  - [x] Stop treating Sentinel `tags` as an ATT&CK source (`parsers/sentinel_parser.py:80`); it produces noise such as `Solorigate`, `NOBELIUM`, `DEV-0537`.
- [x] **C4. Revoked and deprecated techniques accepted as valid [V].** Live data: 149 revoked, 12 deprecated, 157 `revoked-by` relationships. v19 revoked broadly used techniques (e.g. Impair Defenses, Indicator Blocking, Clear Windows Event Logs).
  - [x] Validator must expose `is_revoked`, `is_deprecated` and `replaced_by`.
  - [x] Policy flag: warn, remap via `revoked-by`, or drop. Report remaps in the output.
  - [x] Count rules still mapped to revoked IDs in the report (a useful maintenance metric).
- [x] **C5. Elastic ingestion limited to hand-written YAML [V].**
  - [x] Add TOML (the `detection-rules` repo layout [U]) and NDJSON (Kibana export) parsing; extend `SUPPORTED_EXTENSIONS` and discovery.
  - [x] Content-based routing for `.json` instead of the extension fallback at `core/RuleRepository.py:441-444` (an Elastic-shaped JSON file was silently parsed as Sentinel with zero techniques).
  - [x] Relax the required-fields check at `parsers/elastic_parser.py:416`.
  - [x] When no parser matches, report it; never return an empty rule silently.
- [x] **C6. Report path and JSON serialization [V].**
  - [x] `main.py:367`: sanitize the filename component only, never the whole path (`output/rep.json` currently becomes `output_rep.json` in the CWD).
  - [x] `main.py:370`: serialize sets as sorted lists (custom encoder) instead of `default=str`.
  - [x] Create the output directory when it does not exist (see M3).
- [x] **C7. Temporal analysis ingests its own outputs [V].** The epilog recommends `--snapshots-directory output/` and the tool writes `executive_summary_*.json` and `time_series_data_*.json` there; the `*.json` glob (`core/temporal_analysis.py:297`) loads them as 0-rule snapshots.
  - [x] Identify snapshot files by content (required keys) and skip everything else with a debug message.
  - [x] Write temporal outputs to a separate subdirectory or a distinct filename pattern.
  - [x] Stop reverse-engineering rule counts from Navigator scores (`temporal_analysis.py:171`); read from the coverage report, or embed counts in layer metadata.
  - [x] Fix `tactics` metadata key mismatch (line 177) so Navigator-layer snapshots can report tactics.

---

## 2. High priority

- [x] **H1. Disabled rules counted as coverage [R].** `rule.enabled` is never read outside the parsers. Exclude by default; add `--include-disabled`; report the count.
- [x] **H2. Parent techniques never emitted [V].** Only `T1003.001` -> no `T1003` entry. `get_parent_techniques()` is unused.
  - [x] Emit parent entries (without double counting) and/or set layout `showAggregateScores` and `expandedSubtechniques` (`models/navigator_layer_model.py:382-388`) [U: layer format 4.5].
- [x] **H3. Stale default platform filter [V/R].** `navigator_layer_model.py:303-306` lists `Azure AD`, `Office 365`, `Network`; live data uses `Identity Provider`, `Office Suite`, `Network Devices`, `ESXi`, `Containers`, `IaaS`, `SaaS`, `PRE`. Navigator behavior with unknown names is untested. Default to no platform filter; make it opt-in via a flag; build the list from loaded data.
- [x] **H4. `--attack-version` ignored outside coverage mode [R].** `generators/layer_generator.py:226,320` use the default. Pass it through; validate against loaded data.
- [x] **H5. Wrong data version [V].** `mitre_validator.py:261` records STIX `spec_version` ("2.0"). The `mitre/cti` file has no `x-mitre-collection`. Use a source that exposes the real version (e.g. the versioned `attack-stix-data` files [U]) or read it from objects' `x_mitre_attack_spec_version`/release metadata, and record it in every output.
- [x] **H6. Retry configuration inert [V].** `mitre_validator.py:110`: `Retry(status=[...])` should be `status_forcelist=[...]`.
- [x] **H7. Tactic-technique pairing lost [R].** Keep the (tactic, technique) pairs from Elastic `threat[]` and emit a Navigator `tactic` field so multi-tactic techniques are not lit under every tactic.
- [x] **H8. No tests, no CI [V].**
  - [x] pytest suite with fixtures for Elastic YAML/TOML/NDJSON and Sentinel YAML/ARM JSON.
  - [x] Regression tests for C1-C7, H1-H6 first.
  - [x] GitHub Actions: pytest, flake8/ruff, mypy; Python version matrix (see M11).
  - [x] `pyproject.toml` with dependencies split into runtime and dev extras.

---

## 3. Medium priority

- [x] **M1.** Forbidden-path check is a substring match (`validators/security_validator.py:118-121`, `config.py:62-70`) and blocks `/home/me/proj/etc/rules/`, `/data/sys/rules/`, and everything under `/root/` [V]. Match on path components of the resolved path, and let the user opt out of `/root/` or configure the list.
- [x] **M2.** Symlink check is dead code (`security_validator.py:165,185`: `.resolve()` runs before `.is_symlink()`) [V]. Check before resolving; decide the policy (follow, refuse, or refuse when the target escapes the root).
- [x] **M3.** `-o results/x.json` fails when `results/` does not exist [V]. Create the parent directory.
- [x] **M4.** Depth calculation uses `root.replace(directory_path, '')` (`core/RuleRepository.py:181`); off by one with a trailing slash, and files at the depth limit are skipped [R]. Use `Path.relative_to`.
- [x] **M5.** Elastic risk-score to severity thresholds (75/50/25 in `parsers/elastic_parser.py:226-234`) may not match Elastic's documented bands (I recall low <22, medium 22-47, high 48-73, critical >=74) [U]. Verify and fix.
- [x] **M6.** `risk_score`/`priority` stored as lowercase strings in `parsers/base_parser.py:196` [R]. Keep a numeric `risk_score` separate from the normalized `severity`.
- [~] **M7.** (partly done: files are read once, stats aggregated on the calling thread, results deterministic, deep-copied statistics; NOT done: process-based parallelism for CPU-bound YAML, which needs measurement on a large rule set first) Performance [R]: each file is read and validated several times (every parser's `can_parse`, then `parse`); parsing stats counters are not locked; `get_statistics()` returns a shallow copy. Read once, pass content through; consider process-based parallelism for CPU-bound YAML; return deep copies.
- [x] **M8.** `errors='replace'` makes the `UnicodeDecodeError` branch unreachable (`base_parser.py:244,256`) [R]. Decide: strict with an error, or replace and record a parse warning.
- [x] **M9.** Sentinel parser [R]:
  - [x] ARM templates with multiple `alertRules` resources return only the first (`sentinel_parser.py:202-207`).
  - [x] Dead `displayName` fallback (line 304).
  - [x] Text-scan fallback pulls T-IDs from query text and can create false coverage; make it opt-in and tag the source.
- [x] **M10.** Temporal analysis [R]: coverage denominator hard-coded at 800 (`temporal_analysis.py:68`; v19 has 222 techniques + 475 sub-techniques [U: v19 release notes]); fixed CSV filenames are overwritten; naive vs timezone-aware timestamps can break sorting.
- [x] **M11.** README claims Python 3.8+ but `tuple[int, int]` annotations (`sentinel_parser.py:340`, `elastic_parser.py:246`) need 3.9+; 3.8 and 3.9 are end-of-life. Set the minimum to a supported version and say so in the README and CI.
- [x] **M12.** Online fetch downloads about 49 MB on every run with no on-disk cache [V]. Add a cache directory with ETag/If-Modified-Since or a pinned version; offline mode that uses the cache; `--attack-data-file` for air-gapped use. Decide between `mitre/cti` (STIX 2.0) and `attack-stix-data` (STIX 2.1) [U: both maintained].

---

## 4. Low priority and hygiene

- [x] **L1.** README documents `MITRE_ANALYZER_*` environment variables that no code reads [V]. Implement or remove.
- [x] **L2.** Placeholder repo URLs in README and `main.py:668`; README claims streaming/memory behavior that does not exist [V].
- [x] **L3.** Delete `package_inits.py` (stale, wrong module names). Add real exports to `parsers/__init__.py`.
- [x] **L4.** Remove tracked `.DS_Store` files (root and `tests/`) and add them to `.gitignore`.
- [x] **L5.** Label `sample_snapshots/` as synthetic, or generate it from the tool.
- [x] **L6.** Remove unused imports and placeholder-less f-strings flagged by pyflakes (`config.py`, `core/RuleRepository.py`, `core/temporal_analysis.py`, `main.py`, `parsers/elastic_parser.py`).
- [x] **L7.** Remove or wire in unused methods: `get_coverage_score`, `has_sub_techniques`, `get_rule_complexity_score`, `validate_technique_list`, `is_valid_tactic`, `get_techniques_by_tactic`, `is_safe_for_logging`, `validate_input_string`. Move the bottom-of-file `Path` import in `base_parser.py` to the top.
- [x] **L8.** Split dev tools out of `requirements.txt`; drop the redundant `urllib3[secure]` line (could not reproduce a pip warning here, so cosmetic).
- [x] **L9.** Tone down marketing language ("Enterprise", "CISO") in output text; tie the version string to packaging.

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

Goal (per owner): the tool derives what it can and emits a stable JSON Schema plus per-rule JSON files that other tools populate for the rest. The tool does not attempt to produce operational results, and does not call an LLM (D4).

Status: design only. The owner will supply an example Sentinel schema; reconcile the field names below against it before writing the JSON Schema.

#### Naming standard (D3 proposal)

Conventions
- JSON keys: `snake_case`, English, no abbreviations except well-known ones (`id`, `url`).
- Identifiers end in `_id`. Lists are plural (`tables`), single values singular.
- Durations: ISO 8601 (`PT1H`, `P7D`). Timestamps: RFC 3339 in UTC (`2026-11-09T16:24:31Z`). Enums: lowercase with hyphens or underscores as shown, always listed in the schema.
- `null` means "unknown / not provided"; an empty list means "known to be none". Consumers must be able to tell them apart.
- Every derived value that is a guess (query parsing, LLM) lives next to a `provenance` object; facts copied from the source rule do not need one.
- Avoid overloaded words. Use `source_platform`, `target_platforms`, `cloud_providers`, `source_version`, `revision_count`, `lookback`, `environment_id`; never a bare `platform`, `version` or `revision`.

File 1: `<detection_id>.detection.json` (tool-owned, regenerated every run)
- `schema_version`, `generated_by {tool, tool_version, generated_at}`
- `handling {sensitivity, notes}` where `sensitivity` is one of `public | internal | confidential | restricted`
- `identity {detection_id, id_origin (source|generated), source_rule_id, name, description}`
- `source {source_platform (elastic|sentinel|...), rule_kind (scheduled|nrt|eql|query|...), format (yaml|json|ndjson|toml), file_path (relative to the scanned root; never absolute), repository, source_version (string, as written), source_version_scheme (semver|integer|none), content_hash (sha256 of the normalized rule), revision_count (from VCS history, null if unavailable), created_at, modified_at}`
- `status {enabled, severity (informational|low|medium|high|critical), risk_score}`
- `schedule {frequency, lookback, lookback_source (rule|query), query_windows[]}` (durations ISO 8601; `query_windows` for `ago()`/`bin()`-style windows found inside the query, filled in B3)
- `data {tables[], fields {entity_mappings[], custom_details[], referenced[]}, target_platforms[], cloud_providers[]}`
  - `tables[]` items: `{name, origin (declared|query_parse), connector_or_integration}`
  - `entity_mappings[]` items: `{entity_type, identifier, column}`; `custom_details[]` items: `{key, column}`
  - `target_platforms` values come from the ATT&CK platform list in the loaded data (Windows, Linux, macOS, IaaS, SaaS, Containers, Identity Provider, Office Suite, Network Devices, ESXi, ...); `cloud_providers` values: `azure | aws | gcp | m365 | other`. Two fields because ATT&CK's `IaaS` does not say which cloud.
- `attack {attack_version, techniques[] {technique_id, tactic (null if unpaired), remapped_from}, tactics[], notes[]}`

File 2: `<detection_id>.enrichment.json` (owned by other tools; never overwritten by this tool)
- `schema_version`, `detection_id`, `handling`
- `analysis` (LLM or human authored): `intention {intent, logic, provenance}`, `method {categories[], parameters[], summary, provenance}`, each with `detection_content_hash` = the `source.content_hash` it was written against, so a changed rule makes the analysis detectably stale.
  - `provenance {producer (llm|human|tool), model, model_version, prompt_id, produced_at, reviewed (bool), reviewed_by, confidence}`
  - `method.categories` controlled vocabulary (extend in schema): `threshold | percentile | standard_deviation | series_anomaly | baseline_comparison | new_terms | sequence | correlation | indicator_match | machine_learning | signature`
- `environments[]`: `{environment_id, name, kind (production|staging|development|lab), notes}` (no tenant or workspace secrets in this file)
- `outcomes[]`: `{environment_id, rule_revision {source_version, content_hash}, window_start, window_end, counts {true_positive, benign_positive, false_positive, undetermined, false_negative}, source_system, notes}`
- `validation.bas_results[]`: `{environment_id, tool, test_id, technique_id, outcome (detected|partially_detected|not_detected|not_tested), executed_at, rule_revision {source_version, content_hash}}`

Why these choices
- A single `rule_revision` pair ties every outcome and BAS result to the exact rule it was measured against, so numbers cannot silently carry over to a rewritten rule.
- `false_negative` is only meaningful with a source that can know it (BAS, purple team, incident response); the schema permits `null` rather than 0.
- `source_version` is stored verbatim because Sentinel uses semver strings and Elastic uses integers [U]; the count of revisions is a separate VCS-derived field.

#### B0. Schema design
- [ ] Publish `schemas/detection.schema.json` and `schemas/enrichment.schema.json` (JSON Schema 2020-12, `$id`, `schema_version` semver, versioned independently of the tool).
- [ ] `additionalProperties: false` for the detection file; the enrichment file allows a namespaced `extensions` object (keys must start with `x_`) so other tools can add fields without a schema change.
- [ ] Output layout: one file of each kind per rule, named by `detection_id`, plus a JSONL index of detection files. Document naming for generated IDs.
- [ ] A `validate` subcommand that checks files against the schemas; ship example files for Elastic and Sentinel.
- [ ] Reconcile with the owner's example Sentinel schema before freezing names.

#### B1. Field derivability (what the tool can fill)

Source legend: P = parsed from structured fields, Q = needs query parsing, X = other tools populate, V = VCS history.

| Field | Where | Source | Notes |
|---|---|---|---|
| Detection GUID | `identity.detection_id`, `identity.id_origin`, `identity.source_rule_id` | P | D2. Sentinel `id`; Elastic `rule_id`. |
| Name, description | `identity.name`, `identity.description` | P | Keep the raw text. Parsers no longer append bracketed metadata to descriptions. |
| Tables used | `data.tables[]` | P, Q | Sentinel `requiredDataConnectors[].dataTypes` is structured. Elastic `index` patterns / `data_view_id`. Full KQL parsing (let-bound functions, ASIM parsers such as `imAuthentication` that expand to many tables, `union`, `join`) is B3. |
| Fields used (entity / custom detail) | `data.fields.entity_mappings[]`, `custom_details[]`, `referenced[]` | P (first two), Q (third) | Sentinel `entityMappings` and `customDetails` are structured [U: Microsoft ARM reference]. Elastic `required_fields` is informational only [U]. |
| Platform (Windows/Linux/Azure/GCP/...) | `data.target_platforms[]`, `data.cloud_providers[]` | P, Q | Derive from tables through a maintained table-to-platform lookup shared with F3; mark as inferred. |
| Number of revisions | `source.source_version`, `source.revision_count` | P, V | Do not infer a count from a semver string. |
| Lookback | `schedule.lookback`, `schedule.frequency`, `schedule.query_windows[]` | P, Q | Sentinel `queryPeriod`/`queryFrequency`; Elastic `from` and `interval` (date math such as `now-6m`) [U]. |
| True/benign/false positive, undetermined, false negative | `enrichment.outcomes[]` | X | |
| Environment | `enrichment.environments[]` | X | Sensitive (D6). |
| BAS results | `enrichment.validation.bas_results[]` | X | |
| Detection intention, detection method | `enrichment.analysis` | X (LLM or human) | Schema only (D4). |
| Severity, enabled, rule kind | `status`, `source` | P | Already parsed today. |
| ATT&CK mapping | `attack` | P | Done in the bug-fix pass: validated, revoked IDs remapped, tactic pairs kept. |

#### B2. Structured extraction (no query parsing required)
- [ ] Add a `DetectionRecord` model (sibling of `DetectionRule`) and a serializer producing the detection file; keep the existing model for layer generation.
- [ ] Sentinel: `requiredDataConnectors`, `entityMappings`, `customDetails`, `alertDetailsOverride`, `eventGroupingSettings`, `queryPeriod`, `queryFrequency`, `version`, `status`. The public docs I found confirm `entityMappings`, `customDetails`, `alertDetailsOverride` and `queryPeriod`/`queryFrequency`; they did not confirm the YAML `version` field or the `eventGroupingSettings` sub-fields, so base those on the fixtures and the owner's example schema [U].
- [ ] Elastic: `rule_id`, `index`, `data_view_id`, `required_fields`, `related_integrations`, `from`, `interval`, `version`, `risk_score`, `severity`, `type`, `language`.
- [ ] Duration normalization helper (`5m`, `1h`, `P1D`, `now-6m`, `7d`) to ISO 8601, with tests.
- [ ] Preserve the raw query text and language (`kql`, `eql`, `esql`, `lucene`) so later stages can use it.
- [ ] `source.content_hash`: sha256 over a normalized form of the rule (key order and comments removed) so cosmetic edits do not invalidate enrichment.

#### B3. Table and field extraction from queries (second phase)
- [ ] Evaluate KQL parser options in Python (none first-party that I verified) and record the decision. Regex is acceptable only as a labeled best-effort mode.
- [ ] Handle `let` bindings, user functions, ASIM/normalization parsers (map known parser names to underlying tables; data file shared with F3), `union`, `join`, `externaldata`, watchlists.
- [ ] Mark each extracted table and field with `origin` (`declared` vs `query_parse`) and confidence.

#### B4. Detection method extraction (deterministic, no LLM)
- [ ] KQL `summarize`, `count()`/`dcount()` thresholds in `where`, `percentile()`/`percentiles()`, `stdev()`, `avg`, `make-series`, `series_decompose_anomalies`, `series_fit_*`, `bin()`; Elastic `threshold`, `new_terms`, ML job references, EQL `sequence ... maxspan`.
- [ ] Output method category tags (controlled vocabulary above) with extracted numeric parameters. Written to `data`/`schedule` in the detection file when deterministic; the enrichment `analysis.method` stays reserved for external (LLM/human) analysis.

#### B5. LLM output schema only (per D4)
- [ ] Define `analysis.intention`, `analysis.method` and `provenance` in `enrichment.schema.json` (see naming standard). No LLM client, prompts, redaction, caching or evaluation code in this tool.
- [ ] Document the contract for producers: required provenance fields, the `detection_content_hash` rule, and that consumers must treat `reviewed: false` content as unverified.

#### B6. Skeleton, staleness and lifecycle (per D1)
- [ ] When generating a detection file, create an empty `enrichment.json` skeleton only if none exists; never modify an existing one.
- [ ] `check-enrichment` command: report enrichment files whose recorded `detection_content_hash` or `rule_revision` no longer matches the current rule (stale), whose detection no longer exists (orphaned), and detections without enrichment.
- [ ] Deleted or renamed rules: keep enrichment files, report them as orphaned; with generated IDs (D2) a rename creates a new ID, so document how to move an enrichment file.
- [ ] Document the contract for external tools: where the schemas live, which file they may write, how to supply provenance.

#### B7. Concerns tracked from the design review
- [x] Regeneration clobbering externally supplied data -> resolved by the two-file model (D1) and B6.
- [x] Sending rule content to an external LLM -> out of scope for the tool (D4).
- [ ] Overloaded terms -> naming standard above; confirm against the owner's example schema.
- [ ] Heuristic outputs presented as facts -> `origin`/`provenance` on every derived value (B0, B3).
- [ ] Outcome metrics without window or revision -> `rule_revision`, `window_start`, `window_end` required in `outcomes[]`.
- [ ] Generated-ID stability on rename (D2) -> documented limitation; revisit if it hurts.

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

1. (done) Sections 1-4: bug fixes, tests, CI, documentation.
2. Receive the owner's example Sentinel schema; reconcile the naming standard (B0).
3. B0, B2, B6: schemas, detection-file serializer, enrichment skeleton and staleness check.
4. F1-F3: ATT&CK detection strategies, analytics, data components, and the table-to-data-component mapping file (it also feeds `data.target_platforms`).
5. B3-B4: query parsing and deterministic method extraction.
6. F4-F7, then Track C.
7. Optional engineering follow-ups: mypy pass, process-based parsing if profiling on a large rule set shows a need (M7), Navigator UI check of H2/H7 behavior.
