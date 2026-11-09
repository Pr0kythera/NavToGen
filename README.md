# NavToGen - MITRE ATT&CK Coverage Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)

A tool for analyzing MITRE ATT&CK coverage across detection rule repositories. This analyzer transforms your detection rules from Elastic Security and Microsoft Sentinel into actionable coverage visualizations, helping security teams identify gaps and optimize their detection strategies.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Why Use This Tool](#why-use-this-tool)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Comprehensive Usage Guide](#comprehensive-usage-guide)
- [Supported Rule Formats](#supported-rule-formats)
- [Analysis Modes](#analysis-modes)
- [Advanced Features](#advanced-features)
- [Architecture Overview](#architecture-overview)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Security Considerations](#security-considerations)
- [License](#license)

## Overview

NavToGen bridges the gap between your detection rule repositories and strategic security insights. Instead of manually tracking which MITRE ATT&CK techniques your detection rules cover, this tool automatically parses your rule sets, extracts technique mappings, validates them against the official ATT&CK framework, and generates professional visualizations using the MITRE ATT&CK Navigator.

Think of this tool as your "detection coverage translator" - it takes the technical details buried in hundreds of detection rules and transforms them into clear, actionable intelligence that security leaders can use to make informed decisions about their defensive posture.

### What Makes This Tool Different

Unlike simple regex-based extractors, this analyzer understands the specific formats and structures used by different SIEM platforms. It knows that Elastic Security stores MITRE ATT&CK information in structured `threat` objects, while Microsoft Sentinel uses various field names like `tactics`, `techniques`, or `relevantTechniques`. This format-aware parsing ensures you capture the complete picture of your detection coverage.

## Key Features

### Intelligent Rule Parsing
The analyzer includes specialized parsers for both Elastic Security Detection Engine rules and Microsoft Sentinel Analytics Rules. Each parser understands the specific format and structure used by its platform, ensuring accurate technique extraction from the appropriate fields rather than relying on error-prone text searches.

### Multiple Analysis Modes
Beyond basic coverage analysis, the tool provides several specialized analysis modes. Coverage analysis shows which techniques you detect and how well they're covered. Platform comparison reveals differences between your Elastic and Sentinel deployments, highlighting redundancies and gaps. Frequency analysis identifies your most and least commonly detected techniques, helping prioritize rule development efforts.

### Security-First Design
Enterprise environments require robust security measures. This tool implements comprehensive input validation, path traversal prevention, file size limits, and secure error handling. It validates all file operations and user inputs to prevent common attack vectors while maintaining detailed logging for audit purposes.

### Performance Optimization
Large rule repositories can contain hundreds or thousands of detection rules. The analyzer includes concurrent processing capabilities that dramatically reduce analysis time for large rule sets while maintaining accuracy and reliability through proper error isolation and resource management.

### MITRE ATT&CK Framework Integration
When enabled, the tool fetches the latest MITRE ATT&CK framework data directly from the official repository, validating your extracted techniques against the authoritative source and enriching your analysis with official technique metadata, descriptions, and tactical context.

## Why Use This Tool

### For Security Operations Centers
Security analysts spend countless hours manually tracking detection coverage across different platforms. This tool automates that process, providing instant visibility into which attack techniques you can detect, where you have coverage gaps, and how your detection capabilities compare across platforms.

### For Security Architects
When designing detection strategies, you need to understand your current coverage baseline and identify areas requiring attention. The analyzer provides comprehensive coverage reports that inform strategic decisions about rule development priorities and platform investments.

### For Compliance and Risk Management
Many compliance frameworks require demonstrating detection capabilities against common attack patterns. The tool generates professional reports and visualizations that clearly communicate your detection coverage to auditors, executives, and other stakeholders.

### For Detection Engineers
Rule developers need to understand the broader context of their work and avoid duplicating existing coverage. The frequency analysis mode helps identify over-represented techniques while the gap analysis highlights areas needing additional detection rules.

## Installation

### Prerequisites

- **Python 3.11 or newer** (TOML rule support uses the standard library `tomllib`)
- **Network access (optional)**: only needed to download ATT&CK data for validation. The data is cached on disk, and a local file can be used instead (`--attack-data-file`) for offline or air-gapped use.

### Standard installation

```bash
git clone https://github.com/Pr0kythera/NavToGen.git
cd NavToGen
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py --version
```

### Development installation

```bash
pip install -r requirements-dev.txt
python -m pytest        # run the test suite
ruff check .            # lint
```

CI runs the same two commands on Python 3.11, 3.12 and 3.13.

## Quick Start

### Your First Analysis

Let's start with a simple coverage analysis to get familiar with the tool. This example assumes you have a directory containing detection rules from either Elastic Security or Microsoft Sentinel:

```bash
python main.py -p /path/to/your/rules -o my_first_coverage.json
```

This command tells the analyzer to examine all rules in the specified path and generate a Navigator layer showing your detection coverage. The output file `my_first_coverage.json` can be imported directly into the MITRE ATT&CK Navigator for visualization.

### Viewing Your Results

After running the analysis, you'll have a JSON file that represents your detection coverage. To visualize this data:

1. Open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) in your web browser
2. Click "Open Existing Layer" in the navigation menu
3. Select "Upload from local" and choose your generated JSON file
4. Explore your coverage using the Navigator's interactive interface

The visualization will show your covered techniques in color, with different shades indicating coverage depth. Green typically represents strong coverage (multiple rules), yellow indicates moderate coverage, and red shows minimal coverage that might warrant attention.

### Understanding Your First Results

When you examine the Navigator visualization, you'll notice several important patterns. Techniques covered by multiple detection rules appear in darker colors, indicating robust detection capabilities. Lighter colors suggest areas where you have some detection but might benefit from additional rules. Completely uncovered techniques appear without coloring, representing potential gaps in your detection strategy.

## Comprehensive Usage Guide

### Basic Coverage Analysis

The foundation of detection analysis is understanding which MITRE ATT&CK techniques you currently detect. The basic coverage analysis mode examines all your detection rules, extracts MITRE ATT&CK technique references, and creates a visualization showing your coverage landscape:

```bash
python main.py \
    --path /opt/detection-rules \
    --output coverage_analysis.json \
    --log-level INFO
```

This analysis provides several valuable insights. You'll see which techniques have strong coverage through multiple rules, which techniques have minimal coverage that might be vulnerable to bypasses, and which techniques lack coverage entirely. The tool automatically handles both main techniques (like T1055) and sub-techniques (like T1055.001), ensuring you get a complete picture of your detection granularity.

### Platform Comparison Analysis

One of the most powerful features is comparing detection coverage between different SIEM platforms. If your organization uses both Elastic Security and Microsoft Sentinel, this analysis reveals where you have redundant coverage, where each platform has unique strengths, and where gaps exist across both platforms:

```bash
python main.py \
    --path /opt/detection-rules \
    --output platform_comparison.json \
    --comparison-mode \
    --log-level INFO
```

The resulting visualization uses a color-coded system to show platform-specific coverage. Green indicates techniques covered by both platforms, providing redundancy and confidence in your detection capabilities. Blue shows techniques detected only by Elastic, while orange indicates Sentinel-only coverage. This analysis helps optimize platform deployments and identify single points of failure in your detection architecture.

### Analysis with ATT&CK Validation

Validation checks every extracted technique against the official ATT&CK data:

```bash
# Download (and cache) the latest ATT&CK data
python main.py -p /opt/detection-rules -o validated.json --validate-online --report report.json

# Pin a release (the newest 19.x), useful for reproducible results
python main.py -p /opt/detection-rules --validate-online --attack-version 19

# Offline: use a STIX bundle you downloaded earlier
python main.py -p /opt/detection-rules --attack-data-file enterprise-attack.json
```

What validation does:

- **Removes unknown and deprecated techniques** that cannot be shown in Navigator.
- **Handles revoked techniques.** ATT&CK revokes techniques and names a replacement (for example `T1562.001` was replaced by `T1685` in ATT&CK v19). `--revoked-policy remap` (default) replaces the revoked ID with its successor and lists every remap in the report; `drop` removes it; `keep` leaves it (Navigator will not display revoked techniques). Note that a replacement can be a different level of the hierarchy (a sub-technique can become a technique).
- **Uses the real tactic list** from the ATT&CK data. ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment; rules that still say Defense Evasion are accepted and flagged.
- **Stamps the real ATT&CK version** on the layer and in the report.

If validation was requested but the data cannot be loaded, the tool exits with an error (code 2) instead of silently producing unvalidated results. Pass `--allow-unvalidated` to continue anyway; the summary then states that validation was not performed. If a download fails but an older cached copy exists, the cached copy is used and a warning says so.

Downloads come from the [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) repository (STIX 2.1, which includes the release version) and are cached under `$XDG_CACHE_HOME/navtogen` (default `~/.cache/navtogen`) for 24 hours, then revalidated with an ETag so an unchanged 50 MB file is not downloaded again. Use `--cache-dir`, `--no-cache` and `--refresh-attack-data` to control this.

### Frequency Analysis for Strategic Planning

Understanding which techniques appear most frequently in your detection rules helps inform strategic decisions about rule development and maintenance priorities:

```bash
python main.py \
    --path /opt/detection-rules \
    --output frequency_analysis.json \
    --frequency-mode \
    --validate-online \
    --log-level INFO
```

Frequency analysis reveals patterns in your detection strategy that might not be immediately obvious. Techniques covered by many rules might indicate either strong security focus or potential redundancy worth optimizing. Techniques covered by very few rules might represent either specialized detections for specific threats or areas where additional coverage could improve your security posture.

## Supported Rule Formats

| Platform | Formats |
|---|---|
| Elastic Security | YAML; JSON (Kibana / Detections API); NDJSON exports (many rules per file); TOML as used by the `elastic/detection-rules` repository |
| Microsoft Sentinel | YAML templates (Azure-Sentinel layout); ARM templates with one or more alert rule resources; API-style JSON |

Files are routed to a parser by **content**, not by extension: each parser scores how well a file matches its format and the best match wins. Files no parser recognizes are counted and listed in the report (`errors.unrecognized_files`) instead of being parsed as the wrong platform.

Notes:

- Sentinel tactic names in CamelCase (`CredentialAccess`) and Elastic names ("Credential Access") are both normalized to ATT&CK short names.
- The Sentinel `tags` field is ignored for ATT&CK data. Technique IDs mentioned only in free text are not counted unless you pass `--text-fallback`.
- Disabled rules are excluded from coverage unless you pass `--include-disabled`.
- Elastic rules declare which tactic each technique belongs to; `--tactic-scoped` keeps that pairing in the layer so a technique that exists under several tactics is only coloured under the declared one. This flag is new and has not been checked in the Navigator UI itself, so compare against the default output the first time you use it.
- YAML 1.1 quirk: an unquoted `name: Off`/`No`/`On`/`Yes` is read as a boolean by YAML parsers. Quote such names.

## Analysis Modes

### Coverage Analysis Mode (Default)

Coverage analysis forms the foundation of detection assessment, providing a comprehensive view of which MITRE ATT&CK techniques your detection rules address. This mode processes all your detection rules, extracts technique references, and creates a color-coded visualization that immediately reveals your detection strengths and gaps.

The analysis uses intelligent scoring to indicate coverage quality. Techniques covered by multiple rules receive higher scores and appear in green, indicating robust detection capabilities that are less likely to be bypassed by minor evasion techniques. Techniques covered by only one or two rules appear in yellow or red, suggesting areas where additional detection rules might strengthen your security posture.

When you examine the results, pay particular attention to critical tactics like Initial Access, Execution, and Defense Evasion. Strong coverage in these areas often correlates with effective overall security, as they represent the most common attack entry points and evasion techniques.

### Platform Comparison Mode

Platform comparison analysis addresses one of the most common challenges in modern security operations: understanding how detection capabilities differ across multiple SIEM platforms. This mode separates your rules by platform and creates a side-by-side comparison that reveals coverage overlaps, gaps, and unique strengths.

The visualization uses a three-color system that provides immediate strategic insights. Green indicates techniques covered by both platforms, representing your most resilient detection capabilities. If one platform fails or requires maintenance, you maintain detection coverage through the other platform.

Blue represents techniques detected only by Elastic Security, while orange shows Microsoft Sentinel-only coverage. These platform-specific areas require careful consideration. They might represent legitimate specializations where each platform excels, or they might indicate gaps that create vulnerabilities if one platform is unavailable.

Understanding platform-specific coverage helps optimize resource allocation and platform utilization. You might discover that certain attack techniques are better detected by one platform's native capabilities, informing decisions about where to focus rule development efforts.

### Frequency Analysis Mode

Frequency analysis takes a quantitative approach to understanding your detection rule portfolio, counting how many rules address each MITRE ATT&CK technique and revealing patterns in your detection strategy.

This analysis mode proves particularly valuable for detection engineering teams managing large rule repositories. Techniques appearing in many rules might indicate either strong security focus on high-priority threats or potential redundancy that could be optimized through rule consolidation.

Conversely, techniques appearing in very few rules might represent either highly specialized detections for specific threat actors or potential gaps where additional coverage could improve your overall security posture. The frequency analysis helps prioritize rule development efforts by identifying both over-represented and under-represented attack techniques.

The visualization scales technique colors based on frequency, with darker colors indicating more rules covering that technique. This creates a heat map effect that immediately draws attention to your most and least covered attack techniques, facilitating strategic discussions about detection priorities.

## Advanced Features

### Concurrent Processing for Large Repositories

Enterprise detection rule repositories can contain hundreds or thousands of individual rules across multiple formats and platforms. Processing these sequentially would be time-consuming and inefficient. The analyzer includes sophisticated concurrent processing capabilities that dramatically improve performance for large rule sets.

The concurrent processing system automatically decides when to use parallel processing based on the number of files and available system resources. For smaller rule sets, sequential processing provides better debugging capabilities and resource efficiency. For larger sets, the tool spawns multiple worker threads that process rules in parallel while maintaining error isolation and result accuracy.

You can control the level of concurrency based on your system capabilities and analysis requirements:

```bash
# Use maximum concurrency for fastest processing
python main.py \
    --path /opt/large-rule-repository \
    --output coverage.json \
    --max-workers 8

# Disable concurrency for debugging
python main.py \
    --path /opt/detection-rules \
    --output coverage.json \
    --no-threading \
    --log-level DEBUG
```

The concurrent processing implementation includes sophisticated error handling that ensures individual rule parsing failures don't impact the overall analysis. If one rule fails to parse due to format issues or corruption, the system continues processing other rules and provides detailed error reporting for troubleshooting.

### Comprehensive Logging and Monitoring

Professional security tools require comprehensive logging for operational monitoring, troubleshooting, and audit purposes. The analyzer includes a sophisticated logging system that provides multiple output options and detail levels to meet different operational needs.

During analysis, the tool provides real-time progress updates, performance metrics, and detailed error information. The logging system automatically adapts its output based on the context, providing concise updates for normal operations and detailed diagnostic information when problems occur.

For production environments, you can configure file-based logging that captures all analysis details for later review:

```bash
python main.py \
    --path /opt/detection-rules \
    --output coverage.json \
    --log-level INFO \
    --log-file analysis.log
```

The log files include structured information about parsing success rates, performance metrics, error details, and validation results. This information proves valuable for monitoring the health of your detection rule repository and identifying rules that might need attention or updating.

### Detailed Reporting and Analytics

Beyond the Navigator layer visualization, the analyzer can generate comprehensive reports that provide deep insights into your detection coverage and rule repository health:

```bash
python main.py \
    --path /opt/detection-rules \
    --output coverage.json \
    --report comprehensive_analysis.json \
    --validate-online
```

The detailed reports include statistical analysis of your rule repository, including parsing success rates, technique frequency distributions, platform coverage comparisons, and quality metrics. These reports prove particularly valuable for security leadership, compliance reporting, and strategic planning purposes.

The report format is structured JSON that can be easily integrated with other security tools, dashboards, or reporting systems. You might use this data to populate security metrics dashboards, feed into GRC platforms, or support periodic security assessments.

### MITRE ATT&CK Framework Integration

The tool's integration with the official MITRE ATT&CK framework represents one of its most powerful features, providing authoritative validation and enrichment of your analysis results. When enabled, the system downloads the latest framework data directly from MITRE's official repository and uses it to validate and enhance your technique extraction.

This integration serves multiple important purposes. First, it ensures that your analysis reflects the current state of the ATT&CK framework rather than potentially outdated information embedded in the tool. The framework evolves regularly, with new techniques added and existing techniques updated based on emerging threat intelligence.

Second, the validation process identifies and removes invalid technique references that might appear in your rules due to typos, outdated information, or transcription errors. This cleaning process ensures that your coverage analysis accurately reflects real MITRE ATT&CK techniques rather than including false positives that could skew your understanding.

Finally, the framework integration enriches your analysis with official technique metadata, including names, descriptions, platforms, tactics, and data sources. This additional context helps security teams understand not just which techniques they detect, but also the broader tactical context and potential impact of coverage gaps.

## Architecture Overview

### Modular Design Philosophy

NavToGen is built using a modular architecture that separates concerns and makes the system easy to understand, maintain, and extend. Rather than building everything in a single large file, the system is organized into specialized modules that each handle specific aspects of the analysis process.

This modular approach provides several significant advantages. Individual components can be developed, tested, and maintained independently, making the system more reliable and easier to troubleshoot. New features or support for additional SIEM platforms can be added without modifying existing code, reducing the risk of introducing bugs or breaking existing functionality.

The architecture also supports different deployment scenarios and use cases. Development teams can focus on specific modules relevant to their needs, while operations teams can configure logging and monitoring without understanding parsing internals.

### Core Components

The system consists of several key components that work together to provide comprehensive analysis capabilities:

**Models Package**: Contains the data structures that represent detection rules and Navigator layers throughout the system. These models provide a consistent interface that all other components can rely on, regardless of the original rule format or target output format.

**Validators Package**: Implements all security validation and input sanitization logic. This separation ensures that security concerns are handled consistently throughout the system and makes it easy to audit and update security measures as threats evolve.

**Parsers Package**: Contains format-specific parsing logic for different SIEM platforms. Each parser understands the specific structure and conventions used by its target platform, ensuring accurate technique extraction from the appropriate fields and contexts.

**Core Package**: Provides the orchestration and business logic that coordinates the overall analysis process. This package manages rule discovery, parser selection, validation, and result aggregation while providing a clean interface for the main application.

**Generators Package**: Handles the creation of Navigator layers and other output formats. This separation makes it easy to add support for additional output formats or visualization tools without affecting the analysis logic.

**Utils Package**: Contains common utilities like logging configuration and other shared functionality used throughout the system.

### Security Architecture

Security considerations are woven throughout the architecture rather than being treated as an afterthought. The system implements defense in depth with multiple layers of protection against common attack vectors.

Input validation occurs at multiple levels, starting with command-line argument validation and continuing through file path validation, file content validation, and technique ID validation. This layered approach ensures that malicious inputs are caught early and handled safely.

File operations use comprehensive security checks that prevent path traversal attacks, enforce size limits to prevent resource exhaustion, and validate file permissions before attempting access. These measures protect both the system running the analysis and any network resources that might be accessible.

Error handling is designed to be secure by default, providing useful information for troubleshooting while avoiding the disclosure of sensitive system information that could aid attackers. All error messages are sanitized and logged appropriately for audit purposes.

### Performance Architecture

Each file is read and decoded once, then offered to every parser for scoring. Parsing runs in a thread pool for larger rule sets, and results are combined on the calling thread in input order so runs are deterministic. ATT&CK data is downloaded at most once per cache period and shared by all validation. Whole rule sets are held in memory (a rule is a small object); there is no streaming mode.

## Configuration

### Command-line options

Run `python main.py --help` for the full list. The main groups:

| Option | Purpose |
|---|---|
| `-p/--path`, `-o/--output` | Rules directory; layer output path (missing directories are created) |
| `--comparison-mode`, `--frequency-mode`, `--temporal-analysis` | Analysis modes |
| `--validate-online`, `--attack-data-file`, `--attack-version`, `--revoked-policy`, `--allow-unvalidated` | ATT&CK validation |
| `--cache-dir`, `--no-cache`, `--refresh-attack-data` | ATT&CK data cache |
| `--rule-type`, `--include-disabled`, `--text-fallback` | Which rules and what counts as coverage |
| `--tactic-scoped`, `--platforms` | Layer options. No platform filter is applied unless you pass `--platforms` |
| `--report` | Detailed JSON report. A bare filename is written under `output/` |
| `--max-workers`, `--no-threading` | Parallelism |
| `--log-level`, `--log-file`, `--quiet` | Logging |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Analysis failed (no rules found or parsed, no techniques, output could not be written) |
| 2 | Invalid arguments, or validation was requested but the ATT&CK data could not be loaded |
| 130 | Interrupted |

### Constants

Limits such as the maximum file size, directory depth, forbidden system path prefixes and default worker count are constants in `config.py`. There are no environment-variable overrides (earlier versions of this README described some; they never existed).

## Troubleshooting

### Common Issues and Solutions

**Issue**: Files are reported as an unrecognized format.

**Solution**: A parser claims a file only if it contains enough fields of its format (for example `rule_id`, `risk_score`, `threat` for Elastic; `kind`, `queryFrequency`, `tactics`, `relevantTechniques` for Sentinel). Run with `--log-level DEBUG` to see each parser's score per file, and check `errors.unrecognized_files` in the report.

**Issue**: Analysis completes but shows very few techniques extracted from rules.

**Solution**: This often happens when technique references are embedded in non-standard fields or use unusual formats. Review your rules to ensure MITRE ATT&CK techniques are properly referenced in the expected fields. For Elastic rules, techniques should be in `threat.technique.id` fields. For Sentinel rules, check `tactics`, `techniques`, or `relevantTechniques` arrays.

**Issue**: The tool fails with network-related errors when using `--validate-online`.

**Solution**: Validation needs ATT&CK data. Behind a proxy, set `HTTPS_PROXY`. Offline, download `enterprise-attack.json` from attack-stix-data once and use `--attack-data-file`. A recent cached copy is reused automatically.

**Issue**: Analysis is very slow for large rule repositories.

**Solution**: Files are read once and parsed in a thread pool when there are more than 10 of them (`--max-workers`). YAML parsing is CPU-bound, so extra threads help less than they would for I/O; the PyYAML C extension (`libyaml`) is used automatically when available.

### Debugging Techniques

When troubleshooting issues, start by enabling debug logging to get detailed information about the analysis process:

```bash
python main.py \
    --path /opt/detection-rules \
    --output debug_analysis.json \
    --log-level DEBUG \
    --log-file debug.log
```

Debug logging provides detailed information about file discovery, parser selection, technique extraction, and validation results. This information typically reveals the root cause of analysis issues.

For parsing issues with specific rules, try analyzing a small subset of rules or individual files to isolate the problematic rules. You can then examine these rules manually to understand why the parsing is failing and either fix the rules or report the issue for tool improvement.

If you encounter performance issues, monitor system resources during analysis to identify bottlenecks. The tool provides performance metrics in its output that can help identify whether issues are related to disk I/O, CPU processing, or memory usage.

### Getting Help

For issues not covered in this troubleshooting section, several resources are available:

1. **GitHub Issues**: Report bugs, request features, or ask questions through the project's GitHub issue tracker. Include log files, example rule files (sanitized for security), and detailed descriptions of the issue.

2. **Debug Logs**: When reporting issues, always include debug logs generated with `--log-level DEBUG`. These logs contain detailed information that helps diagnose problems quickly.

3. **Community Support**: Check existing GitHub issues for similar problems and solutions. The community often provides helpful suggestions and workarounds for common challenges.

## Contributing

### Development Setup

```bash
git clone https://github.com/Pr0kythera/NavToGen.git
cd NavToGen
python -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest --cov=.
ruff check .
```

### Code Style and Standards

The project follows established Python coding standards and uses automated tools to maintain code quality and consistency. Lint with `ruff` (currently errors and pyflakes rules only).

Code should include comprehensive docstrings that explain not just what functions do, but why they exist and how they fit into the broader system architecture. This documentation is crucial for maintaining the system as it evolves and helping new contributors understand the codebase.

Type hints are used throughout; a mypy pass is tracked in TODO.md.

### Adding New SIEM Platform Support

Create a parser class in the `parsers` package that inherits from `BaseRuleParser` and implement three methods:

- `get_supported_extensions()`: the file extensions it can read.
- `score(records, file_path)`: given the decoded records of a file (a list of dicts), return how confident you are that they are your format. Return 0 if they are not. The repository picks the highest score.
- `parse_records(records, file_path)`: convert records into `DetectionRule` objects, skipping records that are not rules, and call `update_statistics()` once per rule.

File reading, size limits, UTF-8 handling and decoding of YAML, JSON, TOML and NDJSON are done for you (`read_rule_file`, `decode_structured`); `parse(path)` and `can_parse(path)` are provided on top of the three methods. Register the parser in `RuleRepository.__init__`. Study the Elastic and Sentinel parsers for the expected patterns.

### Testing Guidelines

All new features and bug fixes should include comprehensive tests that verify correct behavior under various conditions. The test suite uses pytest; `tests/` contains unit tests per module and end-to-end CLI tests. Every bug fix should come with a regression test.

When adding new parsers, include test cases that cover various rule formats, edge cases, and error conditions. Test files should use sanitized or synthetic rule data that doesn't expose real organizational security information.



## Security Considerations

### Security by Design

Security considerations are integrated throughout the system architecture rather than being treated as an add-on feature. Every component that handles external input implements appropriate validation and sanitization measures to prevent common attack vectors.

The system assumes that rule files and directories might contain malicious content designed to exploit parsing vulnerabilities or gain unauthorized system access. All file operations include comprehensive security checks that validate paths, enforce size limits, and prevent access to sensitive system resources.

Input validation occurs at multiple levels, from command-line arguments through file content processing. This defense-in-depth approach ensures that malicious inputs are caught early and handled safely without exposing system vulnerabilities.

### Deployment Security

When deploying the analyzer in production environments, consider the security implications of the analysis process and the sensitivity of the rule files being processed. Detection rules often contain information about security monitoring capabilities that could be valuable to attackers.

Run the analyzer with appropriate user permissions that provide access to rule files without granting unnecessary system privileges. Consider using dedicated service accounts with minimal required permissions rather than running with administrative or root access.

If using online validation features, ensure that network access is appropriately controlled and monitored. The tool only accesses the official MITRE ATT&CK repository, but network monitoring helps verify this behavior and detect any anomalous connections.

### Data Protection

The analyzer processes detection rule files that may contain sensitive information about your security monitoring capabilities. Ensure that analysis results, log files, and temporary files are protected with appropriate access controls and encryption where required by organizational policies.

When sharing analysis results or seeking support, sanitize any data that might reveal specific security monitoring capabilities or organizational infrastructure details. The tool's debug logging can be verbose and might inadvertently include sensitive information from rule files.

Consider the retention requirements for analysis results and log files, implementing appropriate data lifecycle management that balances operational needs with security and compliance requirements.

## License

This project is licensed under the MIT License, which provides broad permissions for use, modification, and distribution while limiting liability and requiring attribution. See the LICENSE file for complete license terms and conditions.

The MIT License was chosen to encourage adoption and contribution while providing legal clarity for enterprise users. Organizations can use, modify, and integrate the tool into their security operations without complex licensing restrictions or fees.

---

**Ready to transform your detection rule analysis?** Start with the [Quick Start](#quick-start) guide and discover how NavToGen can show where your detections cover ATT&CK.

For questions, issues, or contributions, please visit our [GitHub repository](https://github.com/Pr0kythera/NavToGen) .
