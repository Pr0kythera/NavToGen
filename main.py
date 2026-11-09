#!/usr/bin/env python3
"""
NavToGen - MITRE ATT&CK Coverage Analyzer
=========================================

Command-line entry point. Parses Elastic Security and Microsoft Sentinel detection rules,
maps them to MITRE ATT&CK, and generates ATT&CK Navigator layers, reports and temporal
trend analysis.

Usage examples:
    # Basic coverage analysis
    python main.py -p /path/to/rules -o coverage_layer.json

    # Platform comparison, validated against ATT&CK data
    python main.py -p /path/to/rules -o comparison.json --comparison-mode --validate-online

    # Offline validation with a local ATT&CK STIX bundle
    python main.py -p /path/to/rules --attack-data-file enterprise-attack.json

    # Temporal analysis of earlier coverage reports
    python main.py --temporal-analysis --snapshots-directory snapshots/

Exit codes:
    0   success
    1   analysis failed (no rules, no techniques, I/O error)
    2   invalid arguments, or ATT&CK validation was requested but could not run
    130 interrupted
"""

import argparse
import json
import logging
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from models.detection_rule import DetectionRule
from validators.security_validator import SecurityValidator
from validators.mitre_validator import MitreAttackValidator
from core.RuleRepository import REVOKED_POLICIES, RuleRepository
from core.temporal_analysis import TemporalAnalyzer
from generators.layer_generator import NavigatorLayerGenerator
from utils import setup_logging, create_logger, log_function_timing

logger = create_logger(__name__)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_BAD_ARGS = 2
EXIT_INTERRUPTED = 130


class AnalysisSession:
    """One complete analysis run, from argument handling to output files."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.start_time = datetime.now()
        self.mitre_validator: Optional[MitreAttackValidator] = None
        self.repository: Optional[RuleRepository] = None
        self.generator: Optional[NavigatorLayerGenerator] = None
        self.results: Dict[str, Any] = {}
        self.disabled_excluded = 0
        self.analyzed_rules: List[DetectionRule] = []

        logger.info(f"Analysis session initialized at {self.start_time}")

    @log_function_timing
    def run(self) -> int:
        """Execute the analysis workflow and return the process exit code."""
        try:
            if self.args.temporal_analysis:
                return self._run_temporal_analysis()

            logger.info("Starting MITRE ATT&CK coverage analysis")

            if not self._initialize_components():
                return EXIT_BAD_ARGS

            rule_files = self._discover_rules()
            if not rule_files:
                logger.error("No valid rule files found - analysis cannot proceed")
                return EXIT_FAILED

            rules = self._parse_rules(rule_files)
            if not rules:
                logger.error("No rules were successfully parsed - analysis cannot proceed")
                return EXIT_FAILED

            layer = self._generate_layer(rules)
            if not layer:
                return EXIT_FAILED

            self._save_results(layer)
            self._display_completion_summary()

            logger.info("Analysis completed successfully")
            return EXIT_OK

        except KeyboardInterrupt:
            logger.info("Analysis interrupted by user")
            return EXIT_INTERRUPTED

        except Exception as e:
            logger.error(f"Unexpected error during analysis: {e}")
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return EXIT_FAILED

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _wants_validation(self) -> bool:
        return bool(self.args.validate_online or self.args.attack_data_file)

    def _initialize_components(self) -> bool:
        """
        Create the validator, repository and generator.

        Returns False (after logging why) when validation was requested but could not be
        performed and ``--allow-unvalidated`` was not given: silently continuing would
        produce results the user believes were validated.
        """
        logger.info("Initializing analysis components...")

        if self._wants_validation():
            validator = MitreAttackValidator(
                cache_dir=self.args.cache_dir, use_cache=not self.args.no_cache)

            if self.args.attack_data_file:
                loaded = validator.load_from_file(self.args.attack_data_file)
            else:
                loaded = validator.fetch_mitre_data(
                    force_refresh=self.args.refresh_attack_data, version=self.args.attack_version)

            if loaded:
                summary = validator.get_validation_summary()
                logger.info(f"ATT&CK data loaded: version {summary['data_version'] or 'unknown'}, "
                            f"{summary['technique_count']} techniques, {summary['tactic_count']} tactics")
                if summary['using_stale_cache']:
                    logger.warning("ATT&CK data comes from a STALE cache because the download failed")
                self.mitre_validator = validator
            elif self.args.allow_unvalidated:
                logger.warning("Could not load ATT&CK data - continuing WITHOUT validation (--allow-unvalidated)")
            else:
                logger.error("ATT&CK validation was requested but the data could not be loaded. "
                             "Fix the network/file problem, or pass --allow-unvalidated to continue without validation.")
                return False

        self.repository = RuleRepository(
            self.mitre_validator,
            revoked_policy=self.args.revoked_policy,
            fallback_text_extraction=self.args.text_fallback
        )

        platforms = self._resolve_platform_filter()
        self.generator = NavigatorLayerGenerator(
            self.mitre_validator,
            attack_version=self.args.attack_version,
            platforms=platforms,
            tactic_scoped=self.args.tactic_scoped
        )

        logger.info("Components initialized successfully")
        return True

    def _resolve_platform_filter(self) -> List[str]:
        """Validate --platforms against the loaded ATT&CK data (when available)."""
        platforms = self.args.platforms or []
        if platforms and self.mitre_validator:
            known = self.mitre_validator.known_platforms()
            unknown = [p for p in platforms if p not in known]
            if unknown:
                logger.warning(f"Platform(s) not present in ATT&CK {self.mitre_validator.data_version}: "
                               f"{', '.join(unknown)}. Known platforms: {', '.join(sorted(known))}")
        return platforms

    # ------------------------------------------------------------------
    # Discovery and parsing
    # ------------------------------------------------------------------

    def _discover_rules(self) -> List[str]:
        logger.info(f"Discovering rule files in: {self.args.path}")
        rule_files = self.repository.discover_rules(self.args.path)

        stats = self.repository.get_statistics()['discovery']
        logger.info(f"Discovery: {stats['files_discovered']} files, {stats['files_skipped']} skipped, "
                    f"{stats['directories_scanned']} directories, {stats['discovery_time_seconds']:.2f}s")
        return rule_files

    def _parse_rules(self, rule_files: List[str]) -> List[DetectionRule]:
        logger.info(f"Parsing {len(rule_files)} rule files...")

        rules = self.repository.parse_rules(
            rule_files, use_concurrent=not self.args.no_threading, max_workers=self.args.max_workers)

        parsing = self.repository.get_statistics()['parsing']
        logger.info(f"Parsed {parsing['rules_parsed']} rules from "
                    f"{parsing['successful_parses']}/{parsing['total_files']} files")

        if self.args.rule_type != "both":
            original_count = len(rules)
            rules = [r for r in rules if r.rule_type.startswith(self.args.rule_type)]
            logger.info(f"Filtered to {len(rules)} {self.args.rule_type} rules (from {original_count})")

        if not self.args.include_disabled:
            enabled = [r for r in rules if r.enabled]
            self.disabled_excluded = len(rules) - len(enabled)
            if self.disabled_excluded:
                logger.info(f"Excluded {self.disabled_excluded} disabled rules (use --include-disabled to count them)")
            rules = enabled

        self.analyzed_rules = rules
        return rules

    # ------------------------------------------------------------------
    # Layer generation
    # ------------------------------------------------------------------

    def _generate_layer(self, rules: List[DetectionRule]) -> Optional[Dict[str, Any]]:
        logger.info("Generating Navigator layer...")
        try:
            if self.args.comparison_mode:
                return self._generate_comparison_layer(rules)
            if self.args.frequency_mode:
                return self._generate_frequency_layer(rules)
            return self._generate_coverage_layer(rules)
        except ValueError as e:
            # e.g. no techniques in any rule: a user-visible condition, not a crash
            logger.error(f"Layer generation failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Layer generation failed: {e}")
            logger.debug(traceback.format_exc())
            return None

    def _generate_coverage_layer(self, rules: List[DetectionRule]) -> Dict[str, Any]:
        layer = self.generator.generate_coverage_layer(
            rules=rules,
            layer_name=self._build_layer_name("Coverage Analysis"),
            description=self._build_layer_description(rules, "coverage"),
            scoring_algorithm='threshold'
        )
        return layer.to_dict()

    def _generate_comparison_layer(self, rules: List[DetectionRule]) -> Dict[str, Any]:
        elastic_rules = [r for r in rules if r.rule_type.startswith("elastic")]
        sentinel_rules = [r for r in rules if r.rule_type.startswith("sentinel")]

        if not elastic_rules or not sentinel_rules:
            logger.warning("Comparison mode requires both Elastic and Sentinel rules; "
                           f"found {len(elastic_rules)} Elastic and {len(sentinel_rules)} Sentinel. "
                           "Falling back to a coverage layer")
            return self._generate_coverage_layer(rules)

        layer = self.generator.generate_comparison_layer(
            elastic_rules, sentinel_rules, layer_name=self._build_layer_name("Platform Comparison"))
        return layer.to_dict()

    def _generate_frequency_layer(self, rules: List[DetectionRule]) -> Dict[str, Any]:
        layer = self.generator.generate_frequency_layer(
            rules=rules, layer_name=self._build_layer_name("Frequency Analysis"))
        return layer.to_dict()

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def _prepare_output_path(self, requested: str, default_dir: Optional[str] = None) -> str:
        """
        Sanitize the filename (never the directories), create missing parent directories,
        and validate the location. A bare filename goes into ``default_dir`` if given.
        """
        path = Path(requested)
        if default_dir and path.parent == Path('.') and not path.is_absolute():
            path = Path(default_dir) / path.name

        output_path = SecurityValidator.sanitize_output_path(str(path))
        is_valid, error_msg = SecurityValidator.validate_output_path(output_path, create_parents=True)
        if not is_valid:
            raise ValueError(f"Invalid output path: {error_msg}")
        return output_path

    def _save_results(self, layer: Dict[str, Any]) -> None:
        logger.info("Saving analysis results...")

        if not self.args.output:
            self.args.output = self._generate_default_output_path()

        output_path = self._prepare_output_path(self.args.output)

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(layer, f, indent=2, ensure_ascii=False)
        except OSError as e:
            raise RuntimeError(f"Failed to save Navigator layer: {e}")

        logger.info(f"Navigator layer saved to: {output_path}")
        self.results['layer_file'] = output_path
        self.results['technique_count'] = len(layer.get('techniques', []))

        if self.args.report:
            self._save_detailed_report()

    def _save_detailed_report(self) -> None:
        logger.info("Generating detailed coverage report...")

        coverage_report = self.repository.get_coverage_report()
        coverage_report['session_info'] = {
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'arguments': vars(self.args),
            'analysis_duration_seconds': (datetime.now() - self.start_time).total_seconds(),
            'disabled_rules_excluded': self.disabled_excluded,
        }
        coverage_report['output_info'] = dict(self.results)

        try:
            report_path = self._prepare_output_path(self.args.report, default_dir="output")
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(coverage_report, f, indent=2, default=str, ensure_ascii=False)
            logger.info(f"Detailed report saved to: {report_path}")
            self.results['report_file'] = report_path
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to save detailed report: {e}")

    def _generate_default_output_path(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.args.comparison_mode:
            filename = f"platform_comparison_{timestamp}.json"
        elif self.args.frequency_mode:
            filename = f"frequency_analysis_{timestamp}.json"
        else:
            filename = f"coverage_analysis_{timestamp}.json"
        return str(Path("output") / filename)

    def _display_completion_summary(self) -> None:
        duration = datetime.now() - self.start_time
        stats = self.repository.get_statistics()
        parsing = stats['parsing']
        platform = stats['by_platform']
        attack = stats['attack_analysis']
        rules = self.analyzed_rules

        print("\n" + "=" * 70)
        print("MITRE ATT&CK COVERAGE ANALYSIS - RESULTS SUMMARY")
        print("=" * 70)
        print(f"Analysis duration: {duration.total_seconds():.1f} seconds")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        total_files = parsing['total_files'] or 1
        print("RULE PROCESSING SUMMARY:")
        print(f"  Files processed: {parsing['total_files']}")
        print(f"  Files yielding rules: {parsing['successful_parses']} "
              f"({parsing['successful_parses'] / total_files * 100:.1f}%)")
        print(f"  Rules parsed: {parsing['rules_parsed']} "
              f"({platform['elastic_rules']} Elastic, {platform['sentinel_rules']} Sentinel)")
        if platform['unknown_format']:
            print(f"  Files in an unrecognized format: {platform['unknown_format']}")
        if self.disabled_excluded:
            print(f"  Disabled rules excluded: {self.disabled_excluded}")
        print(f"  Rules analyzed: {len(rules)}")
        print(f"  Processing rate: {parsing['files_per_second']:.1f} files/second")
        print()

        analyzed_techniques = {t for r in rules for t in r.techniques}
        analyzed_tactics = {t for r in rules for t in r.tactics}
        print("MITRE ATT&CK COVERAGE SUMMARY:")
        print(f"  Unique techniques: {len(analyzed_techniques)}")
        print(f"  Unique tactics: {len(analyzed_tactics)}")
        print(f"  Total technique mappings: {sum(len(r.techniques) for r in rules)}")

        if self.mitre_validator:
            validation = self.mitre_validator.get_validation_summary()
            print(f"  ATT&CK data version: {validation['data_version'] or 'unknown'}")
            print(f"  Techniques validated: {attack['techniques_validated']}")
            print(f"  Revoked techniques remapped: {attack['techniques_remapped']}")
            print(f"  Revoked techniques dropped: {attack['techniques_dropped_revoked']}")
            print(f"  Invalid/deprecated techniques removed: {attack['techniques_invalid']}")
            if attack['legacy_tactic_rules']:
                print(f"  Rules using tactic names not in this ATT&CK version: {attack['legacy_tactic_rules']}")
        else:
            print("  ATT&CK validation: NOT PERFORMED (use --validate-online or --attack-data-file)")
        print()

        print("OUTPUT FILES:")
        print(f"  Navigator layer: {self.results['layer_file']}")
        print(f"  Layer contains: {self.results['technique_count']} technique entries")
        if 'report_file' in self.results:
            print(f"  Detailed report: {self.results['report_file']}")
        print()

        print("NEXT STEPS:")
        print("1. Open https://mitre-attack.github.io/attack-navigator/")
        print("2. Choose 'Open Existing Layer' then 'Upload from local'")
        print("3. Select the generated JSON file")

        error_count = sum(len(v) for v in stats['errors'].values())
        if error_count > 0:
            print(f"\nWARNING: {error_count} issues encountered during analysis")
            print("  Run with --log-level DEBUG, or use --report, for details")

        print("\nAnalysis completed.")
        print("=" * 70)

    def _build_layer_name(self, analysis_type: str) -> str:
        base_name = f"{analysis_type}"
        if self.args.rule_type != "both":
            base_name += f" - {self.args.rule_type.title()}"
        return f"{base_name} ({datetime.now().strftime('%Y-%m-%d')})"

    def _build_layer_description(self, rules: List[DetectionRule], analysis_type: str) -> str:
        elastic_count = sum(1 for r in rules if r.rule_type.startswith('elastic'))
        sentinel_count = sum(1 for r in rules if r.rule_type.startswith('sentinel'))
        all_techniques = {t for r in rules for t in r.techniques}

        parts = [
            f"{analysis_type.title()} analysis generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Analyzed {len(rules)} detection rules ({elastic_count} Elastic, {sentinel_count} Sentinel)",
            f"Covering {len(all_techniques)} unique MITRE ATT&CK techniques",
        ]
        if self.mitre_validator and self.mitre_validator.data_version:
            parts.append(f"Validated against ATT&CK {self.mitre_validator.data_version}")
        return ". ".join(parts) + "."

    # ------------------------------------------------------------------
    # Temporal analysis
    # ------------------------------------------------------------------

    def _run_temporal_analysis(self) -> int:
        logger.info("Starting temporal analysis of detection coverage snapshots")
        try:
            analyzer = TemporalAnalyzer()
            snapshots_loaded = analyzer.load_snapshots_from_directory(self.args.snapshots_directory, "*.json")

            if snapshots_loaded < 2:
                logger.error(f"Need at least 2 snapshots for temporal analysis, found {snapshots_loaded}")
                return EXIT_FAILED

            logger.info(f"Loaded {snapshots_loaded} snapshots for analysis")

            time_series = analyzer.generate_time_series_data()
            executive_summary = analyzer.generate_executive_summary()

            # Temporal outputs get their own subdirectory so they can never be mistaken
            # for input snapshots on a later run
            output_dir = Path("output") / "temporal"
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_files = analyzer.export_to_csv(str(output_dir), suffix=timestamp)

            summary_path = output_dir / f"executive_summary_{timestamp}.json"
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(executive_summary, f, indent=2, default=str, ensure_ascii=False)

            timeseries_path = output_dir / f"time_series_data_{timestamp}.json"
            with open(timeseries_path, 'w', encoding='utf-8') as f:
                json.dump(time_series, f, indent=2, default=str, ensure_ascii=False)

            self._display_temporal_analysis_summary(
                executive_summary, csv_files, str(summary_path), str(timeseries_path))

            logger.info("Temporal analysis completed successfully")
            return EXIT_OK

        except Exception as e:
            logger.error(f"Temporal analysis failed: {e}")
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return EXIT_FAILED

    def _display_temporal_analysis_summary(self, executive_summary: Dict[str, Any],
                                           csv_files: List[str], summary_path: str,
                                           timeseries_path: str) -> None:
        print("\n" + "=" * 70)
        print("TEMPORAL DETECTION COVERAGE ANALYSIS - SUMMARY")
        print("=" * 70)

        period = executive_summary.get('analysis_period', {})
        print(f"Analysis period: {period.get('start_date', 'N/A')} to {period.get('end_date', 'N/A')}")
        print(f"Total duration: {period.get('total_days', 0):.1f} days")
        print(f"Snapshots analyzed: {period.get('total_snapshots', 0)}")
        print()

        growth = executive_summary.get('overall_growth', {})
        print("OVERALL GROWTH METRICS:")
        print(f"  Rules added: {_fmt(growth.get('rules_added'), 'd')}")
        print(f"  New techniques covered: {growth.get('techniques_added', 0)}")
        print(f"  New tactics covered: {growth.get('tactics_added', 0)}")
        print(f"  Coverage improvement: {growth.get('coverage_improvement_percent', 0):.2f} percentage points")
        print(f"  Tactic coverage improvement: {growth.get('tactic_coverage_improvement_percent', 0):.2f} percentage points")
        print()

        status = executive_summary.get('current_status', {})
        print("CURRENT DETECTION STATUS:")
        print(f"  Total rules: {_fmt(status.get('total_rules'), 'd')}")
        print(f"  Unique techniques: {status.get('unique_techniques_covered', 0)}")
        print(f"  Unique tactics: {status.get('unique_tactics_covered', 0)}")
        print(f"  Overall coverage: {status.get('overall_coverage_percent', 0):.2f}%")
        print(f"  Tactic coverage: {status.get('tactic_coverage_percent', 0):.2f}%")
        print(f"  Coverage denominator: {executive_summary.get('coverage_basis', 'unknown')}")
        print()

        velocity = executive_summary.get('velocity_metrics', {})
        print("DEVELOPMENT VELOCITY:")
        print(f"  Rules per day: {_fmt(velocity.get('average_rules_per_day'))}")
        print(f"  Techniques per day: {velocity.get('average_techniques_per_day', 0):.3f}")
        print(f"  Rules per month: {_fmt(velocity.get('average_rules_per_month'), '.1f')}")
        print(f"  Techniques per month: {velocity.get('average_techniques_per_month', 0):.2f}")
        print()

        acceleration = executive_summary.get('trend_analysis', {}).get('acceleration_indicators', {})
        if 'rules_acceleration' in acceleration:
            print("TREND INDICATORS:")
            print(f"  Rules development: {acceleration.get('rules_acceleration', 'unknown').title()}")
            print(f"  Techniques coverage: {acceleration.get('techniques_acceleration', 'unknown').title()}")
            print()

        print("OUTPUT FILES GENERATED:")
        print(f"  Executive summary: {summary_path}")
        print(f"  Time-series data: {timeseries_path}")
        print("  CSV files for charting:")
        for csv_file in csv_files:
            print(f"    - {csv_file}")
        print()

        recommendations = executive_summary.get('recommendations', [])
        if recommendations:
            print("KEY RECOMMENDATIONS:")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"  {i}. {rec}")
            print()

        print("Temporal analysis completed.")
        print("=" * 70)


def _fmt(value: Any, spec: str = ".2f") -> str:
    """Format a number, showing 'n/a' for values that are unknown (None)."""
    return "n/a" if value is None else format(value, spec)


def setup_argument_parser() -> argparse.ArgumentParser:
    """Configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=f"{config.APPLICATION_NAME} v{config.VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic coverage analysis
  python main.py -p /path/to/rules -o coverage_layer.json

  # Platform comparison, validated against current ATT&CK data
  python main.py -p /path/to/rules -o comparison.json --comparison-mode --validate-online

  # Offline validation with a local ATT&CK STIX bundle
  python main.py -p /path/to/rules --attack-data-file enterprise-attack.json

  # Pin a specific ATT&CK release
  python main.py -p /path/to/rules --validate-online --attack-version 19

  # Detailed report
  python main.py -p /path/to/rules -o coverage.json --report coverage_report.json

  # Temporal analysis of earlier coverage reports
  python main.py --temporal-analysis --snapshots-directory snapshots/
        """
    )

    required = parser.add_argument_group('Input and Output')
    required.add_argument("-p", "--path", type=str,
                          help="Directory containing detection rules (not used for temporal analysis)")
    required.add_argument("-o", "--output", type=str,
                          help="Output path for the Navigator layer (default: output/coverage_analysis_TIMESTAMP.json). "
                               "Missing directories are created.")

    analysis = parser.add_argument_group('Analysis Modes')
    analysis.add_argument("--comparison-mode", action="store_true",
                          help="Layer comparing Elastic and Sentinel coverage")
    analysis.add_argument("--frequency-mode", action="store_true",
                          help="Layer showing how many rules cover each technique")
    analysis.add_argument("--temporal-analysis", action="store_true",
                          help="Compare coverage report snapshots over time")
    analysis.add_argument("--snapshots-directory", type=str,
                          help="Directory of coverage reports (from --report) for temporal analysis")

    config_group = parser.add_argument_group('Rule Selection and Layer Options')
    config_group.add_argument("--attack-version", type=str, default=None,
                              help="ATT&CK version, major (19) or major.minor (19.2). With --validate-online this "
                                   "selects the release to download; otherwise it is the version stamped on the layer. "
                                   f"Default: the loaded data's version, else {config.DEFAULT_ATTACK_VERSION}")
    config_group.add_argument("--rule-type", choices=["elastic", "sentinel", "both"], default="both",
                              help="Rule platform(s) to analyze (default: both)")
    config_group.add_argument("--include-disabled", action="store_true",
                              help="Count disabled rules as coverage (excluded by default)")
    config_group.add_argument("--tactic-scoped", action="store_true",
                              help="Emit per-tactic layer entries when a rule declares the tactic for a technique "
                                   "(Elastic does). Techniques without pairing stay unscoped.")
    config_group.add_argument("--platforms", nargs='+', metavar="PLATFORM",
                              help="Filter the layer to these ATT&CK platforms (e.g. Windows 'Identity Provider'). "
                                   "No filter is applied by default.")
    config_group.add_argument("--text-fallback", action="store_true",
                              help="For Sentinel rules with no ATT&CK fields, take technique IDs mentioned in the "
                                   "description/query text. Off by default: a mention is not evidence of detection.")

    validation = parser.add_argument_group('ATT&CK Validation')
    validation.add_argument("--validate-online", action="store_true",
                            help="Validate techniques against ATT&CK data downloaded from the official repository "
                                 "(cached on disk)")
    validation.add_argument("--attack-data-file", type=str,
                            help="Validate against a local ATT&CK STIX bundle instead of downloading (offline use)")
    validation.add_argument("--revoked-policy", choices=list(REVOKED_POLICIES), default="remap",
                            help="Handling of techniques ATT&CK has revoked: remap to the replacement (default), "
                                 "drop, or keep")
    validation.add_argument("--allow-unvalidated", action="store_true",
                            help="Continue without validation if ATT&CK data cannot be loaded "
                                 "(default: exit with an error)")
    validation.add_argument("--cache-dir", type=str,
                            help="Directory for cached ATT&CK data (default: user cache directory)")
    validation.add_argument("--no-cache", action="store_true", help="Do not read or write the ATT&CK data cache")
    validation.add_argument("--refresh-attack-data", action="store_true",
                            help="Revalidate cached ATT&CK data with the server even if it is recent")

    output_group = parser.add_argument_group('Reporting')
    output_group.add_argument("--report", type=str,
                              help="Path for the detailed coverage report (JSON). A bare filename is written "
                                   "under output/.")

    performance = parser.add_argument_group('Performance')
    performance.add_argument("--max-workers", type=int, default=config.MAX_WORKERS,
                             help=f"Maximum worker threads (default: {config.MAX_WORKERS})")
    performance.add_argument("--no-threading", action="store_true",
                             help="Disable concurrent processing (useful for debugging)")

    debug = parser.add_argument_group('Logging')
    debug.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO",
                       help="Logging verbosity (default: INFO)")
    debug.add_argument("--log-file", type=str, help="Also write logs to this file")
    debug.add_argument("--quiet", action="store_true", help="Only show errors and the final summary")

    parser.add_argument("--version", action="version", version=f"{config.APPLICATION_NAME} v{config.VERSION}")
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate arguments and conflicts.

    Raises:
        ValueError: If arguments are invalid or conflicting
    """
    mode_count = sum([args.comparison_mode, args.frequency_mode, args.temporal_analysis])
    if mode_count > 1:
        raise ValueError("Only one analysis mode can be specified at a time")

    if args.attack_version is not None and not config.validate_attack_version(args.attack_version):
        raise ValueError(f"Invalid ATT&CK version: {args.attack_version!r} (use e.g. 20 or 19.2)")

    if args.max_workers < 1 or args.max_workers > 16:
        raise ValueError("Max workers must be between 1 and 16")

    if args.validate_online and args.attack_data_file:
        raise ValueError("Use either --validate-online or --attack-data-file, not both")

    if args.attack_data_file and not Path(args.attack_data_file).is_file():
        raise ValueError(f"ATT&CK data file does not exist: {args.attack_data_file}")

    if args.comparison_mode and args.rule_type != "both":
        logger.warning("Comparison mode works best with --rule-type both")

    if args.temporal_analysis:
        if not args.snapshots_directory:
            raise ValueError("Temporal analysis requires --snapshots-directory")
        if not Path(args.snapshots_directory).is_dir():
            raise ValueError(f"Snapshots directory does not exist: {args.snapshots_directory}")
    elif not args.path:
        raise ValueError("--path is required for all analysis modes except temporal analysis")
    elif not Path(args.path).is_dir():
        raise ValueError(f"Rules directory does not exist: {args.path}")

    if args.output and not args.output.lower().endswith('.json'):
        logger.warning("Output file should have a .json extension for Navigator compatibility")


def main() -> int:
    """Application entry point. Returns the process exit code."""
    try:
        parser = setup_argument_parser()
        args = parser.parse_args()

        log_level = "ERROR" if args.quiet else args.log_level
        setup_logging(log_level, args.log_file, enable_colors=True)

        if not args.quiet:
            print(config.get_banner())

        try:
            validate_arguments(args)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_BAD_ARGS

        if not SecurityValidator.perform_startup_security_check():
            logger.error("Security validation failed - cannot proceed safely")
            return EXIT_FAILED

        return AnalysisSession(args).run()

    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        return EXIT_INTERRUPTED

    except Exception as e:
        if logger.isEnabledFor(logging.DEBUG):
            logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
        else:
            print(f"\nError: {e}")
            print("Run with --log-level DEBUG for detailed error information")
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
