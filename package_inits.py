# models/__init__.py
"""
Data Models Package
==================

This package contains data model classes that represent the core entities
in our MITRE ATT&CK analysis system.

Available Models:
- DetectionRule: Represents a parsed detection rule with MITRE ATT&CK mappings
- NavigatorLayer: Represents a complete Navigator layer for visualization
- TechniqueEntry: Represents a single technique entry within a Navigator layer
- LegendItem: Represents legend items for Navigator layers
"""

from .detection_rule import DetectionRule
from .navigator_layer import NavigatorLayer, TechniqueEntry, LegendItem, LayerFilter

__all__ = [
    'DetectionRule',
    'NavigatorLayer', 
    'TechniqueEntry',
    'LegendItem',
    'LayerFilter'
]

# ============================================================================

# validators/__init__.py
"""
Validation Package
=================

This package provides comprehensive validation utilities for security,
input sanitization, and MITRE ATT&CK framework validation.

Available Validators:
- SecurityValidator: File system security and input validation
- MitreAttackValidator: MITRE ATT&CK framework validation and metadata
"""

from .security_validator import SecurityValidator
from .mitre_validator import MitreAttackValidator

__all__ = [
    'SecurityValidator',
    'MitreAttackValidator'
]

# ============================================================================

# parsers/__init__.py
"""
Rule Parsers Package
===================

This package contains specialized parsers for different detection rule formats.
Each parser implements the BaseRuleParser interface and handles format-specific
parsing logic.

Available Parsers:
- BaseRuleParser: Abstract base class defining the parser interface
- ElasticRuleParser: Parser for Elastic Security Detection Engine rules
- SentinelRuleParser: Parser for Microsoft Sentinel Analytics Rules
"""

from .base_parser import BaseRuleParser
from .elastic_parser import ElasticRuleParser
from .sentinel_parser import SentinelRuleParser

__all__ = [
    'BaseRuleParser',
    'ElasticRuleParser',
    'SentinelRuleParser'
]

# ============================================================================

# core/__init__.py
"""
Core Components Package
======================

This package contains the core orchestration and management components
that coordinate the overall analysis process.

Available Components:
- RuleRepository: Central manager for rule discovery, parsing, and analysis
"""

from .rule_repository import RuleRepository

__all__ = [
    'RuleRepository'
]

# ============================================================================

# generators/__init__.py
"""
Layer Generators Package
========================

This package contains components for generating MITRE ATT&CK Navigator layers
from analyzed detection rules.

Available Generators:
- NavigatorLayerGenerator: Generates various types of Navigator layers
"""

from .layer_generator import NavigatorLayerGenerator

__all__ = [
    'NavigatorLayerGenerator'
]

# ============================================================================

# utils/__init__.py
"""
Utilities Package
================

This package contains utility modules that provide common functionality
across the application.

Available Utilities:
- logging_config: Centralized logging configuration and management
"""

from .logging_config import (
    setup_logging,
    create_logger,
    setup_development_logging,
    setup_production_logging,
    log_function_timing,
    get_log_stats
)

__all__ = [
    'setup_logging',
    'create_logger', 
    'setup_development_logging',
    'setup_production_logging',
    'log_function_timing',
    'get_log_stats'
]
