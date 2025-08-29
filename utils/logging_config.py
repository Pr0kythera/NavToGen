"""
Centralized Logging Configuration
================================

This module provides centralized logging configuration for the entire application.
It ensures consistent logging behavior across all modules while providing
flexibility for different deployment scenarios (development, production, debugging).

The logging configuration follows best practices for enterprise applications:
- Structured log formats for easy parsing and analysis
- Multiple output destinations (console, file, remote systems)
- Appropriate log levels for different components
- Performance-optimized logging to minimize application impact
- Security-conscious logging that avoids exposing sensitive information

Key features:
- Environment-specific configuration (dev/prod/debug modes)
- Automatic log rotation to prevent disk space issues
- Colored console output for better development experience
- Integration with external log aggregation systems
- Performance metrics and timing information
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from config import LOG_FORMAT, LOG_DATE_FORMAT


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds color coding to console log messages.
    
    This formatter enhances the development experience by using ANSI color codes
    to highlight different log levels. It automatically detects if the output
    supports colors and gracefully degrades to plain text when necessary.
    """
    
    # ANSI color codes for different log levels
    COLOR_CODES = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset to default
    }
    
    def __init__(self, fmt=None, datefmt=None, use_colors=None):
        """
        Initialize the colored formatter.
        
        Args:
            fmt: Log message format string
            datefmt: Date format string
            use_colors: Whether to use colors (auto-detected if None)
        """
        super().__init__(fmt, datefmt)
        
        # Auto-detect color support if not specified
        if use_colors is None:
            use_colors = self._supports_color()
        
        self.use_colors = use_colors
    
    def format(self, record):
        """Format a log record with optional color coding."""
        # Get the base formatted message
        formatted = super().format(record)
        
        # Add color coding if supported and enabled
        if self.use_colors and record.levelname in self.COLOR_CODES:
            color_code = self.COLOR_CODES[record.levelname]
            reset_code = self.COLOR_CODES['RESET']
            
            # Only color the level name part of the message
            formatted = formatted.replace(
                record.levelname, 
                f"{color_code}{record.levelname}{reset_code}"
            )
        
        return formatted
    
    @staticmethod
    def _supports_color():
        """
        Detect if the current terminal supports color output.
        
        Returns:
            bool: True if colors should be used, False otherwise
        """
        # Check if we're in a terminal that supports colors
        if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
            return False
        
        # Check environment variables that indicate color support
        if 'TERM' in os.environ:
            term = os.environ['TERM'].lower()
            if 'color' in term or term in ('xterm', 'xterm-256color', 'screen'):
                return True
        
        # Check for explicit color preferences
        if os.environ.get('FORCE_COLOR', '').lower() in ('1', 'true', 'yes'):
            return True
        
        if os.environ.get('NO_COLOR', '').lower() in ('1', 'true', 'yes'):
            return False
        
        # Default to no colors if we can't determine support
        return False


class PerformanceFilter(logging.Filter):
    """
    Logging filter that adds performance timing information to log records.
    
    This filter enhances log records with timing information, helping
    identify performance bottlenecks and monitor system behavior.
    """
    
    def __init__(self):
        """Initialize the performance filter."""
        super().__init__()
        self.start_time = datetime.now()
    
    def filter(self, record):
        """Add timing information to the log record."""
        # Add elapsed time since logger initialization
        elapsed = datetime.now() - self.start_time
        record.elapsed_seconds = elapsed.total_seconds()
        
        # Add process-specific timing if available
        if hasattr(record, 'funcName') and record.funcName:
            # You could extend this to track per-function timing
            pass
        
        return True


def setup_logging(log_level: str = 'INFO', 
                 log_file: Optional[str] = None,
                 enable_colors: bool = True,
                 enable_performance: bool = False,
                 max_file_size: int = 10 * 1024 * 1024,  # 10MB
                 backup_count: int = 5) -> Dict[str, Any]:
    """
    Configure comprehensive logging for the application.
    
    This function sets up a complete logging configuration suitable for
    enterprise use, with console output, optional file logging, and
    various enhancement features.
    
    Args:
        log_level: Minimum log level to capture ('DEBUG', 'INFO', 'WARNING', 'ERROR')
        log_file: Path to log file (None for console-only logging)
        enable_colors: Whether to use colored console output
        enable_performance: Whether to include performance timing information
        max_file_size: Maximum size for individual log files before rotation
        backup_count: Number of rotated log files to keep
        
    Returns:
        Dict[str, Any]: Configuration summary for verification
        
    Example:
        # Basic setup for development
        setup_logging('DEBUG', enable_colors=True)
        
        # Production setup with file logging
        setup_logging('INFO', 'application.log', enable_colors=False)
        
        # Performance monitoring setup
        setup_logging('INFO', 'performance.log', enable_performance=True)
    """
    # Validate log level
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    # Get the root logger and clear any existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(numeric_level)
    
    config_summary = {
        'log_level': log_level,
        'handlers': [],
        'features': []
    }
    
    # Set up console handler with appropriate formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    
    if enable_colors:
        console_formatter = ColoredFormatter(LOG_FORMAT, LOG_DATE_FORMAT)
        config_summary['features'].append('colored_output')
    else:
        console_formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    
    console_handler.setFormatter(console_formatter)
    
    # Add performance filter if requested
    if enable_performance:
        performance_filter = PerformanceFilter()
        console_handler.addFilter(performance_filter)
        config_summary['features'].append('performance_timing')
    
    root_logger.addHandler(console_handler)
    config_summary['handlers'].append('console')
    
    # Set up file handler if requested
    if log_file:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use rotating file handler to prevent unbounded growth
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        
        # File logs don't need colors but should include all information
        file_formatter = logging.Formatter(
            LOG_FORMAT + ' - [PID:%(process)d]',  # Add process ID for multi-process debugging
            LOG_DATE_FORMAT
        )
        file_handler.setFormatter(file_formatter)
        
        # Add performance filter to file handler as well
        if enable_performance:
            file_handler.addFilter(performance_filter)
        
        root_logger.addHandler(file_handler)
        config_summary['handlers'].append(f'file({log_file})')
        config_summary['file_config'] = {
            'path': str(log_path.absolute()),
            'max_size_mb': max_file_size // (1024 * 1024),
            'backup_count': backup_count
        }
    
    # Configure specific logger levels for noisy third-party libraries
    _configure_third_party_loggers()
    
    # Log the configuration for verification
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured: {log_level} level, handlers: {', '.join(config_summary['handlers'])}")
    
    if config_summary['features']:
        logger.info(f"Logging features enabled: {', '.join(config_summary['features'])}")
    
    return config_summary


def _configure_third_party_loggers():
    """
    Configure logging levels for third-party libraries to reduce noise.
    
    Many third-party libraries are very chatty at DEBUG and INFO levels.
    This function sets appropriate levels to keep logs focused on our
    application logic while still capturing important external events.
    """
    # HTTP libraries can be very verbose
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    
    # YAML parsing libraries
    logging.getLogger('yaml').setLevel(logging.WARNING)
    
    # Concurrent processing libraries
    logging.getLogger('concurrent.futures').setLevel(logging.WARNING)
    
    # File system watchers and other utilities
    logging.getLogger('watchdog').setLevel(logging.WARNING)


def create_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Create a properly configured logger for a specific module.
    
    This function creates module-specific loggers that inherit from the
    root configuration while allowing per-module customization if needed.
    
    Args:
        name: Logger name (typically __name__ from the calling module)
        level: Optional override for log level
        
    Returns:
        logging.Logger: Configured logger instance
        
    Example:
        logger = create_logger(__name__)
        logger.info("Module initialized")
    """
    logger = logging.getLogger(name)
    
    if level:
        numeric_level = getattr(logging, level.upper(), None)
        if isinstance(numeric_level, int):
            logger.setLevel(numeric_level)
    
    return logger


def log_function_timing(func):
    """
    Decorator to automatically log function execution time.
    
    This decorator is useful for identifying performance bottlenecks
    in critical code paths. It logs both successful executions and
    exceptions with timing information.
    
    Args:
        func: Function to wrap with timing
        
    Returns:
        Wrapped function with timing logging
        
    Example:
        @log_function_timing
        def parse_large_file(file_path):
            # ... parsing logic ...
            return result
    """
    import functools
    import time
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.debug(f"{func.__name__} completed in {execution_time:.3f}s")
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"{func.__name__} failed after {execution_time:.3f}s: {str(e)}")
            raise
    
    return wrapper


def get_log_stats() -> Dict[str, Any]:
    """
    Get statistics about current logging configuration.
    
    This function provides insights into logging performance and
    configuration, useful for monitoring and troubleshooting.
    
    Returns:
        Dict[str, Any]: Logging statistics and configuration info
    """
    root_logger = logging.getLogger()
    
    stats = {
        'root_level': logging.getLevelName(root_logger.level),
        'handler_count': len(root_logger.handlers),
        'handlers': []
    }
    
    for handler in root_logger.handlers:
        handler_info = {
            'type': type(handler).__name__,
            'level': logging.getLevelName(handler.level),
            'formatter': type(handler.formatter).__name__ if handler.formatter else None
        }
        
        # Add handler-specific information
        if isinstance(handler, logging.FileHandler):
            handler_info['file'] = getattr(handler, 'baseFilename', 'unknown')
        
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            handler_info['max_bytes'] = getattr(handler, 'maxBytes', 0)
            handler_info['backup_count'] = getattr(handler, 'backupCount', 0)
        
        stats['handlers'].append(handler_info)
    
    return stats


def setup_development_logging():
    """
    Quick setup function for development environment.
    
    This provides a convenient way to set up logging for development
    with sensible defaults: DEBUG level, colored output, no file logging.
    """
    return setup_logging(
        log_level='DEBUG',
        enable_colors=True,
        enable_performance=True
    )


def setup_production_logging(log_file: str):
    """
    Quick setup function for production environment.
    
    This provides a convenient way to set up logging for production
    with appropriate defaults: INFO level, file logging, no colors.
    
    Args:
        log_file: Path to the production log file
    """
    return setup_logging(
        log_level='INFO',
        log_file=log_file,
        enable_colors=False,
        enable_performance=False
    )


# Module-level logger for this configuration module
logger = create_logger(__name__)
