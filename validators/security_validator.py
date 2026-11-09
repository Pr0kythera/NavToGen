"""
Security Validator
=================

This module provides comprehensive security validation for file operations and input sanitization.
It acts as the first line of defense against various attack vectors that could compromise the
analysis system or expose sensitive information.

Think of this module as a security checkpoint - every file and input must pass through these
validations before being processed by the rest of the system. This prevents malicious inputs
from reaching sensitive code paths.

The validation follows the "defense in depth" principle, implementing multiple layers of
protection rather than relying on a single security measure.
"""

import os
import logging
from pathlib import Path
from typing import Optional, Set, Tuple

from config import (
    MAX_FILE_SIZE,
    FORBIDDEN_PATH_PREFIXES,
    SUPPORTED_EXTENSIONS
)

logger = logging.getLogger(__name__)


class SecurityValidator:
    """
    Comprehensive security validation utilities for file operations and input sanitization.
    
    This class implements various security checks to prevent common attack vectors in
    file processing applications. Each method focuses on a specific aspect of security,
    allowing for granular validation and clear error reporting.
    
    The design follows the principle of "explicit security" - every security decision
    is made deliberately and documented, rather than assuming inputs are safe.
    
    Security Principles Implemented:
    1. Path Traversal Prevention: Validates file paths to prevent ../../../etc/passwd attacks
    2. Size Limits: Prevents memory exhaustion attacks from oversized files
    3. Extension Validation: Ensures only expected file types are processed
    4. System File Protection: Blocks access to sensitive system directories
    5. Access Control: Verifies file permissions before processing
    """
    
    @staticmethod
    def _forbidden_prefix(path_obj: Path) -> Optional[str]:
        """
        Return the forbidden system prefix that contains this RESOLVED path, or None.

        Matching is component-wise on the full path: '/etc' blocks '/etc/passwd' but not
        '/home/me/etc/rules' or '/etcetera'. Windows prefixes compare case-insensitively.
        """
        path_str = str(path_obj).replace('\\', '/')
        lowered = path_str.lower()
        for prefix in FORBIDDEN_PATH_PREFIXES:
            if prefix[1:2] == ':':  # Windows drive-letter prefix
                candidate, target = prefix.lower(), lowered
            else:
                candidate, target = prefix, path_str
            if target == candidate or target.startswith(candidate.rstrip('/') + '/'):
                return prefix
        return None

    @staticmethod
    def sanitize_output_path(output_path: str) -> str:
        """
        Sanitize only the final filename component of a path, leaving directories intact.

        (Sanitizing the whole string would replace the path separators and turn
        'reports/out.json' into 'reports_out.json'.)
        """
        path_obj = Path(output_path)
        return str(path_obj.parent / SecurityValidator.sanitize_filename(path_obj.name))

    @staticmethod
    def validate_file_path(file_path: str, allowed_extensions: Set[str] = None,
                           allowed_root: Optional[str] = None) -> Tuple[bool, str]:
        """
        Comprehensive validation of a file path for security and accessibility.
        
        This method performs multiple security checks on a file path, ensuring it's
        safe to process and accessible to the application. It's designed to catch
        various attack vectors while providing clear error messages for debugging.
        
        The validation process follows this sequence:
        1. Basic path validation and resolution
        2. Existence and accessibility checks
        3. File type and extension validation
        4. Size limit enforcement
        5. System file protection
        
        Args:
            file_path: File path to validate (can be relative or absolute)
            allowed_extensions: Set of allowed file extensions (defaults to config)
            allowed_root: If given, the fully resolved file path must lie inside this
                directory. This rejects symlinks that point outside the scanned tree.
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
            - is_valid: True if file passes all security checks
            - error_message: Empty string if valid, detailed error if invalid
            
        Example:
            is_valid, error = SecurityValidator.validate_file_path("/path/to/rule.yaml")
            if not is_valid:
                logger.error(f"File validation failed: {error}")
                return
        """
        try:
            # Use allowed_extensions from parameter or fall back to config
            extensions_to_check = allowed_extensions or SUPPORTED_EXTENSIONS
            
            # Step 1: Convert to Path object and resolve to absolute path
            # This normalizes the path and resolves any relative references like ../
            try:
                path_obj = Path(file_path).resolve(strict=True)
            except (OSError, RuntimeError) as e:
                return False, f"Path resolution failed: {str(e)}"
            
            # Step 2: Basic existence and type checks
            if not path_obj.exists():
                return False, f"File does not exist: {file_path}"
            
            if not path_obj.is_file():
                return False, f"Path is not a regular file: {file_path}"
            
            # Step 3: File extension validation
            # This prevents processing of unexpected file types that might contain malicious content
            file_extension = path_obj.suffix.lower()
            if file_extension not in extensions_to_check:
                return False, f"Invalid file extension '{file_extension}'. Allowed: {extensions_to_check}"
            
            # Step 4: File size validation
            # This prevents memory exhaustion attacks from extremely large files
            try:
                file_size = path_obj.stat().st_size
                if file_size > MAX_FILE_SIZE:
                    size_mb = file_size / (1024 * 1024)
                    limit_mb = MAX_FILE_SIZE / (1024 * 1024)
                    return False, f"File too large: {size_mb:.1f}MB (limit: {limit_mb}MB)"
            except OSError as e:
                return False, f"Cannot read file size: {str(e)}"
            
            # Step 5: System file protection
            # This prevents access to sensitive system files and directories
            forbidden = SecurityValidator._forbidden_prefix(path_obj)
            if forbidden:
                return False, f"Access to system files not allowed: {forbidden}"

            if allowed_root is not None:
                try:
                    path_obj.relative_to(Path(allowed_root).resolve())
                except ValueError:
                    return False, f"File resolves outside the scanned directory (symlink?): {path_obj}"
            
            # Step 6: Permission checks
            # Verify the application can actually read the file
            if not os.access(path_obj, os.R_OK):
                return False, f"File is not readable: {file_path}"
            
            # All checks passed - file is safe to process
            logger.debug(f"File validation passed: {path_obj}")
            return True, ""
            
        except Exception as e:
            # Catch any unexpected errors and report them safely
            # This prevents security validation from crashing the application
            logger.error(f"Unexpected error during file validation: {str(e)}")
            return False, f"File validation error: {str(e)}"
    
    @staticmethod
    def validate_directory_path(dir_path: str) -> Tuple[bool, str]:
        """
        Validate directory path for safe traversal and access.
        
        This method ensures a directory path is safe to traverse recursively,
        preventing directory-based attacks while verifying the path is accessible
        for rule discovery operations.
        
        Directory validation is particularly important because the rule discovery
        process recursively walks directory trees, potentially exposing the system
        to path traversal attacks if not properly secured.
        
        Args:
            dir_path: Directory path to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
            
        Security Checks Performed:
        1. Path existence and type validation
        2. Read permission verification
        3. System directory protection
        4. Symbolic link detection (prevents symlink attacks)
        """
        try:
            # Detect symlinks BEFORE resolving; resolve() follows them and hides the fact
            raw_path = Path(dir_path)
            is_symlink = raw_path.is_symlink()
            path_obj = raw_path.resolve()
            
            # Basic existence and type validation
            if not path_obj.exists():
                return False, f"Directory does not exist: {dir_path}"
            
            if not path_obj.is_dir():
                return False, f"Path is not a directory: {dir_path}"
            
            # Permission validation
            if not os.access(path_obj, os.R_OK):
                return False, f"Directory is not readable: {dir_path}"
            
            # System directory protection (checked on the resolved target)
            forbidden = SecurityValidator._forbidden_prefix(path_obj)
            if forbidden:
                return False, f"Access to system directory not allowed: {forbidden}"
            
            if is_symlink:
                logger.warning(f"Directory is a symbolic link: {dir_path} -> {path_obj}")
                # Allowed (the target has passed the checks above) but logged for awareness
            
            logger.debug(f"Directory validation passed: {path_obj}")
            return True, ""
            
        except Exception as e:
            logger.error(f"Directory validation error: {str(e)}")
            return False, f"Directory validation error: {str(e)}"
    
    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 200) -> str:
        """
        Sanitize filename for safe file creation and prevent injection attacks.
        
        This method cleans up filenames to ensure they're safe for file system
        operations across different operating systems. It's particularly important
        when creating output files based on user input.
        
        The sanitization process:
        1. Removes or replaces dangerous characters
        2. Limits filename length to prevent filesystem issues
        3. Ensures the result is a valid filename on common filesystems
        
        Args:
            filename: Original filename to sanitize
            max_length: Maximum allowed length for the filename
            
        Returns:
            str: Sanitized filename safe for file operations
            
        Example:
            sanitized = SecurityValidator.sanitize_filename("coverage<report>.json")
            # Returns: "coverage_report_.json"
        """
        if not filename or not isinstance(filename, str):
            return "default_filename"
        
        # Remove or replace characters that are problematic on Windows and Unix
        # < > : " / \ | ? * are forbidden on Windows
        # Control characters (0-31) can cause issues
        dangerous_chars = '<>:"/\\|?*'
        sanitized = filename
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Remove control characters (ASCII 0-31) and DEL (127)
        sanitized = ''.join(char for char in sanitized if ord(char) > 31 and ord(char) != 127)
        
        # Remove leading/trailing periods and spaces (problematic on Windows)
        sanitized = sanitized.strip('. ')
        
        # Ensure we have something left
        if not sanitized:
            sanitized = "sanitized_filename"
        
        # Limit length to prevent filesystem issues
        if len(sanitized) > max_length:
            # Try to preserve the file extension if present
            if '.' in sanitized:
                name_part, extension = sanitized.rsplit('.', 1)
                max_name_length = max_length - len(extension) - 1  # -1 for the dot
                if max_name_length > 0:
                    sanitized = name_part[:max_name_length] + '.' + extension
                else:
                    sanitized = sanitized[:max_length]
            else:
                sanitized = sanitized[:max_length]
        
        logger.debug(f"Sanitized filename: '{filename}' -> '{sanitized}'")
        return sanitized
    
    @staticmethod
    def validate_output_path(output_path: str, create_parents: bool = False) -> Tuple[bool, str]:
        """
        Validate output file path for safe writing operations.

        Args:
            output_path: Proposed output file path
            create_parents: Create missing parent directories (after the location has
                passed the system-path check)

        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        try:
            path_obj = Path(output_path).resolve()
            parent_dir = path_obj.parent

            # Prevent writing to critical system locations (checked before any mkdir)
            forbidden = SecurityValidator._forbidden_prefix(path_obj)
            if forbidden:
                return False, f"Cannot write to system location: {forbidden}"

            if not parent_dir.exists():
                if not create_parents:
                    return False, f"Output directory does not exist: {parent_dir}"
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                except OSError as e:
                    return False, f"Could not create output directory {parent_dir}: {e}"

            if not parent_dir.is_dir():
                return False, f"Output parent path is not a directory: {parent_dir}"

            if not os.access(parent_dir, os.W_OK):
                return False, f"Output directory is not writable: {parent_dir}"

            # If file exists, check if it's writable
            if path_obj.exists():
                if not os.access(path_obj, os.W_OK):
                    return False, f"Existing output file is not writable: {output_path}"
                logger.info(f"Output file already exists and will be overwritten: {output_path}")

            return True, ""

        except Exception as e:
            logger.error(f"Output path validation error: {str(e)}")
            return False, f"Output path validation error: {str(e)}"

    @classmethod
    def perform_startup_security_check(cls) -> bool:
        """
        Perform security checks at application startup.
        
        This method validates the runtime environment to ensure the application
        is running in a secure configuration. It's designed to catch common
        security misconfigurations before they become problems.
        
        Returns:
            bool: True if all security checks pass, False otherwise
        """
        logger.info("Performing startup security checks...")
        
        checks_passed = 0
        total_checks = 3
        
        # Check 1: Verify file size limits are reasonable
        if MAX_FILE_SIZE <= 0 or MAX_FILE_SIZE > 100 * 1024 * 1024:  # 100MB max
            logger.warning(f"File size limit seems unreasonable: {MAX_FILE_SIZE} bytes")
        else:
            logger.debug(f"File size limit OK: {MAX_FILE_SIZE // (1024*1024)}MB")
            checks_passed += 1
        
        # Check 2: Verify forbidden patterns are configured
        if not FORBIDDEN_PATH_PREFIXES:
            logger.warning("No forbidden path prefixes configured - security risk!")
        else:
            logger.debug(f"Forbidden path prefixes configured: {len(FORBIDDEN_PATH_PREFIXES)}")
            checks_passed += 1
        
        # Check 3: Verify supported extensions are reasonable
        if not SUPPORTED_EXTENSIONS:
            logger.warning("No supported file extensions configured")
        else:
            logger.debug(f"Supported extensions: {SUPPORTED_EXTENSIONS}")
            checks_passed += 1
        
        success_rate = checks_passed / total_checks
        if success_rate >= 0.8:  # Allow for some warnings
            logger.info(f"Security checks passed: {checks_passed}/{total_checks}")
            return True
        else:
            logger.error(f"Security checks failed: {checks_passed}/{total_checks}")
            return False
