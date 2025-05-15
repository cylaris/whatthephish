"""
File handling utilities for WTP
"""

import os
from pathlib import Path


def ensure_directory(path):
    """Ensure a directory exists, creating it if necessary."""
    Path(path).mkdir(parents=True, exist_ok=True)


def get_file_extension(file_path):
    """Get the file extension from a file path."""
    return os.path.splitext(file_path.lower())[1]


def is_supported_file(file_path):
    """Check if the file type is supported by WTP."""
    supported_extensions = ['.msg', '.eml']
    return get_file_extension(file_path) in supported_extensions


def validate_file_exists(file_path):
    """Validate that a file exists and is readable."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Cannot read file: {file_path}")
    
    return True