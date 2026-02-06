"""
App discovery and validation for Python projects.
"""
import ast
import os
from pathlib import Path
from typing import Optional, Dict, Any


class AppValidationError(Exception):
    """Raised when app validation fails."""
    pass


def discover_entry_point(app_path: Path) -> Path:
    """
    Discover the entry point file for a Python app.
    
    Looks for (in order):
    1. __main__.py
    2. main.py
    3. app.py
    
    Args:
        app_path: Path to the app directory
        
    Returns:
        Path to the entry point file
        
    Raises:
        AppValidationError: If no valid entry point is found
    """
    candidates = ["__main__.py", "main.py", "app.py"]
    
    for candidate in candidates:
        entry_point = app_path / candidate
        if entry_point.exists() and entry_point.is_file():
            return entry_point
    
    raise AppValidationError(
        f"No entry point found in {app_path}. "
        f"Expected one of: {', '.join(candidates)}"
    )


def validate_python_syntax(file_path: Path) -> None:
    """
    Validate that a Python file has valid syntax.
    
    Args:
        file_path: Path to the Python file
        
    Raises:
        AppValidationError: If syntax is invalid
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        ast.parse(source)
    except SyntaxError as e:
        raise AppValidationError(
            f"Invalid Python syntax in {file_path.name}:{e.lineno}: {e.msg}"
        )
    except Exception as e:
        raise AppValidationError(
            f"Failed to validate {file_path.name}: {str(e)}"
        )


def has_requirements_file(app_path: Path) -> bool:
    """
    Check if app has a requirements.txt file.
    
    Args:
        app_path: Path to the app directory
        
    Returns:
        True if requirements.txt exists
    """
    req_file = app_path / "requirements.txt"
    return req_file.exists() and req_file.is_file()


def validate_app_directory(app_path: str) -> Dict[str, Any]:
    """
    Validate a Python app directory and return metadata.
    
    Args:
        app_path: Path to the app directory (string)
        
    Returns:
        Dictionary containing:
        - app_path: Absolute path to app directory
        - entry_point: Relative path to entry point file
        - entry_point_name: Name of entry point file
        - has_requirements: Whether requirements.txt exists
        - requirements_path: Path to requirements.txt (if exists)
        
    Raises:
        AppValidationError: If validation fails
    """
    app_path_obj = Path(app_path).resolve()
    
    # Check directory exists
    if not app_path_obj.exists():
        raise AppValidationError(f"Directory does not exist: {app_path}")
    
    if not app_path_obj.is_dir():
        raise AppValidationError(f"Not a directory: {app_path}")
    
    # Discover entry point
    entry_point = discover_entry_point(app_path_obj)
    
    # Validate Python syntax
    validate_python_syntax(entry_point)
    
    # Check for requirements
    has_reqs = has_requirements_file(app_path_obj)
    
    return {
        "app_path": str(app_path_obj),
        "entry_point": entry_point.name,
        "entry_point_name": entry_point.stem,
        "has_requirements": has_reqs,
        "requirements_path": str(app_path_obj / "requirements.txt") if has_reqs else None,
    }
