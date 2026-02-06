#!/usr/bin/env python3
"""Test suite for run-app command and app discovery."""

import tempfile
from pathlib import Path
import json

from egresslens.run_app import (
    discover_entry_point,
    validate_python_syntax,
    has_requirements_file,
    validate_app_directory,
    AppValidationError,
)


def test_discover_entry_point_main_py():
    """Test discovering main.py as entry point."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        main_file = app_dir / "main.py"
        main_file.write_text("print('hello')")
        
        entry_point = discover_entry_point(app_dir)
        assert entry_point.name == "main.py"
        print("✓ Successfully discovered main.py")


def test_discover_entry_point_app_py():
    """Test discovering app.py as entry point."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        app_file = app_dir / "app.py"
        app_file.write_text("print('hello')")
        
        entry_point = discover_entry_point(app_dir)
        assert entry_point.name == "app.py"
        print("✓ Successfully discovered app.py")


def test_discover_entry_point_main_module():
    """Test discovering __main__.py as entry point."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        main_file = app_dir / "__main__.py"
        main_file.write_text("print('hello')")
        
        entry_point = discover_entry_point(app_dir)
        assert entry_point.name == "__main__.py"
        print("✓ Successfully discovered __main__.py")


def test_discover_entry_point_priority():
    """Test entry point priority: __main__.py > main.py > app.py."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        
        # Create all three
        (app_dir / "__main__.py").write_text("print('main')")
        (app_dir / "main.py").write_text("print('main')")
        (app_dir / "app.py").write_text("print('app')")
        
        entry_point = discover_entry_point(app_dir)
        assert entry_point.name == "__main__.py"
        print("✓ Successfully validated entry point priority")


def test_discover_entry_point_not_found():
    """Test error when no entry point found."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        
        try:
            discover_entry_point(app_dir)
            assert False, "Should have raised AppValidationError"
        except AppValidationError as e:
            assert "No entry point found" in str(e)
            print("✓ Successfully caught missing entry point")


def test_validate_python_syntax_valid():
    """Test validating valid Python syntax."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        valid_file = app_dir / "valid.py"
        valid_file.write_text("import os\nprint('hello world')")
        
        validate_python_syntax(valid_file)  # Should not raise
        print("✓ Successfully validated correct Python syntax")


def test_validate_python_syntax_invalid():
    """Test catching invalid Python syntax."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        invalid_file = app_dir / "invalid.py"
        invalid_file.write_text("def broken(\nprint('missing closing paren')")
        
        try:
            validate_python_syntax(invalid_file)
            assert False, "Should have raised AppValidationError"
        except AppValidationError as e:
            assert "Invalid Python syntax" in str(e)
            print("✓ Successfully caught invalid Python syntax")


def test_has_requirements_file():
    """Test detecting requirements.txt."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        
        # Without requirements
        assert not has_requirements_file(app_dir)
        
        # With requirements
        req_file = app_dir / "requirements.txt"
        req_file.write_text("requests==2.28.0")
        assert has_requirements_file(app_dir)
        print("✓ Successfully detected requirements.txt")


def test_validate_app_directory_success():
    """Test complete app directory validation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        
        # Create valid app
        app_file = app_dir / "app.py"
        app_file.write_text("import sys\nprint('hello')")
        
        req_file = app_dir / "requirements.txt"
        req_file.write_text("requests>=2.28.0")
        
        result = validate_app_directory(str(app_dir))
        
        assert result["entry_point"] == "app.py"
        assert result["entry_point_name"] == "app"
        assert result["has_requirements"] is True
        assert "requirements.txt" in result["requirements_path"]
        print("✓ Successfully validated app directory with requirements")


def test_validate_app_directory_without_requirements():
    """Test app validation without requirements.txt."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = Path(tmpdir)
        
        # Create valid app without requirements
        main_file = app_dir / "main.py"
        main_file.write_text("print('simple app')")
        
        result = validate_app_directory(str(app_dir))
        
        assert result["entry_point"] == "main.py"
        assert result["has_requirements"] is False
        assert result["requirements_path"] is None
        print("✓ Successfully validated app directory without requirements")


def test_validate_app_directory_not_exists():
    """Test error for non-existent directory."""
    try:
        validate_app_directory("/nonexistent/path")
        assert False, "Should have raised AppValidationError"
    except AppValidationError as e:
        assert "does not exist" in str(e)
        print("✓ Successfully caught non-existent directory")


def test_validate_app_directory_not_directory():
    """Test error when path is not a directory."""
    with tempfile.NamedTemporaryFile() as tmpfile:
        try:
            validate_app_directory(tmpfile.name)
            assert False, "Should have raised AppValidationError"
        except AppValidationError as e:
            assert "Not a directory" in str(e)
            print("✓ Successfully caught non-directory path")


def test_sample_app_validation():
    """Test that sample_app passes validation."""
    # This assumes sample_app exists in the workspace
    sample_app_path = Path(__file__).parent.parent / "sample_app"
    
    if not sample_app_path.exists():
        print("⊘ Skipping sample_app validation (not found)")
        return
    
    try:
        result = validate_app_directory(str(sample_app_path))
        assert result["entry_point"] in ["app.py", "main.py", "__main__.py"]
        assert result["has_requirements"] is True  # sample_app has requirements
        print(f"✓ Successfully validated sample_app (entry: {result['entry_point']})")
    except AppValidationError as e:
        print(f"✗ sample_app validation failed: {e}")
        raise


def run_all_tests():
    """Run all test functions."""
    test_functions = [
        test_discover_entry_point_main_py,
        test_discover_entry_point_app_py,
        test_discover_entry_point_main_module,
        test_discover_entry_point_priority,
        test_discover_entry_point_not_found,
        test_validate_python_syntax_valid,
        test_validate_python_syntax_invalid,
        test_has_requirements_file,
        test_validate_app_directory_success,
        test_validate_app_directory_without_requirements,
        test_validate_app_directory_not_exists,
        test_validate_app_directory_not_directory,
        test_sample_app_validation,
    ]
    
    print("\n=== Running run-app tests ===\n")
    passed = 0
    failed = 0
    
    for test_func in test_functions:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__} failed: {e}")
            failed += 1
    
    print(f"\n=== Results: {passed} passed, {failed} failed ===\n")
    
    return failed == 0


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
