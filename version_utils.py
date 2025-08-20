#!/usr/bin/env python3
"""
Version Utilities for NetworkMap
Handles version comparison and validation for agent versions
"""

import re
from typing import Optional, Tuple, List


def parse_version(version: str) -> Optional[Tuple[int, ...]]:
    """
    Parse a version string into a tuple of integers for comparison
    
    Args:
        version: Version string (e.g., "1.6.0", "2.1.3")
    
    Returns:
        tuple: Tuple of integers representing version parts, or None if invalid
    """
    if not version:
        return None
    
    try:
        # Remove any non-digit, non-dot characters (like "v1.6.0")
        clean_version = re.sub(r'[^0-9.]', '', str(version))
        
        # Split by dots and convert to integers
        parts = [int(part) for part in clean_version.split('.') if part.isdigit()]
        
        if not parts:
            return None
            
        return tuple(parts)
    except (ValueError, AttributeError):
        return None


def compare_versions(version1: str, version2: str) -> int:
    """
    Compare two version strings
    
    Args:
        version1: First version string
        version2: Second version string
    
    Returns:
        int: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
             Returns 0 if either version is invalid
    """
    v1_parts = parse_version(version1)
    v2_parts = parse_version(version2)
    
    # If either version is invalid, consider them equal
    if v1_parts is None or v2_parts is None:
        return 0
    
    # Normalize lengths by padding with zeros
    max_len = max(len(v1_parts), len(v2_parts))
    v1_normalized = v1_parts + (0,) * (max_len - len(v1_parts))
    v2_normalized = v2_parts + (0,) * (max_len - len(v2_parts))
    
    # Compare part by part
    if v1_normalized < v2_normalized:
        return -1
    elif v1_normalized > v2_normalized:
        return 1
    else:
        return 0


def is_version_compatible(current_version: str, minimum_version: str) -> bool:
    """
    Check if current version meets minimum version requirement
    
    Args:
        current_version: Current agent version
        minimum_version: Minimum required version
    
    Returns:
        bool: True if current_version >= minimum_version
    """
    if not current_version or not minimum_version:
        return False
    
    # Parse both versions to ensure they are valid
    current_parsed = parse_version(current_version)
    minimum_parsed = parse_version(minimum_version)
    
    # If either version is invalid, consider incompatible
    if current_parsed is None or minimum_parsed is None:
        return False
    
    return compare_versions(current_version, minimum_version) >= 0


def get_version_info(version: str) -> dict:
    """
    Get detailed information about a version string
    
    Args:
        version: Version string
    
    Returns:
        dict: Version information including parsed parts and display format
    """
    parsed = parse_version(version)
    
    return {
        'original': version,
        'parsed': parsed,
        'is_valid': parsed is not None,
        'normalized': '.'.join(map(str, parsed)) if parsed else None,
        'parts': {
            'major': parsed[0] if parsed and len(parsed) > 0 else None,
            'minor': parsed[1] if parsed and len(parsed) > 1 else None,
            'patch': parsed[2] if parsed and len(parsed) > 2 else None,
        } if parsed else None
    }


def format_version_comparison_error(current_version: str, minimum_version: str) -> str:
    """
    Format a user-friendly error message for version incompatibility
    
    Args:
        current_version: Current agent version
        minimum_version: Minimum required version
    
    Returns:
        str: Formatted error message
    """
    current_info = get_version_info(current_version)
    minimum_info = get_version_info(minimum_version)
    
    if not current_info['is_valid']:
        return f"Invalid agent version '{current_version}'. Cannot determine version compatibility."
    
    if not minimum_info['is_valid']:
        return f"Invalid minimum version requirement '{minimum_version}'. Please check configuration."
    
    return (
        f"Agent version {current_info['normalized']} does not meet the minimum "
        f"required version {minimum_info['normalized']} for AI script execution."
    )


if __name__ == "__main__":
    # Test version comparison
    test_cases = [
        ("1.6.0", "1.6.0", True),   # Equal
        ("1.6.1", "1.6.0", True),   # Patch higher
        ("1.7.0", "1.6.0", True),   # Minor higher  
        ("2.0.0", "1.6.0", True),   # Major higher
        ("1.5.9", "1.6.0", False),  # Minor lower
        ("1.6.0", "1.6.1", False),  # Patch lower
        ("0.9.9", "1.0.0", False),  # Major lower
        ("v1.6.0", "1.6.0", True),  # With prefix
        ("1.6", "1.6.0", True),     # Missing patch
        ("1.6.0.1", "1.6.0", True), # Extra version part
    ]
    
    print("Version Compatibility Tests:")
    for current, minimum, expected in test_cases:
        result = is_version_compatible(current, minimum)
        status = "✓" if result == expected else "✗"
        print(f"{status} {current} >= {minimum}: {result}")
    
    print("\nVersion Comparison Tests:")
    comparison_tests = [
        ("1.6.0", "1.6.0", 0),
        ("1.6.1", "1.6.0", 1),
        ("1.6.0", "1.6.1", -1),
        ("2.0.0", "1.9.9", 1),
    ]
    
    for v1, v2, expected in comparison_tests:
        result = compare_versions(v1, v2)
        status = "✓" if result == expected else "✗"
        print(f"{status} compare({v1}, {v2}): {result}")
