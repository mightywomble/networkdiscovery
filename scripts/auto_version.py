#!/usr/bin/env python3
"""
Automated versioning script for NetworkMap Agent
Increments version numbers when agent files are modified
"""

import os
import re
import sys
from datetime import datetime
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent
AGENT_FILES = [
    BASE_DIR / "networkmap_agent.py",
    BASE_DIR / "static" / "networkmap_agent.py"
]
VERSION_INFO_FILE = BASE_DIR / "VERSION_INFO.txt"

def get_current_version():
    """Get current version from VERSION_INFO.txt"""
    try:
        if VERSION_INFO_FILE.exists():
            with open(VERSION_INFO_FILE, 'r') as f:
                content = f.read()
                # Look for version line
                version_match = re.search(r'Agent Version:\s*(\d+\.\d+\.\d+)', content)
                if version_match:
                    return version_match.group(1)
    except Exception as e:
        print(f"Warning: Could not read current version: {e}")
    
    # Default version if not found
    return "1.5.2"

def increment_version(current_version):
    """Increment the patch version number (X.Y.Z -> X.Y.Z+1)"""
    try:
        major, minor, patch = map(int, current_version.split('.'))
        # For agent updates, we increment the patch version
        new_patch = patch + 1
        return f"{major}.{minor}.{new_patch}"
    except Exception as e:
        print(f"Error incrementing version {current_version}: {e}")
        return "1.6.0"  # fallback to starting version

def update_agent_file(file_path, new_version, build_date):
    """Update version information in agent Python file"""
    if not file_path.exists():
        print(f"Warning: Agent file not found: {file_path}")
        return False
    
    try:
        # Read current content
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Update version patterns
        patterns = [
            (r'__version__\s*=\s*["\'][^"\']*["\']', f'__version__ = "{new_version}"'),
            (r'__build_date__\s*=\s*["\'][^"\']*["\']', f'__build_date__ = "{build_date}"'),
            (r'VERSION\s*=\s*["\'][^"\']*["\']', f'VERSION = "{new_version}"'),
            (r'BUILD_DATE\s*=\s*["\'][^"\']*["\']', f'BUILD_DATE = "{build_date}"')
        ]
        
        updated = False
        for pattern, replacement in patterns:
            if re.search(pattern, content):
                content = re.sub(pattern, replacement, content)
                updated = True
        
        # If no version patterns found, add them after imports
        if not updated:
            # Look for the end of imports or beginning of class definition
            insertion_point = None
            lines = content.split('\n')
            
            for i, line in enumerate(lines):
                if line.strip().startswith('class ') or line.strip().startswith('def ') or line.strip().startswith('if __name__'):
                    insertion_point = i
                    break
            
            if insertion_point is None:
                # Find line with imports
                for i, line in enumerate(lines):
                    if line.strip() and not line.startswith('#') and not line.startswith('"""') and not line.startswith("'''"):
                        if 'import' in line:
                            continue
                        insertion_point = i
                        break
            
            if insertion_point is not None:
                version_lines = [
                    "",
                    "# Agent version and build information",
                    f'__version__ = "{new_version}"',
                    f'__build_date__ = "{build_date}"',
                    "",
                    f'VERSION = __version__',
                    f'BUILD_DATE = __build_date__',
                    ""
                ]
                
                lines = lines[:insertion_point] + version_lines + lines[insertion_point:]
                content = '\n'.join(lines)
                updated = True
        
        if updated:
            # Write updated content
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"✓ Updated version in {file_path}")
            return True
        else:
            print(f"Warning: No version patterns found in {file_path}")
            return False
            
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

def update_version_info_file(new_version, build_date):
    """Update VERSION_INFO.txt file"""
    try:
        content = f"""NetworkMap Agent Version Information
=====================================

Agent Version: {new_version}
Build Date: {build_date}
Build Time: {datetime.now().strftime('%H:%M:%S')}
Git Commit: AUTO_VERSIONED

Release Notes:
- Automated version increment
- Agent files updated with new version information
- Version tracking enhanced

File Locations:
- Main Agent: networkmap_agent.py
- Static Agent: static/networkmap_agent.py
- Version Info: VERSION_INFO.txt

Last Updated: {datetime.now().isoformat()}
"""
        
        with open(VERSION_INFO_FILE, 'w') as f:
            f.write(content)
        
        print(f"✓ Updated {VERSION_INFO_FILE}")
        return True
        
    except Exception as e:
        print(f"Error updating version info file: {e}")
        return False

def main():
    """Main versioning function"""
    print("🔄 NetworkMap Agent Auto-Versioning System")
    print("=" * 50)
    
    # Get current version
    current_version = get_current_version()
    print(f"Current version: {current_version}")
    
    # Increment version
    new_version = increment_version(current_version)
    print(f"New version: {new_version}")
    
    # Build date
    build_date = datetime.now().strftime('%Y-%m-%d')
    print(f"Build date: {build_date}")
    
    # Update all agent files
    update_count = 0
    for agent_file in AGENT_FILES:
        if update_agent_file(agent_file, new_version, build_date):
            update_count += 1
    
    # Update version info file
    if update_version_info_file(new_version, build_date):
        update_count += 1
    
    print(f"\n✅ Successfully updated {update_count} files with version {new_version}")
    
    # Stage the updated files for git
    try:
        import subprocess
        files_to_stage = []
        
        for agent_file in AGENT_FILES:
            if agent_file.exists():
                files_to_stage.append(str(agent_file))
        
        if VERSION_INFO_FILE.exists():
            files_to_stage.append(str(VERSION_INFO_FILE))
        
        if files_to_stage:
            # Stage files
            subprocess.run(['git', 'add'] + files_to_stage, cwd=BASE_DIR, check=True)
            print(f"✓ Staged {len(files_to_stage)} updated files for commit")
        
    except Exception as e:
        print(f"Warning: Could not stage files automatically: {e}")
        print("Please manually stage the updated files")
    
    return True

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️ Versioning interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Versioning failed: {e}")
        sys.exit(1)
