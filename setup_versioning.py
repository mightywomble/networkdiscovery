#!/usr/bin/env python3
"""
Setup script for NetworkMap Agent Auto-Versioning System
Initializes the versioning system with version 1.6.0
"""

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent
AGENT_FILES = [
    BASE_DIR / "networkmap_agent.py",
    BASE_DIR / "static" / "networkmap_agent.py"
]
VERSION_INFO_FILE = BASE_DIR / "VERSION_INFO.txt"

def set_initial_version():
    """Set initial version to 1.6.0 in all agent files and VERSION_INFO.txt"""
    
    initial_version = "1.6.0"
    build_date = datetime.now().strftime('%Y-%m-%d')
    
    print("🚀 Setting up NetworkMap Agent Auto-Versioning System")
    print("=" * 55)
    print(f"Initial version: {initial_version}")
    print(f"Build date: {build_date}")
    print()
    
    update_count = 0
    
    # Update all agent files
    for agent_file in AGENT_FILES:
        if not agent_file.exists():
            print(f"⚠️  Agent file not found: {agent_file}")
            continue
            
        try:
            # Read current content
            with open(agent_file, 'r') as f:
                content = f.read()
            
            # Update version patterns
            patterns = [
                (r'__version__\s*=\s*["\'][^"\']*["\']', f'__version__ = "{initial_version}"'),
                (r'__build_date__\s*=\s*["\'][^"\']*["\']', f'__build_date__ = "{build_date}"'),
                (r'VERSION\s*=\s*__version__', f'VERSION = __version__'),
                (r'BUILD_DATE\s*=\s*__build_date__', f'BUILD_DATE = __build_date__')
            ]
            
            updated = False
            for pattern, replacement in patterns:
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)
                    updated = True
            
            if updated:
                # Write updated content
                with open(agent_file, 'w') as f:
                    f.write(content)
                print(f"✅ Updated version in {agent_file.name}")
                update_count += 1
            else:
                print(f"⚠️  No version patterns found in {agent_file.name}")
                
        except Exception as e:
            print(f"❌ Error updating {agent_file}: {e}")
    
    # Update VERSION_INFO.txt
    try:
        content = f"""NetworkMap Agent Version Information
=====================================

Agent Version: {initial_version}
Build Date: {build_date}
Build Time: {datetime.now().strftime('%H:%M:%S')}
Git Commit: INITIAL_SETUP

Release Notes:
- Auto-versioning system initialized
- Version tracking system in place
- Git pre-commit hooks configured

System Features:
- Automatic version increment on agent file changes
- Git pre-commit hook integration
- Manual version update capability
- Centralized version tracking

File Locations:
- Main Agent: networkmap_agent.py
- Static Agent: static/networkmap_agent.py
- Version Info: VERSION_INFO.txt
- Versioning Script: scripts/auto_version.py
- Manual Update: update_agent_version.sh

Usage:
- Versions increment automatically when agent files are committed
- Use './update_agent_version.sh' for manual version updates
- Current version format: X.Y.Z (patch version increments)

Last Updated: {datetime.now().isoformat()}

CHANGELOG:
==========

v{initial_version} (2025-08-15) - Auto-Versioning System
------------------------------------------------------
✅ Implemented automated version management
✅ Git pre-commit hooks for version control
✅ Centralized version tracking
✅ Manual version update capabilities
✅ Enhanced test results preservation (app.py bug fix)
"""
        
        with open(VERSION_INFO_FILE, 'w') as f:
            f.write(content)
        
        print(f"✅ Updated {VERSION_INFO_FILE.name}")
        update_count += 1
        
    except Exception as e:
        print(f"❌ Error updating VERSION_INFO.txt: {e}")
    
    print(f"\n🎉 Successfully updated {update_count} files with version {initial_version}")
    
    # Check Git hooks
    pre_commit_hook = BASE_DIR / ".git" / "hooks" / "pre-commit"
    if pre_commit_hook.exists():
        print("✅ Git pre-commit hook is installed")
    else:
        print("⚠️  Git pre-commit hook not found")
    
    # Check versioning scripts
    auto_version_script = BASE_DIR / "scripts" / "auto_version.py"
    manual_update_script = BASE_DIR / "update_agent_version.sh"
    
    if auto_version_script.exists():
        print("✅ Auto-versioning script is installed")
    else:
        print("⚠️  Auto-versioning script not found")
    
    if manual_update_script.exists():
        print("✅ Manual update script is installed")
    else:
        print("⚠️  Manual update script not found")
    
    print("\n📋 SETUP COMPLETE!")
    print("================")
    print("Your auto-versioning system is now ready:")
    print()
    print("🔄 Automatic versioning:")
    print("   - Edit any agent file (networkmap_agent.py, static/networkmap_agent.py)")
    print("   - Commit changes with git")
    print("   - Version will automatically increment")
    print()
    print("⚙️ Manual versioning:")
    print("   - Run: ./update_agent_version.sh")
    print("   - Or: python3 scripts/auto_version.py")
    print()
    print("📊 Version tracking:")
    print("   - Current version info in VERSION_INFO.txt")
    print("   - Agent files contain embedded version numbers")
    print()
    print("🚀 Next version will be: 1.6.1")
    
    return True

if __name__ == '__main__':
    try:
        success = set_initial_version()
        if success:
            print("\n✅ Auto-versioning system setup completed successfully!")
        exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        exit(1)
