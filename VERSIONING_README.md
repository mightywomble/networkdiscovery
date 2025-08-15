# NetworkMap Agent Auto-Versioning System

🚀 **Automated version management for NetworkMap Agent files**

## Overview

This system automatically increments version numbers whenever changes are made to the NetworkMap Agent Python files. The version follows semantic versioning format (X.Y.Z) where the patch number (Z) increments automatically.

## Features

✅ **Automatic Version Increment**: Version numbers update automatically when agent files are modified  
✅ **Git Integration**: Pre-commit hooks ensure versions are updated before commits  
✅ **Manual Control**: Scripts available for manual version updates  
✅ **Centralized Tracking**: All version information maintained in VERSION_INFO.txt  
✅ **Multiple File Support**: Updates both main and static agent files simultaneously  

## Files Monitored

- `networkmap_agent.py` - Main agent file
- `static/networkmap_agent.py` - Static agent file for web distribution

## Version Format

**Current Version**: `1.6.0`
**Next Version**: `1.6.1` (after next change)

Versions follow the pattern: `MAJOR.MINOR.PATCH`
- The patch number (last digit) increments automatically with each change
- Major and minor versions can be manually adjusted if needed

## How It Works

### 1. Automatic Versioning (Recommended)

When you make changes to agent files and commit them:

```bash
# Edit agent files
vim networkmap_agent.py
vim static/networkmap_agent.py

# Commit changes - version will increment automatically
git add .
git commit -m "Updated agent functionality"
git push
```

**What happens:**
1. Pre-commit hook detects agent file changes
2. Auto-versioning script runs automatically
3. Version numbers update in all files
4. Updated files are staged for commit
5. Commit proceeds with version updates included

### 2. Manual Versioning

For immediate version updates without committing:

```bash
# Method 1: Use the convenience script
./update_agent_version.sh

# Method 2: Run the versioning script directly
python3 scripts/auto_version.py
```

## System Components

### Core Files

- **`scripts/auto_version.py`** - Main versioning logic
- **`.git/hooks/pre-commit`** - Git hook for automatic versioning
- **`update_agent_version.sh`** - Manual version update script
- **`setup_versioning.py`** - Initial system setup script
- **`VERSION_INFO.txt`** - Centralized version information

### Agent Files Updated

- **`networkmap_agent.py`** - Main agent file
  - Updates `__version__ = "X.Y.Z"`
  - Updates `__build_date__ = "YYYY-MM-DD"`
- **`static/networkmap_agent.py`** - Web-distributed agent
  - Updates `__version__ = "X.Y.Z"`
  - Updates `__build_date__ = "YYYY-MM-DD"`
- **`VERSION_INFO.txt`** - Version tracking file
  - Updates agent version
  - Updates build information
  - Maintains changelog

## Installation

The system is already installed and configured! But if you need to reinstall:

```bash
# Run the setup script
python3 setup_versioning.py

# Verify installation
ls -la .git/hooks/pre-commit     # Should exist and be executable
ls -la scripts/auto_version.py   # Should exist and be executable
ls -la update_agent_version.sh   # Should exist and be executable
```

## Usage Examples

### Scenario 1: Making Agent Improvements

```bash
# Edit agent functionality
vim static/networkmap_agent.py

# Regular commit - version increments automatically
git add .
git commit -m "Enhanced network discovery capabilities"
# Version automatically increments: 1.6.0 → 1.6.1

git push
```

### Scenario 2: Manual Version Bump

```bash
# Update version immediately
./update_agent_version.sh

# Review changes
git diff

# Commit the version update
git add .
git commit -m "Version bump for release preparation"
git push
```

### Scenario 3: Checking Current Version

```bash
# Check version in files
grep -E "__version__|VERSION" static/networkmap_agent.py

# Check centralized version info
cat VERSION_INFO.txt

# Check version on deployed agents
python3 static/networkmap_agent.py --version
```

## Version History

- **v1.6.0** - Auto-versioning system initialized
- **v1.5.3** - Test results preservation bug fix
- **v1.5.2** - Enhanced testing framework

## Troubleshooting

### Pre-commit Hook Not Running

```bash
# Check if hook exists and is executable
ls -la .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Version Not Updating

```bash
# Run manual version update
./update_agent_version.sh

# Check for errors in the versioning script
python3 scripts/auto_version.py
```

### Reset Version System

```bash
# Reinstall the versioning system
python3 setup_versioning.py
```

## Advanced Configuration

### Customizing Version Patterns

Edit `scripts/auto_version.py` to modify:
- Version number format
- Build date format  
- File patterns to update

### Adding New Files

To monitor additional files, update the `AGENT_FILES` list in:
- `scripts/auto_version.py`
- `.git/hooks/pre-commit`

### Changing Version Increment Logic

In `scripts/auto_version.py`, modify the `increment_version()` function:

```python
def increment_version(current_version):
    major, minor, patch = map(int, current_version.split('.'))
    # Customize increment logic here
    new_patch = patch + 1  # Current: increment patch
    return f"{major}.{minor}.{new_patch}"
```

## Integration with Deployment

When agents are updated on remote hosts, they will report their new version numbers, making it easy to track deployment status across your network infrastructure.

The version information is embedded in the Python files themselves, so deployed agents carry their version metadata with them.

## Support

The versioning system is designed to be maintenance-free. It runs automatically whenever you commit changes to agent files, ensuring version consistency across all deployments.

For issues or customizations, refer to the script files which contain detailed comments and error handling.
