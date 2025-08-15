#!/bin/bash
#
# Manual NetworkMap Agent Version Update
# Run this script to manually increment the agent version
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 NetworkMap Agent Manual Version Update${NC}"
echo -e "${BLUE}===========================================${NC}"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTO_VERSION_SCRIPT="$SCRIPT_DIR/scripts/auto_version.py"

# Check if auto-versioning script exists
if [ ! -f "$AUTO_VERSION_SCRIPT" ]; then
    echo -e "${RED}❌ Auto-versioning script not found: $AUTO_VERSION_SCRIPT${NC}"
    exit 1
fi

# Make sure the script is executable
chmod +x "$AUTO_VERSION_SCRIPT"

echo -e "${BLUE}📋 Current agent file status:${NC}"

# Check if agent files exist
AGENT_FILES=("networkmap_agent.py" "static/networkmap_agent.py")
for file in "${AGENT_FILES[@]}"; do
    if [ -f "$SCRIPT_DIR/$file" ]; then
        # Extract current version
        VERSION=$(grep -E "__version__|VERSION" "$SCRIPT_DIR/$file" | head -1 | sed -E 's/.*["'"'"']([0-9]+\.[0-9]+\.[0-9]+)["'"'"'].*/\1/')
        echo -e "${GREEN}   ✓ $file (current version: $VERSION)${NC}"
    else
        echo -e "${YELLOW}   ⚠ $file (not found)${NC}"
    fi
done

echo ""
echo -e "${BLUE}🔄 Running version update...${NC}"

# Run the versioning script
if python3 "$AUTO_VERSION_SCRIPT"; then
    echo ""
    echo -e "${GREEN}✅ Version update completed successfully!${NC}"
    
    echo -e "${BLUE}📄 Updated files:${NC}"
    for file in "${AGENT_FILES[@]}"; do
        if [ -f "$SCRIPT_DIR/$file" ]; then
            NEW_VERSION=$(grep -E "__version__|VERSION" "$SCRIPT_DIR/$file" | head -1 | sed -E 's/.*["'"'"']([0-9]+\.[0-9]+\.[0-9]+)["'"'"'].*/\1/')
            echo -e "${GREEN}   ✓ $file (new version: $NEW_VERSION)${NC}"
        fi
    done
    
    if [ -f "$SCRIPT_DIR/VERSION_INFO.txt" ]; then
        echo -e "${GREEN}   ✓ VERSION_INFO.txt (updated)${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}📝 Next steps:${NC}"
    echo -e "   1. Review the changes: ${BLUE}git diff${NC}"
    echo -e "   2. Commit the updates: ${BLUE}git add . && git commit -m 'Update agent version'${NC}"
    echo -e "   3. Push to repository: ${BLUE}git push${NC}"
    
else
    echo -e "${RED}❌ Version update failed${NC}"
    exit 1
fi
