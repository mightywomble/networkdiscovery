#!/bin/bash

# Network Map Application Setup Script

echo "=========================================="
echo "Network Map Application Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python 3 is available
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        echo -e "${GREEN}✓${NC} Python 3 found: $PYTHON_VERSION"
    else
        echo -e "${RED}✗${NC} Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
}

# Set up virtual environment
setup_venv() {
    echo -e "\n${YELLOW}Setting up virtual environment...${NC}"
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        echo -e "${GREEN}✓${NC} Virtual environment created"
    else
        echo -e "${GREEN}✓${NC} Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    echo -e "${GREEN}✓${NC} Pip upgraded"
}

# Install dependencies
install_deps() {
    echo -e "\n${YELLOW}Installing dependencies...${NC}"
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        echo -e "${GREEN}✓${NC} Dependencies installed"
    else
        echo -e "${RED}✗${NC} requirements.txt not found"
        exit 1
    fi
}

# Check optional dependencies
check_optional() {
    echo -e "\n${YELLOW}Checking optional dependencies...${NC}"
    
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}✓${NC} nmap found (enhanced port scanning available)"
    else
        echo -e "${YELLOW}!${NC} nmap not found (basic port scanning only)"
        echo "  To install: brew install nmap (macOS) or apt-get install nmap (Ubuntu)"
    fi
    
    if command -v ssh &> /dev/null; then
        echo -e "${GREEN}✓${NC} SSH client found"
    else
        echo -e "${RED}✗${NC} SSH client not found"
    fi
}

# Run basic tests
run_tests() {
    echo -e "\n${YELLOW}Running basic tests...${NC}"
    
    if python3 test_basic.py; then
        echo -e "${GREEN}✓${NC} Basic tests passed"
    else
        echo -e "${RED}✗${NC} Some tests failed"
        echo "  Check the output above for details"
    fi
}

# SSH setup instructions
ssh_instructions() {
    echo -e "\n${YELLOW}SSH Setup Instructions:${NC}"
    echo "1. Generate SSH key (if you don't have one):"
    echo "   ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa"
    echo ""
    echo "2. Copy your public key to target hosts:"
    echo "   ssh-copy-id username@host-ip"
    echo ""
    echo "3. Test SSH connection:"
    echo "   ssh username@host-ip"
    echo ""
    echo "Make sure you can SSH to your target hosts without passwords!"
}

# Final instructions
final_instructions() {
    echo -e "\n${GREEN}=========================================="
    echo -e "Setup Complete!"
    echo -e "==========================================${NC}"
    echo ""
    echo "To start the application:"
    echo "  1. Activate virtual environment: source venv/bin/activate"
    echo "  2. Run the application: python3 run.py"
    echo "  3. Open browser to: http://localhost:5150"
    echo ""
    echo "First steps:"
    echo "  1. Add your first host in the 'Hosts' section"
    echo "  2. Click 'Scan Now' to start monitoring"
    echo "  3. View results in the 'Network Map'"
    echo ""
    echo "Need help? Check README.md for detailed instructions."
}

# Main execution
main() {
    check_python
    setup_venv
    install_deps
    check_optional
    run_tests
    ssh_instructions
    final_instructions
}

# Run main function
main
