#!/bin/bash

# ReconMaster Fix Script
# This script fixes issues with the ReconMaster tool

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored status messages
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root"
    exit 1
fi

INSTALL_DIR="/opt/reconmaster"
TOOLS_DIR="$INSTALL_DIR/tools"

# Fix the Python script syntax warning
print_status "Fixing syntax warning in reconmaster.py..."
sed -i 's/grep '\''\\\.js$'\''/grep '\''\\.js$'\''/' $INSTALL_DIR/reconmaster.py
print_success "Fixed invalid escape sequence in grep command"

# Check if Go is properly installed and in PATH
if ! command -v go &> /dev/null; then
    print_status "Installing Go..."
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' > /etc/profile.d/go.sh
    chmod +x /etc/profile.d/go.sh
    print_success "Go installed. Please log out and log back in to update your PATH"
else
    print_success "Go is already installed"
fi

# Create a directory for Go bins if it doesn't exist
mkdir -p /usr/local/bin

# Function to install Go tools and create symlinks
install_go_tool() {
    TOOL_NAME=$1
    TOOL_REPO=$2
    TOOL_CMD=$3
    
    print_status "Installing $TOOL_NAME..."
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    # Install the tool
    go install $TOOL_REPO@latest
    
    # Find the binary
    if [ -f "$HOME/go/bin/$TOOL_CMD" ]; then
        print_status "Creating symlink for $TOOL_CMD..."
        ln -sf $HOME/go/bin/$TOOL_CMD /usr/local/bin/$TOOL_CMD
        chmod +x /usr/local/bin/$TOOL_CMD
        print_success "$TOOL_NAME installed successfully"
    else
        print_error "Failed to find $TOOL_CMD binary. Trying to locate it..."
        
        # Try to find the binary
        GO_BIN=$(find $HOME/go/bin -name "$TOOL_CMD" 2>/dev/null)
        if [ -n "$GO_BIN" ]; then
            print_status "Found $TOOL_CMD at $GO_BIN"
            ln -sf $GO_BIN /usr/local/bin/$TOOL_CMD
            chmod +x /usr/local/bin/$TOOL_CMD
            print_success "$TOOL_NAME installed successfully"
        else
            print_error "Cannot find $TOOL_CMD binary. You might need to install it manually."
        fi
    fi
}

# Install all the required tools
print_status "Installing required tools..."

# Install subfinder
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"

# Install assetfinder
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder" "assetfinder"

# Install amass
install_go_tool "amass" "github.com/owasp-amass/amass/v3/..." "amass"

# Install httpx
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"

# Install ffuf
install_go_tool "ffuf" "github.com/ffuf/ffuf" "ffuf"

# Install gowitness
install_go_tool "gowitness" "github.com/sensepost/gowitness" "gowitness"

# Install katana
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana" "katana"

# Install subjs
install_go_tool "subjs" "github.com/lc/subjs" "subjs"

# Install subzy
install_go_tool "subzy" "github.com/PentestPad/subzy" "subzy"

# Install socialhunter
install_go_tool "socialhunter" "github.com/utkusen/socialhunter" "socialhunter"

# Install LinkFinder if not already installed
if [ ! -d "$TOOLS_DIR/LinkFinder" ]; then
    print_status "Installing LinkFinder..."
    mkdir -p $TOOLS_DIR
    git clone https://github.com/GerbenJavado/LinkFinder.git $TOOLS_DIR/LinkFinder
    cd $TOOLS_DIR/LinkFinder
    pip3 install -r requirements.txt
    python3 setup.py install
    print_success "LinkFinder installed successfully"
else
    print_success "LinkFinder is already installed"
fi

# Install Arjun if not already installed
if [ ! -d "$TOOLS_DIR/Arjun" ]; then
    print_status "Installing Arjun..."
    mkdir -p $TOOLS_DIR
    git clone https://github.com/s0md3v/Arjun.git $TOOLS_DIR/Arjun
    cd $TOOLS_DIR/Arjun
    pip3 install -r requirements.txt
    
    # Create a wrapper script for Arjun
    cat > /usr/local/bin/arjun << 'EOF'
#!/bin/bash
python3 /opt/reconmaster/tools/Arjun/arjun.py "$@"
EOF
    chmod +x /usr/local/bin/arjun
    print_success "Arjun installed successfully"
else
    print_success "Arjun is already installed"
    
    # Ensure the wrapper script exists
    if [ ! -f "/usr/local/bin/arjun" ]; then
        cat > /usr/local/bin/arjun << 'EOF'
#!/bin/bash
python3 /opt/reconmaster/tools/Arjun/arjun.py "$@"
EOF
        chmod +x /usr/local/bin/arjun
    fi
fi

# Download SecLists if not already installed
if [ ! -d "/usr/share/seclists" ]; then
    print_status "Downloading SecLists (common wordlists)..."
    git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    print_success "SecLists downloaded successfully"
else
    print_success "SecLists already exists"
fi

# Create a setup script that users can run to update their PATH
cat > /usr/local/bin/reconmaster-setup << 'EOF'
#!/bin/bash
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
echo "PATH updated. Please restart your terminal or run 'source ~/.bashrc'"
EOF
chmod +x /usr/local/bin/reconmaster-setup

# Fix missing LinkFinder path in reconmaster.py
print_status "Updating LinkFinder path in reconmaster.py..."
LINKFINDER_PATH="$TOOLS_DIR/LinkFinder"
sed -i "s|python3 /path/to/LinkFinder/linkfinder.py|python3 $LINKFINDER_PATH/linkfinder.py|" $INSTALL_DIR/reconmaster.py
print_success "LinkFinder path updated in reconmaster.py"

# Update PATH for this session
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Installation complete
echo -e "${GREEN}"
echo "======================================================="
echo "         ReconMaster Fix Applied Successfully!"
echo "======================================================="
echo -e "${NC}"
echo "1. The escape sequence error has been fixed."
echo "2. All required tools have been installed and symlinked."
echo ""
echo "Please run the following command to update your PATH:"
echo "    reconmaster-setup"
echo ""
echo "After that, either restart your terminal or run 'source ~/.bashrc'"
echo "Then you should be able to run reconmaster without issues."
echo ""
echo "Happy Hunting!"
