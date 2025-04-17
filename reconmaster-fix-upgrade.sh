#!/bin/bash

# ReconMaster Fix and Upgrade Script
# This script fixes issues with the ReconMaster tool and upgrades all components
# Version: 2.0

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

print_info() {
    echo -e "${CYAN}[i]${NC} $1"
}

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root"
    exit 1
fi

# Directories
INSTALL_DIR="/opt/reconmaster"
TOOLS_DIR="$INSTALL_DIR/tools"
WORDLISTS_DIR="$INSTALL_DIR/wordlists"
BACKUP_DIR="$INSTALL_DIR/backups/$(date +%Y%m%d%H%M%S)"

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p $INSTALL_DIR
    mkdir -p $TOOLS_DIR
    mkdir -p $WORDLISTS_DIR
    mkdir -p $BACKUP_DIR
    mkdir -p /usr/local/bin
    print_success "Directories created"
}

# Backup current installation
backup_current_installation() {
    if [ -f "$INSTALL_DIR/reconmaster.py" ]; then
        print_status "Backing up current ReconMaster installation..."
        cp -r $INSTALL_DIR/* $BACKUP_DIR/ 2>/dev/null || true
        print_success "Backup created at $BACKUP_DIR"
    else
        print_warning "No existing ReconMaster installation found to backup"
    fi
}

# Fix the Python script syntax warning
fix_syntax_warning() {
    if [ -f "$INSTALL_DIR/reconmaster.py" ]; then
        print_status "Fixing syntax warning in reconmaster.py..."
        # Make a backup first
        cp "$INSTALL_DIR/reconmaster.py" "$INSTALL_DIR/reconmaster.py.bak"
        
        # Fix invalid escape sequence
        sed -i 's/grep '\''\\\.js$'\''/grep '\''\\.js$'\''/' "$INSTALL_DIR/reconmaster.py"
        
        # Fix any potential hardcoded paths
        sed -i "s|python3 /path/to/LinkFinder/linkfinder.py|python3 $TOOLS_DIR/LinkFinder/linkfinder.py|g" "$INSTALL_DIR/reconmaster.py"
        
        print_success "Fixed invalid escape sequences and paths in reconmaster.py"
    else
        print_warning "reconmaster.py not found. Skipping syntax fixes."
    fi
}

# Install required system packages
install_system_dependencies() {
    print_status "Updating package lists..."
    apt-get update -qq
    
    print_status "Installing required system dependencies..."
    apt-get install -y -qq curl wget git python3 python3-pip build-essential libssl-dev libffi-dev python3-dev chromium-driver
    
    print_success "System dependencies installed"
}

# Install and configure Go
install_go() {
    # Latest stable Go version as of April 2025
    GO_VERSION="1.22.2"
    
    if command -v go &> /dev/null; then
        CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_info "Go version $CURRENT_GO_VERSION is installed"
        
        # Compare versions
        if [ "$(printf '%s\n' "$GO_VERSION" "$CURRENT_GO_VERSION" | sort -V | head -n1)" != "$GO_VERSION" ]; then
            print_status "Upgrading Go from $CURRENT_GO_VERSION to $GO_VERSION..."
            rm -rf /usr/local/go
        else
            print_success "Go is already at the latest required version"
            return 0
        fi
    else
        print_status "Go not found. Installing Go $GO_VERSION..."
    fi
    
    # Download and install Go
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    if [ $? -ne 0 ]; then
        print_error "Failed to download Go. Please check your internet connection."
        return 1
    fi
    
    # Extract Go
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    if [ $? -ne 0 ]; then
        print_error "Failed to extract Go."
        return 1
    fi
    
    # Set up Go environment
    cat > /etc/profile.d/go.sh << 'EOF'
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
EOF
    chmod +x /etc/profile.d/go.sh
    
    # Source the environment for current session
    export GOPATH=$HOME/go
    export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
    
    # Verify installation
    if command -v go &> /dev/null; then
        print_success "Go $GO_VERSION installed successfully"
    else
        print_error "Go installation failed. Please install manually."
        return 1
    fi
    
    return 0
}

# Function to install or update a Go tool
install_go_tool() {
    TOOL_NAME=$1
    TOOL_REPO=$2
    TOOL_CMD=$3
    
    print_status "Installing/Updating $TOOL_NAME..."
    
    # Check if tool is already installed
    if command -v $TOOL_CMD &> /dev/null; then
        print_info "$TOOL_NAME is already installed. Updating..."
    fi
    
    # Install or update the tool
    go install $TOOL_REPO@latest
    
    if [ $? -ne 0 ]; then
        print_error "Failed to install $TOOL_NAME. Trying alternative method..."
        # Try alternative installation method
        GO111MODULE=on go install $TOOL_REPO@latest
        
        if [ $? -ne 0 ]; then
            print_error "Failed to install $TOOL_NAME."
            return 1
        fi
    fi
    
    # Find the binary
    TOOL_PATH=""
    if [ -f "$GOPATH/bin/$TOOL_CMD" ]; then
        TOOL_PATH="$GOPATH/bin/$TOOL_CMD"
    elif [ -f "$HOME/go/bin/$TOOL_CMD" ]; then
        TOOL_PATH="$HOME/go/bin/$TOOL_CMD"
    else
        # Try to find the binary anywhere in Go paths
        TOOL_PATH=$(find $GOPATH/bin $HOME/go/bin -name "$TOOL_CMD" 2>/dev/null | head -n 1)
    fi
    
    if [ -n "$TOOL_PATH" ]; then
        print_status "Creating symlink for $TOOL_CMD..."
        ln -sf "$TOOL_PATH" "/usr/local/bin/$TOOL_CMD"
        chmod +x "/usr/local/bin/$TOOL_CMD"
        print_success "$TOOL_NAME installed/updated successfully"
        return 0
    else
        print_error "Cannot find $TOOL_CMD binary. Installation may have failed."
        return 1
    fi
}

# Install Git repositories with potential Python dependencies
install_git_repo() {
    TOOL_NAME=$1
    REPO_URL=$2
    INSTALL_PATH="$TOOLS_DIR/$TOOL_NAME"
    REQUIREMENTS_FILE=${3:-"requirements.txt"}
    SETUP_FILE=${4:-"setup.py"}
    BIN_NAME=$5
    
    print_status "Installing/Updating $TOOL_NAME..."
    
    # Check if directory exists
    if [ -d "$INSTALL_PATH" ]; then
        print_info "$TOOL_NAME directory exists. Updating..."
        cd "$INSTALL_PATH"
        git pull
    else
        print_info "Cloning $TOOL_NAME repository..."
        git clone "$REPO_URL" "$INSTALL_PATH"
        cd "$INSTALL_PATH"
    fi
    
    # Install requirements if they exist
    if [ -f "$REQUIREMENTS_FILE" ]; then
        print_info "Installing Python dependencies for $TOOL_NAME..."
        pip3 install -r "$REQUIREMENTS_FILE"
    fi
    
    # Run setup.py if it exists
    if [ -f "$SETUP_FILE" ]; then
        print_info "Running setup for $TOOL_NAME..."
        python3 "$SETUP_FILE" install
    fi
    
    # Create wrapper script if BIN_NAME is provided
    if [ -n "$BIN_NAME" ]; then
        print_info "Creating wrapper script for $TOOL_NAME..."
        cat > "/usr/local/bin/$BIN_NAME" << EOF
#!/bin/bash
python3 "$INSTALL_PATH/${BIN_NAME}.py" "\$@"
EOF
        chmod +x "/usr/local/bin/$BIN_NAME"
    fi
    
    print_success "$TOOL_NAME installed/updated successfully"
}

# Install all required Go tools
install_all_go_tools() {
    print_status "Installing/Updating all required Go tools..."
    
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
    install_go_tool "subzy" "github.com/LukaSikic/subzy" "subzy"
    
    # Install socialhunter
    install_go_tool "socialhunter" "github.com/utkusen/socialhunter" "socialhunter"
    
    # New tools (2025 additions)
    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei" "nuclei"
    install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx" "dnsx"
    install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu" "naabu"
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau" "gau"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls" "waybackurls"
    
    print_success "All Go tools installed/updated successfully"
}

# Install Python-based tools
install_python_tools() {
    print_status "Installing/Updating Python-based tools..."
    
    # Install LinkFinder
    install_git_repo "LinkFinder" "https://github.com/GerbenJavado/LinkFinder.git"
    
    # Install Arjun
    install_git_repo "Arjun" "https://github.com/s0md3v/Arjun.git" "requirements.txt" "" "arjun"
    
    # New Python-based tools (2025 additions)
    pip3 install dirsearch
    pip3 install git+https://github.com/aboul3la/Sublist3r.git
    
    print_success "All Python tools installed/updated successfully"
}

# Download wordlists and reference data
download_wordlists() {
    print_status "Downloading/Updating wordlists and reference data..."
    
    # Download SecLists if not already installed
    if [ ! -d "/usr/share/seclists" ]; then
        print_status "Downloading SecLists..."
        git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
        print_success "SecLists downloaded successfully"
    else
        print_status "Updating SecLists..."
        cd /usr/share/seclists
        git pull
        print_success "SecLists updated successfully"
    fi
    
    # Create symlinks to commonly used wordlists
    print_status "Creating symlinks to commonly used wordlists..."
    ln -sf /usr/share/seclists/Discovery/Web-Content/common.txt $WORDLISTS_DIR/common-web.txt
    ln -sf /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt $WORDLISTS_DIR/common-subdomains.txt
    ln -sf /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt $WORDLISTS_DIR/api-endpoints.txt
    
    print_success "Wordlists and reference data setup complete"
}

# Create setup scripts and configuration files
create_setup_scripts() {
    print_status "Creating setup scripts and configuration files..."
    
    # Create a setup script that users can run to update their PATH
    cat > /usr/local/bin/reconmaster-setup << 'EOF'
#!/bin/bash
echo '# ReconMaster PATH setup' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc
echo "PATH updated. Please restart your terminal or run 'source ~/.bashrc'"
EOF
    chmod +x /usr/local/bin/reconmaster-setup
    
    # Create a tool updater script
    cat > /usr/local/bin/reconmaster-update << 'EOF'
#!/bin/bash
echo "Updating ReconMaster tools..."
sudo /opt/reconmaster/tools/update.sh
EOF
    chmod +x /usr/local/bin/reconmaster-update
    
    # Create the update script
    cat > $TOOLS_DIR/update.sh << 'EOF'
#!/bin/bash
# ReconMaster Update Script
cd /opt/reconmaster && git pull
bash /opt/reconmaster/fix-upgrade.sh --no-backup
EOF
    chmod +x $TOOLS_DIR/update.sh
    
    # Create a desktop icon/shortcut
    mkdir -p /usr/share/applications
    cat > /usr/share/applications/reconmaster.desktop << 'EOF'
[Desktop Entry]
Name=ReconMaster
Comment=Security reconnaissance tool
Exec=terminator -e "bash -c 'cd /opt/reconmaster && sudo python3 reconmaster.py; bash'"
Icon=/opt/reconmaster/icon.png
Terminal=false
Type=Application
Categories=Security;
EOF
    
    print_success "Setup scripts and configuration files created"
}

# Verify installations
verify_installations() {
    print_status "Verifying installations..."
    
    FAILED_TOOLS=()
    
    # List of tools to verify
    TOOLS=(
        "go"
        "subfinder"
        "assetfinder"
        "amass"
        "httpx"
        "ffuf"
        "gowitness"
        "katana"
        "subjs"
        "subzy"
        "nuclei"
        "dnsx"
        "naabu"
        "gau"
        "waybackurls"
        "arjun"
    )
    
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_success "$tool is properly installed and accessible"
        else
            print_error "$tool could not be found in PATH"
            FAILED_TOOLS+=("$tool")
        fi
    done
    
    # Check Python tools
    if [ -d "$TOOLS_DIR/LinkFinder" ]; then
        print_success "LinkFinder is installed"
    else
        print_error "LinkFinder installation is missing"
        FAILED_TOOLS+=("LinkFinder")
    fi
    
    if [ -d "$TOOLS_DIR/Arjun" ]; then
        print_success "Arjun is installed"
    else
        print_error "Arjun installation is missing"
        FAILED_TOOLS+=("Arjun")
    fi
    
    # Check wordlists
    if [ -d "/usr/share/seclists" ]; then
        print_success "SecLists is installed"
    else
        print_error "SecLists installation is missing"
        FAILED_TOOLS+=("SecLists")
    fi
    
    # Report results
    if [ ${#FAILED_TOOLS[@]} -eq 0 ]; then
        print_success "All components verified successfully!"
    else
        print_warning "The following components have issues: ${FAILED_TOOLS[*]}"
        print_warning "You may need to run the script again or install them manually."
    fi
}

# Main execution
main() {
    echo -e "${GREEN}"
    echo "======================================================="
    echo "       ReconMaster Fix and Upgrade Script v2.0"
    echo "======================================================="
    echo -e "${NC}"
    
    # Parse arguments
    NO_BACKUP=false
    for arg in "$@"; do
        case $arg in
            --no-backup)
                NO_BACKUP=true
                shift
                ;;
        esac
    done
    
    # Create directories
    create_directories
    
    # Backup if not disabled
    if [ "$NO_BACKUP" = false ]; then
        backup_current_installation
    fi
    
    # Fix syntax in main script
    fix_syntax_warning
    
    # Install dependencies
    install_system_dependencies
    
    # Install/Update Go
    install_go
    
    # Install all tools
    install_all_go_tools
    install_python_tools
    
    # Download wordlists
    download_wordlists
    
    # Create setup scripts
    create_setup_scripts
    
    # Verify installations
    verify_installations
    
    # Save this script for future updates
    cp "$0" "$INSTALL_DIR/fix-upgrade.sh"
    chmod +x "$INSTALL_DIR/fix-upgrade.sh"
    
    echo -e "${GREEN}"
    echo "======================================================="
    echo "    ReconMaster Fix and Upgrade Applied Successfully!"
    echo "======================================================="
    echo -e "${NC}"
    echo "All tools have been installed/updated and configured."
    echo ""
    echo "To update your PATH for this session, run:"
    echo "    source /etc/profile.d/go.sh"
    echo ""
    echo "To permanently update your PATH, run:"
    echo "    reconmaster-setup"
    echo ""
    echo "To update ReconMaster tools in the future, run:"
    echo "    reconmaster-update"
    echo ""
    echo "Happy Hunting!"
}

# Run the main function
main "$@"
