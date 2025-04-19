#!/bin/bash

set -e

echo "===================================================="
echo "    ReconMaster Installation Script"
echo "                                 by viphacker.100"
echo "===================================================="
echo

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install packages based on distro
install_packages() {
    echo "[+] Installing required system packages..."
    
    if command_exists apt-get; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv git wget curl nmap dig whois dnsutils libpcap-dev
    elif command_exists dnf; then
        # Fedora
        sudo dnf install -y python3 python3-pip git wget curl nmap bind-utils whois libpcap-devel
    elif command_exists pacman; then
        # Arch Linux
        sudo pacman -Sy python python-pip git wget curl nmap whois dnsutils libpcap
    elif command_exists brew; then
        # macOS
        brew install python3 git wget curl nmap whois bind libpcap
    else
        echo "[!] Unsupported package manager. Please install the following packages manually:"
        echo "    - python3, python3-pip, git, wget, curl, nmap, dig, whois, libpcap-dev"
        exit 1
    fi
    
    echo "[+] System packages installed successfully"
}

# Create directories
setup_directories() {
    echo "[+] Setting up directories..."
    
    # Create base directory
    mkdir -p ~/tools/reconmaster
    mkdir -p ~/tools/wordlists
    
    # Clone ReconMaster repository if it exists (assuming)
    echo "[+] Setting up ReconMaster..."
    cp reconmaster.py ~/tools/reconmaster/
    chmod +x ~/tools/reconmaster/reconmaster.py
    
    echo "[+] Directories set up successfully"
}

# Install Python dependencies
install_python_deps() {
    echo "[+] Setting up Python virtual environment..."
    
    cd ~/tools/reconmaster
    python3 -m venv venv
    source venv/bin/activate
    
    echo "[+] Installing Python dependencies..."
    pip install --upgrade pip
    pip install aiohttp asyncio argparse concurrent.futures logging
    
    echo "[+] Python dependencies installed successfully"
}

# Install Go
install_go() {
    if ! command_exists go; then
        echo "[+] Installing Go..."
        
        # Download and install Go
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        
        # Add Go to PATH
        echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin:~/go/bin
        
        echo "[+] Go installed successfully"
    else
        echo "[+] Go is already installed, skipping..."
    fi
}

# Install Go tools
install_go_tools() {
    echo "[+] Installing Go tools..."
    
    # Make sure Go is in PATH
    export PATH=$PATH:/usr/local/go/bin:~/go/bin
    
    # Install subfinder
    if ! command_exists subfinder; then
        echo "[+] Installing subfinder..."
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    fi
    
    # Install assetfinder
    if ! command_exists assetfinder; then
        echo "[+] Installing assetfinder..."
        go install -v github.com/tomnomnom/assetfinder@latest
    fi
    
    # Install httpx
    if ! command_exists httpx; then
        echo "[+] Installing httpx..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi
    
    # Install ffuf
    if ! command_exists ffuf; then
        echo "[+] Installing ffuf..."
        go install -v github.com/ffuf/ffuf@latest
    fi
    
    # Install katana
    if ! command_exists katana; then
        echo "[+] Installing katana..."
        go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    fi
    
    # Install gowitness
    if ! command_exists gowitness; then
        echo "[+] Installing gowitness..."
        go install -v github.com/sensepost/gowitness@latest
    fi
    
    # Install subzy
    if ! command_exists subzy; then
        echo "[+] Installing subzy..."
        go install -v github.com/LukaSikic/subzy@latest
    fi
    
    echo "[+] Go tools installed successfully"
}

# Install Arjun
install_arjun() {
    echo "[+] Installing Arjun..."
    pip install arjun
    echo "[+] Arjun installed successfully"
}

# Download and set up LinkFinder
setup_linkfinder() {
    echo "[+] Setting up LinkFinder..."
    
    cd ~/tools
    git clone https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder
    pip install -r requirements.txt
    python setup.py install
    
    echo "[+] LinkFinder set up successfully"
}

# Download and set up Amass
setup_amass() {
    echo "[+] Setting up Amass..."
    
    if ! command_exists amass; then
        go install -v github.com/OWASP/Amass/v3/...@latest
    fi
    
    echo "[+] Amass set up successfully"
}

# Download wordlists
download_wordlists() {
    echo "[+] Downloading wordlists..."
    
    cd ~/tools/wordlists
    
    # Download n0kovo subdomain wordlist
    if [ ! -d "n0kovo_subdomains" ]; then
        echo "[+] Downloading n0kovo subdomains wordlist..."
        mkdir -p n0kovo_subdomains/fuzz
        wget https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains.txt -O n0kovo_subdomains/n0kovo_subdomains.txt
        
        # Get directory wordlist
        wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O n0kovo_subdomains/fuzz/directory-list.txt
    fi
    
    echo "[+] Wordlists downloaded successfully"
}

# Create launcher script
create_launcher() {
    echo "[+] Creating launcher script..."
    
    cat > ~/tools/reconmaster/reconmaster << EOL
#!/bin/bash
cd ~/tools/reconmaster
source venv/bin/activate
python reconmaster.py "\$@"
EOL
    
    chmod +x ~/tools/reconmaster/reconmaster
    sudo ln -sf ~/tools/reconmaster/reconmaster /usr/local/bin/reconmaster
    
    echo "[+] Launcher script created successfully"
}

# Update configuration paths in script
update_paths() {
    echo "[+] Updating paths in script..."
    
    # Replace hardcoded paths in the script
    sed -i "s|/path/to/n0kovo_subdomains/n0kovo_subdomains.txt|$HOME/tools/wordlists/n0kovo_subdomains/n0kovo_subdomains.txt|g" ~/tools/reconmaster/reconmaster.py
    sed -i "s|/path/to/n0kovo_subdomains/fuzz/directory-list.txt|$HOME/tools/wordlists/n0kovo_subdomains/fuzz/directory-list.txt|g" ~/tools/reconmaster/reconmaster.py
    sed -i "s|/path/to/LinkFinder/linkfinder.py|$HOME/tools/LinkFinder/linkfinder.py|g" ~/tools/reconmaster/reconmaster.py
    
    echo "[+] Paths updated successfully"
}

# Main installation function
main() {
    install_packages
    setup_directories
    install_python_deps
    install_go
    install_go_tools
    install_arjun
    setup_linkfinder
    setup_amass
    download_wordlists
    create_launcher
    update_paths
    
    echo
    echo "=============================================="
    echo "     ReconMaster Installation Complete!"
    echo "=============================================="
    echo
    echo "To use ReconMaster, run: reconmaster -d example.com"
    echo "For more options, run: reconmaster -h"
    echo
    echo "Note: You may need to restart your terminal or run"
    echo "      'source ~/.bashrc' to update your PATH."
}

# Run the installation
main
