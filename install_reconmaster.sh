#!/bin/bash

# Installation script for ReconMaster
# This script will install ReconMaster and all required dependencies

set -e

# Text formatting
BOLD="\e[1m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RED="\e[31m"
RESET="\e[0m"

echo -e "${BOLD}${BLUE}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                               
${RESET}${BOLD}Advanced Reconnaissance Tool - Installation Script${RESET}
"

# Check if script is running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}This script requires root privileges to install dependencies.${RESET}"
    echo -e "${YELLOW}Please run with sudo: sudo bash install_reconmaster.sh${RESET}"
    exit 1
fi

# Detect OS
echo -e "${BOLD}Detecting operating system...${RESET}"
OS="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
elif [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    OS=$DISTRIB_ID
fi

case "$OS" in
    ubuntu|debian|kali)
        echo -e "${GREEN}Detected $OS system${RESET}"
        PKG_MANAGER="apt-get"
        PKG_UPDATE="$PKG_MANAGER update"
        PKG_INSTALL="$PKG_MANAGER install -y"
        PACKAGES="python3 python3-pip git nmap wget curl build-essential libssl-dev golang chromium-driver"
        ;;
    fedora|centos|rhel)
        echo -e "${GREEN}Detected $OS system${RESET}"
        PKG_MANAGER="dnf"
        PKG_UPDATE="$PKG_MANAGER check-update -y || true"
        PKG_INSTALL="$PKG_MANAGER install -y"
        PACKAGES="python3 python3-pip git nmap wget curl golang gcc openssl-devel chromedriver"
        ;;
    arch|manjaro)
        echo -e "${GREEN}Detected $OS system${RESET}"
        PKG_MANAGER="pacman"
        PKG_UPDATE="$PKG_MANAGER -Sy"
        PKG_INSTALL="$PKG_MANAGER -S --noconfirm"
        PACKAGES="python python-pip git nmap wget curl base-devel openssl go chromium"
        ;;
    *)
        echo -e "${RED}Unsupported operating system: $OS${RESET}"
        echo -e "${YELLOW}This script supports Ubuntu, Debian, Kali, Fedora, CentOS, RHEL, Arch, and Manjaro.${RESET}"
        echo -e "${YELLOW}You'll need to install dependencies manually and then run this script with --skip-deps flag.${RESET}"
        exit 1
        ;;
esac

INSTALL_DIR="/opt/reconmaster"
GO_TOOLS_DIR="/opt/go-tools"
WORDLISTS_DIR="/opt/wordlists"
BIN_DIR="/usr/local/bin"
USER_HOME=$(eval echo ~$SUDO_USER)
LOCAL_BIN="$USER_HOME/.local/bin"

# Skip dependencies flag
SKIP_DEPS=0
for arg in "$@"; do
    if [ "$arg" == "--skip-deps" ]; then
        SKIP_DEPS=1
    fi
done

if [ $SKIP_DEPS -eq 0 ]; then
    echo -e "${BOLD}Updating package lists...${RESET}"
    $PKG_UPDATE

    echo -e "${BOLD}Installing system dependencies...${RESET}"
    $PKG_INSTALL $PACKAGES

    # Set up Go environment
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Go installation failed. Please install Go manually.${RESET}"
        exit 1
    fi

    # Create Go directory structure
    mkdir -p $GO_TOOLS_DIR
    mkdir -p $GO_TOOLS_DIR/bin
    chown -R $SUDO_USER:$SUDO_USER $GO_TOOLS_DIR

    # Set Go environment variables for the installation
    export GOPATH=$GO_TOOLS_DIR
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
fi

# Create installation directories
mkdir -p $INSTALL_DIR
mkdir -p $WORDLISTS_DIR
mkdir -p $LOCAL_BIN

# Create wordlists directory and download some basic wordlists
echo -e "${BOLD}Downloading wordlists...${RESET}"
mkdir -p $WORDLISTS_DIR/subdomains
mkdir -p $WORDLISTS_DIR/directories
mkdir -p $WORDLISTS_DIR/parameters

# Download basic wordlists
echo -e "${BOLD}Downloading subdomain wordlist...${RESET}"
wget -q -O $WORDLISTS_DIR/subdomains/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
echo -e "${BOLD}Downloading directory wordlist...${RESET}"
wget -q -O $WORDLISTS_DIR/directories/directory-list.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
echo -e "${BOLD}Downloading parameter wordlist...${RESET}"
wget -q -O $WORDLISTS_DIR/parameters/parameters.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt

# Install Go tools if not skipping dependencies
if [ $SKIP_DEPS -eq 0 ]; then
    echo -e "${BOLD}Installing Go-based reconnaissance tools...${RESET}"

    # Install subfinder
    echo -e "${BOLD}Installing subfinder...${RESET}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    # Install assetfinder
    echo -e "${BOLD}Installing assetfinder...${RESET}"
    go install -v github.com/tomnomnom/assetfinder@latest

    # Install httpx
    echo -e "${BOLD}Installing httpx...${RESET}"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

    # Install ffuf
    echo -e "${BOLD}Installing ffuf...${RESET}"
    go install -v github.com/ffuf/ffuf@latest

    # Install amass
    echo -e "${BOLD}Installing amass...${RESET}"
    go install -v github.com/owasp-amass/amass/v3/...@latest

    # Install gowitness
    echo -e "${BOLD}Installing gowitness...${RESET}"
    go install -v github.com/sensepost/gowitness@latest

    # Install katana
    echo -e "${BOLD}Installing katana...${RESET}"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest

    # Install arjun
    echo -e "${BOLD}Installing arjun...${RESET}"
    pip3 install --upgrade arjun

    # Install socialhunter
    echo -e "${BOLD}Installing socialhunter...${RESET}"
    go install -v github.com/utkusen/socialhunter@latest

    # Copy Go tools to bin directory
    cp $GO_TOOLS_DIR/bin/* $BIN_DIR/ 2>/dev/null || true
fi

# Create reconmaster directories
mkdir -p $INSTALL_DIR/wordlists
mkdir -p $INSTALL_DIR/config

# Create default configuration file
echo -e "${BOLD}Creating default configuration file...${RESET}"
cat > $INSTALL_DIR/config/reconmaster.conf << EOF
[tools]
subfinder = subfinder
assetfinder = assetfinder
amass = amass
ffuf = ffuf
httpx = httpx
gowitness = gowitness
katana = katana
arjun = arjun
nmap = nmap
socialhunter = socialhunter

[wordlists]
subdomains = $WORDLISTS_DIR/subdomains/subdomains.txt
directories = $WORDLISTS_DIR/directories/directory-list.txt
parameters = $WORDLISTS_DIR/parameters/parameters.txt

[scan]
ports = 80,443,8080,8443,21,22,25,53,110,123,143,389,445,587,3306,3389,5432,6379,9000,9090,9200
threads = 10
timeout = 30
retries = 3
delay = 0.5
max_rate = 100
EOF

# Create basic wordlists
echo -e "${BOLD}Creating minimal built-in wordlists...${RESET}"
mkdir -p $INSTALL_DIR/wordlists

# Minimal subdomain wordlist
cat > $INSTALL_DIR/wordlists/subdomains.txt << EOF
www
mail
remote
blog
webmail
server
ns1
ns2
smtp
secure
vpn
m
shop
ftp
mail2
test
portal
dns
ns
ww1
host
support
dev
web
bbs
ww42
mx
email
cloud
1
mail1
2
forum
owa
www2
gw
admin
store
mx1
cdn
api
exchange
app
gov
2tty
vps
govyty
hgfgdf
news
1rer
lkjkui
server1
ups
sdfsdf
mysql
FTP
EOF

# Minimal directory wordlist
cat > $INSTALL_DIR/wordlists/directory-list.txt << EOF
admin
wp-admin
login
wp-content
css
js
images
img
uploads
api
static
assets
download
media
wp-includes
admin.php
wp-login.php
wp-login
administrator
index.php
index.html
robots.txt
sitemap.xml
.git
.svn
.htaccess
config
backup
db
database
log
logs
temp
test
old
dev
development
staging
beta
docs
files
upload
EOF

# Minimal parameters wordlist
cat > $INSTALL_DIR/wordlists/parameters.txt << EOF
id
page
file
search
key
email
token
user
username
password
query
url
ref
redirect
data
format
view
code
type
dir
path
sort
q
limit
offset
year
month
day
lang
language
name
EOF

# Create the ReconMaster Python script
echo -e "${BOLD}Setting up ReconMaster script...${RESET}"
cat > $INSTALL_DIR/reconmaster.py < paste.txt

# Make the script executable
chmod +x $INSTALL_DIR/reconmaster.py

# Create launcher script
cat > $BIN_DIR/reconmaster << EOF
#!/bin/bash
python3 $INSTALL_DIR/reconmaster.py "\$@"
EOF

# Make launcher executable
chmod +x $BIN_DIR/reconmaster

# Add a symbolic link to the user's bin directory
ln -sf $BIN_DIR/reconmaster $LOCAL_BIN/reconmaster 2>/dev/null || true

# Set proper permissions
chown -R root:root $INSTALL_DIR
chown -R root:root $WORDLISTS_DIR

# Verify installation
echo -e "${BOLD}Verifying installation...${RESET}"
if command -v reconmaster &> /dev/null; then
    echo -e "${GREEN}ReconMaster has been successfully installed!${RESET}"
    echo -e "${BOLD}You can now run it using:${RESET} reconmaster <domain>"
    echo -e "${BOLD}For help with options:${RESET} reconmaster -h"
else
    echo -e "${RED}Installation verification failed.${RESET}"
    echo -e "${YELLOW}You may need to add $BIN_DIR to your PATH or restart your terminal.${RESET}"
    echo -e "${YELLOW}You can also run ReconMaster directly: python3 $INSTALL_DIR/reconmaster.py${RESET}"
fi

echo -e "${BOLD}${GREEN}Installation completed!${RESET}"
echo -e "${BLUE}============================================${RESET}"
echo -e "${BOLD}ReconMaster is installed in:${RESET} $INSTALL_DIR"
echo -e "${BOLD}Wordlists are located in:${RESET} $WORDLISTS_DIR"
echo -e "${BOLD}Configuration file:${RESET} $INSTALL_DIR/config/reconmaster.conf"
echo -e "${BLUE}============================================${RESET}"
echo -e "To begin a scan: ${BOLD}reconmaster example.com${RESET}"
echo -e "For more options: ${BOLD}reconmaster -h${RESET}"
