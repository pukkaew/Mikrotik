#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script (Fixed)
# Version: 2.3
# Compatible with: Ubuntu 22.04 LTS
# Description: Complete VPN-based Hotspot Management Solution
# =============================================================================

set -e  # Exit on any error

# =============================================================================
# GLOBAL VARIABLES AND CONFIGURATION
# =============================================================================

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
SYSTEM_DIR="/opt/mikrotik-vpn"
LOG_DIR="/var/log/mikrotik-vpn"
BACKUP_DIR="/opt/mikrotik-vpn/backups"
SCRIPT_DIR="/opt/mikrotik-vpn/scripts"

# =============================================================================
# UTILITY FUNCTIONS (MUST BE DECLARED FIRST)
# =============================================================================

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}[ERROR]${NC} Please run this script as root (use sudo)"
        exit 1
    fi
}

# Print functions (declared first to avoid "not found" errors)
print_header() {
    clear
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}              MikroTik VPN Management System v2.3${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Create initial directories early to avoid path issues
create_initial_directories() {
    echo "Creating system directories..."
    
    # Create all directories with proper structure
    mkdir -p "$SYSTEM_DIR"/{configs,data,logs,backups,scripts,ssl,clients}
    mkdir -p "$SYSTEM_DIR"/{app,nginx,openvpn,mongodb,redis}
    mkdir -p "$SYSTEM_DIR"/nginx/{conf.d,ssl,logs,html}
    mkdir -p "$SYSTEM_DIR"/openvpn/{server,client-configs,easy-rsa,ccd}
    mkdir -p "$SYSTEM_DIR"/mongodb/{data,logs,backups}
    mkdir -p "$SYSTEM_DIR"/redis/{data,logs}
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"/{daily,weekly,monthly}
    mkdir -p "$SCRIPT_DIR"
    
    # Create log file
    touch "$LOG_DIR/setup.log" 2>/dev/null || true
    chmod 644 "$LOG_DIR/setup.log" 2>/dev/null || true
    
    # Set proper permissions
    chown -R root:root "$SYSTEM_DIR" "$LOG_DIR" 2>/dev/null || true
    chmod -R 755 "$SYSTEM_DIR" "$LOG_DIR" 2>/dev/null || true
    chmod 700 "$SYSTEM_DIR/configs" 2>/dev/null || true
    
    echo "✓ System directories created successfully"
}

# Logging functions (declared after directories are created)
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${msg}${NC}"
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ] && [ -w "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log" 2>/dev/null || true
    fi
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}${msg}${NC}" >&2
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ] && [ -w "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log" 2>/dev/null || true
    fi
}

log_warning() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1"
    echo -e "${YELLOW}${msg}${NC}"
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ] && [ -w "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log" 2>/dev/null || true
    fi
}

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1"
    echo -e "${BLUE}${msg}${NC}"
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ] && [ -w "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log" 2>/dev/null || true
    fi
}

# =============================================================================
# SYSTEM CHECK FUNCTIONS
# =============================================================================

print_banner() {
    clear
    echo -e "${CYAN}===================================================================${NC}"
    echo -e "${CYAN}       MikroTik VPN Management System - Installer v2.3${NC}"
    echo -e "${CYAN}       Complete VPN-based Hotspot Management Solution${NC}"
    echo -e "${CYAN}===================================================================${NC}"
    echo -e "${BLUE}       Automated Installation for Ubuntu 22.04 LTS${NC}"
    echo -e "${BLUE}       Fixed Version - All Errors Resolved${NC}"
    echo -e "${CYAN}===================================================================${NC}"
    echo
}

check_system_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [ -f /etc/lsb-release ]; then
        if ! grep -q "Ubuntu" /etc/lsb-release; then
            log_warning "This installer is designed for Ubuntu. Current OS may not be fully supported."
            read -p "Continue anyway? (y/n): " continue_anyway
            if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    else
        log_warning "Cannot detect OS version. Continuing with installation..."
    fi
    
    # Check available disk space (minimum 10GB)
    if command -v df >/dev/null 2>&1; then
        available_space=$(df / | awk 'NR==2 {print $4}' 2>/dev/null || echo "0")
        required_space=$((10 * 1024 * 1024)) # 10GB in KB
        
        if [ "$available_space" -gt 0 ] && [ "$available_space" -lt "$required_space" ]; then
            log_error "Insufficient disk space. Required: 10GB, Available: $(($available_space / 1024 / 1024))GB"
            exit 1
        fi
    fi
    
    # Check available memory (minimum 2GB)
    if command -v free >/dev/null 2>&1; then
        total_mem=$(free | awk '/^Mem:/ {print $2}' 2>/dev/null || echo "0")
        required_mem=$((2 * 1024 * 1024)) # 2GB in KB
        
        if [ "$total_mem" -gt 0 ] && [ "$total_mem" -lt "$required_mem" ]; then
            log_warning "Low memory detected. Recommended: 4GB+, Available: $(($total_mem / 1024 / 1024))GB"
            read -p "Continue with low memory? (y/n): " continue_low_mem
            if [[ ! $continue_low_mem =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    # Check internet connectivity
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_warning "Internet connectivity check failed. Installation may fail."
        read -p "Continue without internet check? (y/n): " continue_no_internet
        if [[ ! $continue_no_internet =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    log "✓ System requirements check passed"
}

# Function to check if the system is properly installed
check_installation() {
    local missing_files=()
    
    # Check for critical files
    if [ ! -f "$SYSTEM_DIR/mikrotik-vpn-manager.sh" ]; then
        missing_files+=("mikrotik-vpn-manager.sh")
    fi
    
    if [ ! -f "$SYSTEM_DIR/configs/setup.env" ]; then
        missing_files+=("setup.env")
    fi
    
    if [ ! -d "$SCRIPT_DIR" ]; then
        missing_files+=("scripts directory")
    fi
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        log_warning "Installation appears incomplete. Missing: ${missing_files[*]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# CLEANUP AND CONFIGURATION FUNCTIONS
# =============================================================================

# Function to clean up incomplete installation
cleanup_incomplete_installation() {
    log "Cleaning up incomplete installation..."
    
    # Stop any running containers if Docker is available
    if command -v docker >/dev/null 2>&1; then
        # Stop containers
        if docker ps -q --filter name=mikrotik 2>/dev/null | grep -q .; then
            docker stop $(docker ps -q --filter name=mikrotik) 2>/dev/null || true
        fi
        
        # Remove containers
        if docker ps -aq --filter name=mikrotik 2>/dev/null | grep -q .; then
            docker rm $(docker ps -aq --filter name=mikrotik) 2>/dev/null || true
        fi
        
        # Remove network
        docker network rm mikrotik-vpn-net 2>/dev/null || true
    else
        log_warning "Docker not available, skipping container cleanup"
    fi
    
    # Remove systemd service if exists
    if [ -f "/etc/systemd/system/mikrotik-vpn.service" ]; then
        systemctl stop mikrotik-vpn 2>/dev/null || true
        systemctl disable mikrotik-vpn 2>/dev/null || true
        rm -f /etc/systemd/system/mikrotik-vpn.service
        systemctl daemon-reload 2>/dev/null || true
    fi
    
    # Backup existing config if present
    if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
        log "Backing up existing configuration..."
        cp "$SYSTEM_DIR/configs/setup.env" "/tmp/mikrotik-vpn-backup.env" 2>/dev/null || true
        export BACKUP_CONFIG_EXISTS=true
    fi
    
    # Remove incomplete installation but keep logs for debugging
    if [ -d "$SYSTEM_DIR" ]; then
        rm -rf "$SYSTEM_DIR" 2>/dev/null || true
    fi
    
    log "Cleanup completed"
}

# Function to restore previous configuration
restore_previous_config() {
    if [ "${BACKUP_CONFIG_EXISTS:-false}" = "true" ] && [ -f "/tmp/mikrotik-vpn-backup.env" ]; then
        log "Restoring previous configuration..."
        mkdir -p "$SYSTEM_DIR/configs"
        cp "/tmp/mikrotik-vpn-backup.env" "$SYSTEM_DIR/configs/setup.env"
        chmod 600 "$SYSTEM_DIR/configs/setup.env"
        
        # Source the configuration
        source "/tmp/mikrotik-vpn-backup.env" 2>/dev/null || true
        
        log "Previous configuration restored"
        return 0
    fi
    return 1
}

# Function to get user input with validation
get_user_input() {
    # Try to restore previous config first
    if restore_previous_config; then
        echo "Previous configuration found:"
        echo "Domain: ${DOMAIN_NAME:-not set}"
        echo "Email: ${ADMIN_EMAIL:-not set}"
        echo "SSH Port: ${SSH_PORT:-not set}"
        echo "VPN Network: ${VPN_NETWORK:-not set}"
        echo
        read -p "Use previous configuration? (y/n): " use_previous
        if [[ $use_previous =~ ^[Yy]$ ]]; then
            export DOMAIN_NAME ADMIN_EMAIL SSH_PORT TIMEZONE VPN_NETWORK
            export MONGO_ROOT_PASSWORD MONGO_APP_PASSWORD REDIS_PASSWORD
            return 0
        fi
    fi
    
    echo
    echo "==================================================================="
    echo "MikroTik VPN Management System Configuration"
    echo "==================================================================="
    
    # Domain configuration
    while true; do
        read -p "Enter your domain name (e.g., vpn.company.com or localhost): " DOMAIN_NAME
        
        # Remove leading/trailing whitespace
        DOMAIN_NAME=$(echo "$DOMAIN_NAME" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)
        
        # Check if domain is not empty
        if [ -z "$DOMAIN_NAME" ]; then
            echo "Domain name cannot be empty. Please try again."
            continue
        fi
        
        # Basic domain validation - allow localhost and IP for testing
        if [[ $DOMAIN_NAME == "localhost" ]] || \
           [[ $DOMAIN_NAME =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || \
           [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
            break
        else
            echo "Invalid domain name format. You can use:"
            echo "  - A valid domain (e.g., example.com)"
            echo "  - localhost (for testing)"
            echo "  - An IP address (for testing)"
        fi
    done
    
    # Email configuration
    while true; do
        read -p "Enter admin email address: " ADMIN_EMAIL
        
        # Remove leading/trailing whitespace
        ADMIN_EMAIL=$(echo "$ADMIN_EMAIL" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)
        
        # Check if email is not empty
        if [ -z "$ADMIN_EMAIL" ]; then
            echo "Email address cannot be empty. Please try again."
            continue
        fi
        
        # Basic email validation
        if [[ $ADMIN_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && \
           [[ ${#ADMIN_EMAIL} -le 254 ]]; then
            break
        else
            echo "Invalid email format. Please enter a valid email address."
        fi
    done
    
    # SSH port configuration
    while true; do
        read -p "Enter SSH port (default 22): " SSH_PORT
        SSH_PORT=${SSH_PORT:-22}
        
        if [[ $SSH_PORT =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
            break
        else
            echo "Invalid port number. Please enter a number between 1 and 65535."
        fi
    done
    
    # Timezone configuration
    echo
    echo "Common timezones:"
    echo "  Asia/Bangkok (Thailand)"
    echo "  Asia/Singapore (Singapore)" 
    echo "  UTC (Universal Time)"
    echo
    read -p "Enter timezone (default Asia/Bangkok): " TIMEZONE
    TIMEZONE=${TIMEZONE:-Asia/Bangkok}
    
    # VPN network configuration
    while true; do
        read -p "Enter VPN network (default 10.8.0.0/24): " VPN_NETWORK
        VPN_NETWORK=${VPN_NETWORK:-10.8.0.0/24}
        
        if [[ $VPN_NETWORK =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            break
        else
            echo "Invalid network format. Please use CIDR notation (e.g., 10.8.0.0/24)."
        fi
    done
    
    # Database passwords - generate secure random passwords
    echo
    echo "Generating secure database passwords..."
    
    # Generate secure random passwords
    MONGO_ROOT_PASSWORD="Mongo$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)"
    MONGO_APP_PASSWORD="App$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)"
    REDIS_PASSWORD="Redis$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)"
    
    echo "✓ Secure passwords generated for databases"
    
    # Summary
    echo
    echo "==================================================================="
    echo "Configuration Summary:"
    echo "==================================================================="
    echo "Domain Name: $DOMAIN_NAME"
    echo "Admin Email: $ADMIN_EMAIL"
    echo "SSH Port: $SSH_PORT"
    echo "Timezone: $TIMEZONE"
    echo "VPN Network: $VPN_NETWORK"
    echo "Database passwords: Generated securely"
    echo "==================================================================="
    echo
    
    read -p "Is this configuration correct? (y/n): " confirm_config
    if [[ ! $confirm_config =~ ^[Yy]$ ]]; then
        echo "Configuration cancelled. Please run the script again."
        exit 0
    fi
    
    # Export variables
    export DOMAIN_NAME ADMIN_EMAIL SSH_PORT TIMEZONE VPN_NETWORK
    export MONGO_ROOT_PASSWORD MONGO_APP_PASSWORD REDIS_PASSWORD
    
    log "Configuration completed. Starting installation..."
}

# =============================================================================
# PHASE 1: SYSTEM PREPARATION
# =============================================================================

phase1_system_preparation() {
    log "==================================================================="
    log "PHASE 1: SYSTEM PREPARATION"
    log "==================================================================="
    
    log "Updating system packages..."
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists
    if ! apt update; then
        log_error "Failed to update package lists. Please check your internet connection."
        exit 1
    fi
    
    # Upgrade system (optional, but recommended)
    read -p "Upgrade system packages? (recommended) (y/n): " upgrade_system
    if [[ $upgrade_system =~ ^[Yy]$ ]]; then
        apt upgrade -y || log_warning "Some packages failed to upgrade, but continuing..."
    fi
    
    log "Setting timezone to $TIMEZONE..."
    timedatectl set-timezone "$TIMEZONE" || log_warning "Failed to set timezone"
    
    log "Installing essential packages..."
    if ! apt install -y \
        curl \
        wget \
        vim \
        nano \
        htop \
        net-tools \
        dnsutils \
        iputils-ping \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        fail2ban \
        unzip \
        git \
        build-essential \
        jq \
        cron \
        logrotate \
        rsync \
        openssl; then
        log_error "Failed to install essential packages"
        exit 1
    fi
    
    # Create system user for application
    if ! id "mikrotik-vpn" &>/dev/null; then
        log "Creating mikrotik-vpn system user..."
        if ! useradd -r -m -s /bin/bash -d /home/mikrotik-vpn mikrotik-vpn; then
            log_error "Failed to create system user"
            exit 1
        fi
    else
        log "System user mikrotik-vpn already exists"
    fi
    
    log "Setting up system optimizations..."
    create_system_optimizations
    
    log "Phase 1 completed successfully!"
}

create_system_optimizations() {
    # System limits for performance
    cat << 'EOF' > /etc/security/limits.d/mikrotik-vpn.conf
mikrotik-vpn soft nofile 65536
mikrotik-vpn hard nofile 65536
mikrotik-vpn soft nproc 32768
mikrotik-vpn hard nproc 32768
* soft nofile 65536
* hard nofile 65536
EOF

    # Kernel optimizations for networking and VPN
    cat << 'EOF' > /etc/sysctl.d/99-mikrotik-vpn.conf
# Network Performance Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000

# VPN and IP forwarding
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Security hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Memory management
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
EOF

    sysctl -p /etc/sysctl.d/99-mikrotik-vpn.conf || log_warning "Failed to apply sysctl settings"
}

# =============================================================================
# PHASE 2: DOCKER INSTALLATION
# =============================================================================

phase2_docker_installation() {
    log "==================================================================="
    log "PHASE 2: DOCKER INSTALLATION"
    log "==================================================================="
    
    # Check if Docker is already installed
    if command -v docker >/dev/null 2>&1; then
        DOCKER_VERSION=$(docker --version)
        log "Docker is already installed: $DOCKER_VERSION"
        
        # Check if Docker daemon is running
        if docker info >/dev/null 2>&1; then
            log "Docker daemon is running"
        else
            log "Starting Docker daemon..."
            systemctl start docker || {
                log_error "Failed to start Docker daemon"
                exit 1
            }
        fi
    else
        log "Installing Docker..."
        install_docker
    fi
    
    # Configure Docker daemon
    create_docker_config
    
    log "Adding users to docker group..."
    if [ -n "${SUDO_USER:-}" ]; then
        usermod -aG docker "$SUDO_USER" || log_warning "Failed to add $SUDO_USER to docker group"
    fi
    usermod -aG docker mikrotik-vpn || log_warning "Failed to add mikrotik-vpn to docker group"
    
    log "Ensuring Docker is running..."
    systemctl enable docker
    if ! systemctl is-active --quiet docker; then
        systemctl start docker || {
            log_error "Failed to start Docker"
            exit 1
        }
    fi
    
    # Wait for Docker to be ready
    log "Waiting for Docker to be ready..."
    for i in {1..30}; do
        if docker info >/dev/null 2>&1; then
            break
        fi
        sleep 2
        if [ $i -eq 30 ]; then
            log_error "Docker failed to start properly"
            exit 1
        fi
    done
    
    log "Creating Docker network..."
    if ! docker network ls | grep -q mikrotik-vpn-net; then
        if ! docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16; then
            log_warning "Failed to create Docker network, will retry later"
        fi
    else
        log "Docker network mikrotik-vpn-net already exists"
    fi
    
    log "Verifying Docker installation..."
    docker --version
    docker compose version || {
        log_error "Docker Compose is not available"
        exit 1
    }
    
    log "Phase 2 completed successfully!"
}

install_docker() {
    # Remove old versions
    apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker's official GPG key
    if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; then
        log_error "Failed to add Docker GPG key"
        exit 1
    fi
    
    # Add Docker repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker Engine
    apt update
    if ! apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        log_error "Failed to install Docker"
        exit 1
    fi
}

create_docker_config() {
    cat << 'EOF' > /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  },
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "live-restore": true
}
EOF

    systemctl restart docker || log_warning "Failed to restart Docker with new config"
}

# =============================================================================
# PHASE 3: VPN SERVER SETUP
# =============================================================================

phase3_vpn_server_setup() {
    log "==================================================================="
    log "PHASE 3: VPN SERVER SETUP"
    log "==================================================================="
    
    log "Setting up OpenVPN server..."
    setup_openvpn_server
    
    log "Phase 3 completed successfully!"
}

setup_openvpn_server() {
    # Ensure OpenVPN directories exist
    mkdir -p "$SYSTEM_DIR/openvpn"/{server,client-configs,easy-rsa,ccd}
    
    log "Installing OpenVPN..."
    apt install -y openvpn || {
        log_error "Failed to install OpenVPN"
        exit 1
    }
    
    log "Downloading and setting up Easy-RSA..."
    cd "$SYSTEM_DIR/openvpn" || exit 1
    
    # Download Easy-RSA
    if [ ! -f "EasyRSA-3.1.0.tgz" ]; then
        if ! wget -q https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz; then
            log_error "Failed to download Easy-RSA"
            exit 1
        fi
    fi
    
    tar xzf EasyRSA-3.1.0.tgz
    rm -rf easy-rsa 2>/dev/null || true
    mv EasyRSA-3.1.0 easy-rsa
    rm -f EasyRSA-3.1.0.tgz
    
    # Setup Easy-RSA configuration
    cd easy-rsa || exit 1
    cat << EOF > vars
set_var EASYRSA_REQ_COUNTRY    "TH"
set_var EASYRSA_REQ_PROVINCE   "Bangkok"
set_var EASYRSA_REQ_CITY       "Bangkok"
set_var EASYRSA_REQ_ORG        "MikroTik VPN System"
set_var EASYRSA_REQ_EMAIL      "$ADMIN_EMAIL"
set_var EASYRSA_REQ_OU         "VPN Management"
set_var EASYRSA_ALGO           "rsa"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_DIGEST         "sha256"
EOF
    
    # Initialize PKI
    ./easyrsa init-pki
    echo "MikroTik-VPN-CA" | ./easyrsa build-ca nopass
    
    # Generate server certificate
    ./easyrsa gen-req vpn-server nopass
    ./easyrsa sign-req server vpn-server
    
    # Generate Diffie-Hellman parameters
    ./easyrsa gen-dh
    
    # Generate HMAC signature
    openvpn --genkey secret ta.key
    
    # Create OpenVPN server configuration
    VPN_SERVER_IP=$(echo "$VPN_NETWORK" | cut -d'/' -f1 | sed 's/\.[0-9]*$/\.1/')
    VPN_SUBNET=$(echo "$VPN_NETWORK" | cut -d'/' -f1)
    
    cat << EOF > "$SYSTEM_DIR/openvpn/server/server.conf"
# OpenVPN Server Configuration for MikroTik Management
port 1194
proto udp
dev tun

# Certificates and keys
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/vpn-server.crt
key /etc/openvpn/easy-rsa/pki/private/vpn-server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/easy-rsa/ta.key 0

# Network configuration
server $VPN_SUBNET 255.255.255.0
push "route $VPN_SUBNET 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Client configuration
client-to-client
keepalive 10 120
cipher AES-256-GCM
auth SHA256
comp-lzo

# Security
user nobody
group nogroup
persist-key
persist-tun
duplicate-cn

# Logging
status /var/log/openvpn/status.log
log-append /var/log/openvpn/openvpn.log
verb 3

# Performance
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"

# Connection limits
max-clients 100

# Management interface
management localhost 7505

# Client configuration directory
client-config-dir /etc/openvpn/ccd
EOF
    
    # Create OpenVPN Docker Compose
    cat << 'EOF' > "$SYSTEM_DIR/docker-compose-openvpn.yml"
version: '3.8'

services:
  openvpn:
    image: kylemanna/openvpn:latest
    container_name: mikrotik-openvpn
    cap_add:
      - NET_ADMIN
    ports:
      - "1194:1194/udp"
      - "127.0.0.1:7505:7505"
    volumes:
      - $SYSTEM_DIR/openvpn:/etc/openvpn
      - $LOG_DIR:/var/log/openvpn
    restart: unless-stopped
    networks:
      - mikrotik-vpn-net

networks:
  mikrotik-vpn-net:
    external: true
EOF
    
    # Set proper ownership
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/openvpn" || true
}

# =============================================================================
# PHASE 4: DATABASE SETUP
# =============================================================================

phase4_database_setup() {
    log "==================================================================="
    log "PHASE 4: DATABASE SETUP"
    log "==================================================================="
    
    log "Setting up MongoDB..."
    setup_mongodb
    
    log "Setting up Redis..."
    setup_redis
    
    log "Phase 4 completed successfully!"
}

setup_mongodb() {
    # Create MongoDB directories
    mkdir -p "$SYSTEM_DIR/mongodb"/{data,logs,backups}
    
    # Create MongoDB initialization script
    cat << EOF > "$SYSTEM_DIR/mongodb/mongo-init.js"
// Create application database and user
db = db.getSiblingDB('mikrotik_vpn');

db.createUser({
  user: 'mikrotik_app',
  pwd: '$MONGO_APP_PASSWORD',
  roles: [
    {
      role: 'readWrite',
      db: 'mikrotik_vpn'
    }
  ]
});

// Create collections
db.createCollection('organizations');
db.createCollection('sites');
db.createCollection('devices');
db.createCollection('users');
db.createCollection('vouchers');
db.createCollection('sessions');
db.createCollection('logs');
db.createCollection('configurations');

// Create basic indexes
db.organizations.createIndex({ "domain": 1 });
db.sites.createIndex({ "organization_id": 1 });
db.devices.createIndex({ "serial_number": 1 });
db.users.createIndex({ "username": 1 });
db.vouchers.createIndex({ "code": 1 });
db.sessions.createIndex({ "user_id": 1 });
db.logs.createIndex({ "timestamp": -1 });
EOF
    
    # Create MongoDB Docker Compose
    cat << 'EOF' > "$SYSTEM_DIR/docker-compose-mongodb.yml"
version: '3.8'

services:
  mongodb:
    image: mongo:6.0
    container_name: mikrotik-mongodb
    restart: unless-stopped
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=$MONGO_ROOT_PASSWORD
      - MONGO_INITDB_DATABASE=mikrotik_vpn
    volumes:
      - $SYSTEM_DIR/mongodb/data:/data/db
      - $SYSTEM_DIR/mongodb/logs:/var/log/mongodb
      - $SYSTEM_DIR/mongodb/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    ports:
      - "127.0.0.1:27017:27017"
    command: mongod --auth --bind_ip_all
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.runCommand('ping').ok", "--quiet"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 40s

networks:
  mikrotik-vpn-net:
    external: true
EOF
}

setup_redis() {
    # Create Redis directories
    mkdir -p "$SYSTEM_DIR/redis"/{data,logs}
    
    # Create Redis configuration
    cat << 'EOF' > "$SYSTEM_DIR/redis/redis.conf"
# Redis Configuration
bind 127.0.0.1
protected-mode yes
port 6379
daemonize no
supervised no
loglevel notice
logfile /var/log/redis/redis.log
databases 16

# Persistence
save 900 1
save 300 10
save 60 10000
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /data

# Security
requirepass $REDIS_PASSWORD

# Limits
maxclients 1000
maxmemory 512mb
maxmemory-policy allkeys-lru

# Network
tcp-backlog 511
timeout 0
tcp-keepalive 300

# AOF
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
EOF
    
    # Create Redis Docker Compose
    cat << 'EOF' > "$SYSTEM_DIR/docker-compose-redis.yml"
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: mikrotik-redis
    restart: unless-stopped
    command: redis-server /usr/local/etc/redis/redis.conf
    volumes:
      - $SYSTEM_DIR/redis/data:/data
      - $SYSTEM_DIR/redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
      - $SYSTEM_DIR/redis/logs:/var/log/redis
    ports:
      - "127.0.0.1:6379:6379"
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "redis-cli", "--no-auth-warning", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 20s

networks:
  mikrotik-vpn-net:
    external: true
EOF
}

# =============================================================================
# PHASE 5: WEB SERVER SETUP
# =============================================================================

phase5_webserver_setup() {
    log "==================================================================="
    log "PHASE 5: WEB SERVER SETUP (NGINX)"
    log "==================================================================="
    
    log "Setting up Nginx reverse proxy..."
    setup_nginx
    
    log "Configuring SSL certificates..."
    setup_ssl_certificates
    
    log "Phase 5 completed successfully!"
}

setup_nginx() {
    # Create Nginx directories
    mkdir -p "$SYSTEM_DIR/nginx"/{conf.d,ssl,logs,html}
    
    # Create main Nginx configuration
    cat << 'EOF' > "$SYSTEM_DIR/nginx/nginx.conf"
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 50M;

    server_tokens off;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript;

    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Create site-specific configuration
    cat << EOF > "$SYSTEM_DIR/nginx/conf.d/mikrotik-vpn.conf"
# Default server for HTTP
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        try_files \$uri =404;
    }
    
    # Health check
    location /health {
        access_log off;
        proxy_pass http://app:3000/health;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    
    # Redirect to HTTPS if domain matches
    location / {
        if (\$host = $DOMAIN_NAME) {
            return 301 https://\$server_name\$request_uri;
        }
        return 200 "MikroTik VPN Management System - Status: Running";
        add_header Content-Type text/plain;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME localhost _;

    # SSL configuration
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Main application
    location / {
        proxy_pass http://app:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # API endpoints
    location /api/ {
        proxy_pass http://app:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Health check
    location /health {
        access_log off;
        proxy_pass http://app:3000/health;
    }

    # Static files
    location /static/ {
        alias /var/www/html/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

    # Create Docker Compose for Nginx
    cat << 'EOF' > "$SYSTEM_DIR/docker-compose-nginx.yml"
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    container_name: mikrotik-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - $SYSTEM_DIR/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - $SYSTEM_DIR/nginx/conf.d:/etc/nginx/conf.d:ro
      - $SYSTEM_DIR/nginx/ssl:/etc/nginx/ssl:ro
      - $SYSTEM_DIR/nginx/html:/var/www/html:ro
      - $SYSTEM_DIR/nginx/logs:/var/log/nginx
      - certbot_www:/var/www/certbot:ro
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    depends_on:
      - app

volumes:
  certbot_www:

networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create default index page
    mkdir -p "$SYSTEM_DIR/nginx/html"
    cat << 'EOF' > "$SYSTEM_DIR/nginx/html/index.html"
<!DOCTYPE html>
<html>
<head>
    <title>MikroTik VPN Management System</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 600px; margin: 0 auto; }
        .status { color: #28a745; font-weight: bold; }
        .info { color: #17a2b8; margin: 20px 0; }
        .warning { color: #ffc107; background: #fff3cd; padding: 10px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 MikroTik VPN Management System</h1>
        <p class="status">✅ System is Running</p>
        <div class="info">
            <p><strong>Version:</strong> 2.3</p>
            <p><strong>Status:</strong> Online</p>
            <p><strong>Access:</strong> <a href="/api">API Endpoint</a></p>
        </div>
        <div class="warning">
            <strong>Note:</strong> This is the default page. The full application interface will be available after completing the setup.
        </div>
    </div>
</body>
</html>
EOF
}

setup_ssl_certificates() {
    log "Setting up SSL certificates..."
    
    # Create self-signed certificate for immediate use
    if ! openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SYSTEM_DIR/nginx/ssl/privkey.pem" \
        -out "$SYSTEM_DIR/nginx/ssl/fullchain.pem" \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
        -addext "subjectAltName=DNS:$DOMAIN_NAME,DNS:localhost" 2>/dev/null; then
        
        # Fallback for older OpenSSL versions
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SYSTEM_DIR/nginx/ssl/privkey.pem" \
            -out "$SYSTEM_DIR/nginx/ssl/fullchain.pem" \
            -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME"
    fi
    
    chmod 600 "$SYSTEM_DIR/nginx/ssl/privkey.pem"
    chmod 644 "$SYSTEM_DIR/nginx/ssl/fullchain.pem"
    
    log "Self-signed SSL certificates created"
}

# =============================================================================
# PHASE 6: APPLICATION SETUP
# =============================================================================

phase6_application_setup() {
    log "==================================================================="
    log "PHASE 6: APPLICATION SETUP (NODE.JS)"
    log "==================================================================="
    
    log "Installing Node.js and npm..."
    install_nodejs
    
    log "Creating application structure..."
    create_application_structure
    
    log "Phase 6 completed successfully!"
}

install_nodejs() {
    # Check if Node.js is already installed
    if command -v node >/dev/null 2>&1; then
        NODE_VERSION=$(node --version)
        log "Node.js is already installed: $NODE_VERSION"
        
        # Check if version is suitable (v16+)
        if node -e "process.exit(parseInt(process.version.slice(1)) >= 16 ? 0 : 1)" 2>/dev/null; then
            log "Node.js version is suitable"
            return
        else
            log "Node.js version is too old, installing newer version..."
        fi
    fi
    
    # Install Node.js 20 LTS
    if ! curl -fsSL https://deb.nodesource.com/setup_20.x | bash -; then
        log_error "Failed to add NodeSource repository"
        exit 1
    fi
    
    if ! apt-get install -y nodejs; then
        log_error "Failed to install Node.js"
        exit 1
    fi
    
    # Verify installation
    node --version
    npm --version
}

create_application_structure() {
    # Create application directory structure
    mkdir -p "$SYSTEM_DIR/app"/{src,config,public,views,routes,models,controllers,middleware,utils}
    
    # Create package.json
    cat << 'EOF' > "$SYSTEM_DIR/app/package.json"
{
  "name": "mikrotik-vpn-management",
  "version": "2.3.0",
  "description": "MikroTik VPN-based Hotspot Management System",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "mongoose": "^7.5.0",
    "redis": "^4.6.5",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "dotenv": "^16.3.0",
    "winston": "^3.10.0",
    "socket.io": "^4.7.0",
    "express-rate-limit": "^6.7.0"
  },
  "engines": {
    "node": ">=16.0.0"
  }
}
EOF
