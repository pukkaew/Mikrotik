#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script
# Version: 4.2 - Docker Fix Edition
# Description: Complete installation with Docker service fix and better error handling
# Compatible with: Ubuntu 22.04/24.04 LTS
# =============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# =============================================================================
# GLOBAL VARIABLES AND CONFIGURATION
# =============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# System directories
SYSTEM_DIR="/opt/mikrotik-vpn"
LOG_DIR="/var/log/mikrotik-vpn"
BACKUP_DIR="/opt/mikrotik-vpn/backups"
SCRIPT_DIR="/opt/mikrotik-vpn/scripts"
CONFIG_DIR="/opt/mikrotik-vpn/configs"

# Log file
LOG_FILE="$LOG_DIR/installation.log"

# Temporary directory
TEMP_DIR="/tmp/mikrotik-vpn-install-$$"

# System resources
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
MONGODB_CACHE_SIZE=$((TOTAL_MEM / 4 / 1024))  # 25% of RAM in GB
REDIS_MAX_MEM=$((TOTAL_MEM / 4))  # 25% of RAM in MB

# =============================================================================
# INITIALIZATION
# =============================================================================

# Create necessary directories
mkdir -p "$LOG_DIR" "$TEMP_DIR"

# Logging functions
log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${message}${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}${message}${NC}" | tee -a "$LOG_FILE"
}

log_warning() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1"
    echo -e "${YELLOW}${message}${NC}" | tee -a "$LOG_FILE"
}

log_info() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1"
    echo -e "${BLUE}${message}${NC}" | tee -a "$LOG_FILE"
}

# Error handler
error_handler() {
    local line_number=$1
    log_error "Script failed at line $line_number"
    log_error "Last command: $BASH_COMMAND"
    cleanup_on_error
    exit 1
}

trap 'error_handler $LINENO' ERR

# Cleanup on error
cleanup_on_error() {
    log_warning "Cleaning up after error..."
    cd /
    rm -rf "$TEMP_DIR" 2>/dev/null || true
}

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Fix Docker service issues
fix_docker_service() {
    log "Fixing Docker service issues..."
    
    # Stop Docker and related services
    systemctl stop docker 2>/dev/null || true
    systemctl stop docker.socket 2>/dev/null || true
    systemctl stop containerd 2>/dev/null || true
    
    # Clean up any problematic Docker files
    rm -rf /var/lib/docker/network/files/local-kv.db 2>/dev/null || true
    
    # Remove Docker lock files if they exist
    rm -f /var/run/docker.pid 2>/dev/null || true
    rm -f /var/run/docker.sock 2>/dev/null || true
    rm -f /var/run/docker/containerd/containerd.pid 2>/dev/null || true
    
    # Ensure Docker directories exist with correct permissions
    mkdir -p /etc/docker
    mkdir -p /var/lib/docker
    
    # Check for storage driver issues
    if [[ -d /var/lib/docker/overlay2 ]]; then
        log "Cleaning up overlay2 storage..."
        systemctl stop docker 2>/dev/null || true
        rm -rf /var/lib/docker/overlay2/* 2>/dev/null || true
    fi
    
    # Fix iptables issues that might prevent Docker from starting
    log "Checking iptables modules..."
    
    # Load required kernel modules
    for module in ip_tables iptable_filter iptable_nat nf_nat nf_conntrack br_netfilter; do
        if ! lsmod | grep -q "^$module"; then
            log_info "Loading kernel module: $module"
            modprobe $module 2>/dev/null || log_warning "Could not load module $module (may not be needed)"
        fi
    done
    
    # Enable IPv4 forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    
    # Update alternatives for iptables (use legacy if needed)
    if command -v update-alternatives &> /dev/null; then
        log "Setting up iptables alternatives..."
        # Check if iptables-legacy exists
        if [[ -f /usr/sbin/iptables-legacy ]]; then
            update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
            update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
        fi
    fi
    
    # Clean up any Docker bridge issues
    ip link delete docker0 2>/dev/null || true
    
    # Check and fix containerd
    if command -v containerd &> /dev/null; then
        log "Restarting containerd..."
        systemctl restart containerd || {
            log_warning "Containerd restart failed, reinstalling..."
            apt-get install --reinstall -y containerd.io
        }
    fi
    
    # Create default Docker daemon configuration if missing
    if [[ ! -f /etc/docker/daemon.json ]]; then
        log "Creating default Docker daemon configuration..."
        cat << 'EOF' > /etc/docker/daemon.json
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
    fi
    
    # Ensure systemd knows about the changes
    systemctl daemon-reload
    
    sleep 2
}

# Diagnose Docker issues
diagnose_docker_issues() {
    log "Diagnosing Docker issues..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        return 1
    fi
    
    # Check systemd service file
    if [[ ! -f /lib/systemd/system/docker.service ]]; then
        log_error "Docker service file is missing"
        return 1
    fi
    
    # Check for common error patterns in journal
    local docker_errors=$(journalctl -u docker.service --no-pager -n 50 2>/dev/null)
    
    if echo "$docker_errors" | grep -q "failed to start daemon"; then
        log_error "Docker daemon failed to start"
        
        # Check for storage driver issues
        if echo "$docker_errors" | grep -q "storage-driver"; then
            log_warning "Storage driver issue detected"
            rm -rf /var/lib/docker/* 2>/dev/null || true
        fi
        
        # Check for network issues
        if echo "$docker_errors" | grep -q "bridge"; then
            log_warning "Network bridge issue detected"
            ip link delete docker0 2>/dev/null || true
        fi
    fi
    
    # Check for socket issues
    if echo "$docker_errors" | grep -q "docker.sock"; then
        log_warning "Docker socket issue detected"
        rm -f /var/run/docker.sock 2>/dev/null || true
    fi
    
    # Check for containerd issues
    if echo "$docker_errors" | grep -q "containerd"; then
        log_warning "Containerd issue detected"
        systemctl restart containerd 2>/dev/null || true
    fi
    
    return 0
}

# Create or check docker network
create_docker_network() {
    if ! docker network ls --format '{{.Name}}' | grep -q "^mikrotik-vpn-net$"; then
        log "Creating Docker network..."
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
    else
        log "Docker network already exists"
    fi
}

# Print header
print_header() {
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║        MikroTik VPN Management System - Installation v4.2                 ║
║                                                                           ║
║                    Complete All-in-One Installation Script                ║
║                            Docker Fix Edition                             ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo
}

# =============================================================================
# PHASE 0: SYSTEM DETECTION AND PREPARATION
# =============================================================================

phase0_system_detection() {
    log "==================================================================="
    log "PHASE 0: SYSTEM DETECTION AND PREPARATION"
    log "==================================================================="
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS version"
        exit 1
    fi
    
    log "Detected OS: $OS $VER"
    
    # Check Ubuntu version
    if [[ ! "$OS" =~ "Ubuntu" ]] || [[ ! "$VER" =~ ^(22.04|24.04)$ ]]; then
        log_error "This script requires Ubuntu 22.04 or 24.04 LTS"
        exit 1
    fi
    
    # Check system resources
    CPU_CORES=$(nproc)
    TOTAL_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    log "System Resources:"
    log "  CPU Cores: $CPU_CORES"
    log "  Total Memory: ${TOTAL_MEM}MB"
    log "  Available Disk: ${TOTAL_DISK}GB"
    log "  MongoDB Cache Size: ${MONGODB_CACHE_SIZE}GB"
    log "  Redis Max Memory: ${REDIS_MAX_MEM}MB"
    
    # Check minimum requirements
    if [[ $TOTAL_MEM -lt 2048 ]]; then
        log_warning "System has less than 2GB RAM. Performance may be affected."
    fi
    
    if [[ $TOTAL_DISK -lt 20 ]]; then
        log_error "Insufficient disk space. At least 20GB required."
        exit 1
    fi
    
    # Check if system is already installed
    if [[ -d "$SYSTEM_DIR" ]]; then
        log_warning "Existing installation detected at $SYSTEM_DIR"
        echo
        echo "What would you like to do?"
        echo "1. Complete fresh installation (remove existing)"
        echo "2. Fix/repair existing installation"
        echo "3. Exit"
        echo
        read -p "Enter choice (1-3): " install_choice
        
        case $install_choice in
            1)
                log "Backing up existing configuration..."
                backup_existing_installation
                log "Removing existing installation..."
                stop_all_services
                rm -rf "$SYSTEM_DIR"
                ;;
            2)
                log "Proceeding with repair mode..."
                REPAIR_MODE=true
                ;;
            3)
                log "Installation cancelled by user"
                exit 0
                ;;
            *)
                log_error "Invalid choice"
                exit 1
                ;;
        esac
    fi
    
    log "Phase 0 completed successfully!"
}

# Backup existing installation
backup_existing_installation() {
    local backup_name="backup-$(date +%Y%m%d_%H%M%S)"
    local backup_path="/root/mikrotik-vpn-backups/$backup_name"
    
    mkdir -p "$backup_path"
    
    if [[ -f "$CONFIG_DIR/setup.env" ]]; then
        cp -r "$CONFIG_DIR" "$backup_path/" 2>/dev/null || true
        log "Configuration backed up to: $backup_path"
    fi
}

# Stop all services
stop_all_services() {
    log "Stopping all existing services..."
    
    # Stop systemd service
    systemctl stop mikrotik-vpn 2>/dev/null || true
    systemctl disable mikrotik-vpn 2>/dev/null || true
    
    # Stop Docker containers
    if command -v docker &> /dev/null; then
        cd "$SYSTEM_DIR" 2>/dev/null || true
        docker compose down 2>/dev/null || true
        docker ps -a | grep mikrotik | awk '{print $1}' | xargs -r docker rm -f 2>/dev/null || true
    fi
}

# =============================================================================
# PHASE 1: USER CONFIGURATION
# =============================================================================

phase1_configuration() {
    log "==================================================================="
    log "PHASE 1: SYSTEM CONFIGURATION"
    log "==================================================================="
    
    # Check for existing configuration
    if [[ -f "$CONFIG_DIR/setup.env" ]] && [[ "${REPAIR_MODE:-false}" == "true" ]]; then
        log "Loading existing configuration..."
        source "$CONFIG_DIR/setup.env"
        
        echo
        echo "Current Configuration:"
        echo "━━━━━━━━━━━━━━━━━━━━━"
        echo "Domain: $DOMAIN_NAME"
        echo "Admin Email: $ADMIN_EMAIL"
        echo "SSH Port: $SSH_PORT"
        echo "VPN Network: $VPN_NETWORK"
        echo
        
        read -p "Keep this configuration? (y/n): " keep_config
        if [[ $keep_config =~ ^[Yy]$ ]]; then
            log "Using existing configuration"
            return
        fi
    fi
    
    # Get new configuration
    echo
    echo "System Configuration"
    echo "━━━━━━━━━━━━━━━━━━"
    
    # Domain name
    while true; do
        read -p "Enter domain name (e.g., vpn.company.com): " DOMAIN_NAME
        if [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo "Invalid domain format. Please try again."
        fi
    done
    
    # Admin email
    while true; do
        read -p "Enter admin email address: " ADMIN_EMAIL
        if [[ $ADMIN_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo "Invalid email format. Please try again."
        fi
    done
    
    # SSH port
    read -p "Enter SSH port (default 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    # Other configurations
    TIMEZONE="Asia/Bangkok"
    VPN_NETWORK="10.8.0.0/24"
    
    # Generate secure passwords
    log "Generating secure passwords..."
    MONGO_ROOT_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    MONGO_APP_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    REDIS_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    JWT_SECRET=$(openssl rand -base64 32)
    SESSION_SECRET=$(openssl rand -base64 32)
    API_KEY=$(openssl rand -base64 32)
    L2TP_PSK=$(openssl rand -base64 32)
    GRAFANA_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    # Save configuration
    save_configuration
    
    # Display summary
    echo
    echo "Configuration Summary"
    echo "━━━━━━━━━━━━━━━━━━━"
    echo "Domain: $DOMAIN_NAME"
    echo "Admin Email: $ADMIN_EMAIL"
    echo "SSH Port: $SSH_PORT"
    echo "Timezone: $TIMEZONE"
    echo "VPN Network: $VPN_NETWORK"
    echo
    
    read -p "Proceed with installation? (y/n): " proceed
    if [[ ! $proceed =~ ^[Yy]$ ]]; then
        log "Installation cancelled by user"
        exit 0
    fi
    
    log "Phase 1 completed successfully!"
}

# Save configuration
save_configuration() {
    mkdir -p "$CONFIG_DIR"
    
    cat << EOF > "$CONFIG_DIR/setup.env"
# MikroTik VPN System Configuration
# Generated: $(date)

# Basic Configuration
export DOMAIN_NAME="$DOMAIN_NAME"
export ADMIN_EMAIL="$ADMIN_EMAIL"
export SSH_PORT="$SSH_PORT"
export TIMEZONE="$TIMEZONE"
export VPN_NETWORK="$VPN_NETWORK"

# Database Passwords
export MONGO_ROOT_PASSWORD="$MONGO_ROOT_PASSWORD"
export MONGO_APP_PASSWORD="$MONGO_APP_PASSWORD"
export REDIS_PASSWORD="$REDIS_PASSWORD"

# Application Secrets
export JWT_SECRET="$JWT_SECRET"
export SESSION_SECRET="$SESSION_SECRET"
export API_KEY="$API_KEY"

# VPN Configuration
export L2TP_PSK="$L2TP_PSK"

# Monitoring
export GRAFANA_PASSWORD="$GRAFANA_PASSWORD"

# System Paths
export SYSTEM_DIR="$SYSTEM_DIR"
export LOG_DIR="$LOG_DIR"
export BACKUP_DIR="$BACKUP_DIR"
export SCRIPT_DIR="$SCRIPT_DIR"
export CONFIG_DIR="$CONFIG_DIR"

# Resource Limits
export MONGODB_CACHE_SIZE="$MONGODB_CACHE_SIZE"
export REDIS_MAX_MEM="$REDIS_MAX_MEM"
EOF
    
    chmod 600 "$CONFIG_DIR/setup.env"
    
    # Create Docker Compose .env file
    mkdir -p "$SYSTEM_DIR"
    cat << EOF > "$SYSTEM_DIR/.env"
# Docker Compose Environment Variables
MONGO_ROOT_PASSWORD=$MONGO_ROOT_PASSWORD
MONGO_APP_PASSWORD=$MONGO_APP_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD
L2TP_PSK=$L2TP_PSK
DOMAIN_NAME=$DOMAIN_NAME
ADMIN_EMAIL=$ADMIN_EMAIL
GRAFANA_PASSWORD=$GRAFANA_PASSWORD
JWT_SECRET=$JWT_SECRET
SESSION_SECRET=$SESSION_SECRET
API_KEY=$API_KEY
MONGODB_CACHE_SIZE=$MONGODB_CACHE_SIZE
REDIS_MAX_MEM=$REDIS_MAX_MEM
EOF
    
    chmod 600 "$SYSTEM_DIR/.env"
}

# =============================================================================
# PHASE 2: SYSTEM PREPARATION
# =============================================================================

phase2_system_preparation() {
    log "==================================================================="
    log "PHASE 2: SYSTEM PREPARATION"
    log "==================================================================="
    
    # Update system
    log "Updating system packages..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    
    # Set timezone
    log "Setting timezone to $TIMEZONE..."
    timedatectl set-timezone "$TIMEZONE"
    
    # Install essential packages
    log "Installing essential packages..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        wget \
        vim \
        nano \
        htop \
        iotop \
        iftop \
        net-tools \
        dnsutils \
        iputils-ping \
        traceroute \
        tcpdump \
        mtr \
        nmap \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        fail2ban \
        unzip \
        zip \
        git \
        build-essential \
        python3-pip \
        python3-venv \
        tree \
        jq \
        certbot \
        python3-certbot-nginx \
        mailutils \
        cron \
        logrotate \
        rsync \
        screen \
        tmux \
        aide \
        clamav \
        clamav-daemon \
        rkhunter \
        openssl \
        openssh-server \
        openvpn \
        easy-rsa \
        whois \
        dirmngr \
        gpg-agent \
        iptables
    
    # Create system user
    log "Creating system user..."
    if ! id -u mikrotik-vpn &>/dev/null; then
        useradd -r -m -s /bin/bash -d /home/mikrotik-vpn mikrotik-vpn
        usermod -aG sudo mikrotik-vpn
    fi
    
    # Apply system optimizations
    log "Applying system optimizations..."
    apply_system_optimizations
    
    log "Phase 2 completed successfully!"
}

# Apply system optimizations
apply_system_optimizations() {
    log "Applying system optimizations..."
    
    # System limits
    cat << 'EOF' > /etc/security/limits.d/99-mikrotik-vpn.conf
# MikroTik VPN System Limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
root soft nproc 32768
root hard nproc 32768
mikrotik-vpn soft nofile 65536
mikrotik-vpn hard nofile 65536
mikrotik-vpn soft nproc 32768
mikrotik-vpn hard nproc 32768
EOF

    # Try to load kernel modules (don't fail if not available)
    log "Checking kernel modules..."
    for module in nf_conntrack nf_conntrack_ipv4 nf_conntrack_ipv6; do
        modprobe $module 2>/dev/null || log_warning "Module $module not available"
    done
    
    # Add modules to load at boot (if available)
    if [[ -d /etc/modules-load.d ]]; then
        cat << 'EOF' > /etc/modules-load.d/mikrotik-vpn.conf
# Modules required for MikroTik VPN (load if available)
nf_conntrack
nf_conntrack_ipv4
nf_conntrack_ipv6
ip_tables
iptable_nat
iptable_filter
EOF
    fi

    # Kernel parameters - only apply what's available
    log "Applying kernel parameters..."
    
    # Create main sysctl config
    cat << 'EOF' > /etc/sysctl.d/99-mikrotik-vpn.conf
# Network Performance Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000

# VPN Settings
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.forwarding = 1

# Security Hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
EOF

    # Check for BBR support
    if modprobe tcp_bbr 2>/dev/null; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-mikrotik-vpn.conf
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.d/99-mikrotik-vpn.conf
    else
        log_warning "BBR not available, using default congestion control"
    fi

    # Apply main sysctl settings
    sysctl -p /etc/sysctl.d/99-mikrotik-vpn.conf 2>/dev/null || {
        log_warning "Some sysctl settings could not be applied"
        # Apply only essential settings
        sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
        sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
    }

    # Try to apply connection tracking settings if module is loaded
    if lsmod | grep -q nf_conntrack 2>/dev/null; then
        log "Applying connection tracking settings..."
        cat << 'EOF' > /etc/sysctl.d/99-mikrotik-vpn-conntrack.conf
# Connection Tracking (optional)
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
EOF
        sysctl -p /etc/sysctl.d/99-mikrotik-vpn-conntrack.conf 2>/dev/null || \
            log_warning "Connection tracking settings not applied (not critical)"
    else
        log_info "Connection tracking not available - skipping (system will work normally)"
    fi
    
    log "System optimizations applied (some settings may be skipped based on system capabilities)"
}

# =============================================================================
# PHASE 3: DOCKER INSTALLATION
# =============================================================================

phase3_docker_installation() {
    log "==================================================================="
    log "PHASE 3: DOCKER INSTALLATION"
    log "==================================================================="
    
    # Check if we're in a container or WSL environment
    if [[ -f /.dockerenv ]] || grep -q microsoft /proc/version 2>/dev/null; then
        log_warning "Detected container or WSL environment"
        log_warning "Docker might not work properly in this environment"
    fi
    
    # Check if systemctl is working
    if ! systemctl is-system-running &>/dev/null; then
        log_warning "systemd is not running properly"
        log_warning "Attempting to start Docker manually..."
        
        # Try to start Docker daemon manually
        if command -v dockerd &> /dev/null; then
            log "Starting Docker daemon in background..."
            dockerd > /var/log/docker-manual.log 2>&1 &
            DOCKER_PID=$!
            sleep 10
            
            # Check if Docker is running
            if docker version &>/dev/null; then
                log "Docker is running (manual start)"
                return 0
            else
                log_error "Failed to start Docker manually"
                kill $DOCKER_PID 2>/dev/null || true
            fi
        fi
    fi
    
    # Check if Docker is already installed and running
    if command -v docker &> /dev/null; then
        log "Docker is already installed"
        docker --version
        
        # Check if Docker is actually running
        if docker ps &>/dev/null; then
            log "Docker is running"
            docker --version
            docker compose version
            create_docker_network
            log "Phase 3 completed successfully!"
            return 0
        else
            log "Docker is installed but not running"
            # Try to start it
            if systemctl start docker 2>/dev/null; then
                log "Docker started successfully"
                create_docker_network
                log "Phase 3 completed successfully!"
                return 0
            else
                log_warning "Cannot start Docker with systemctl, trying alternative methods..."
            fi
        fi
    else
        log "Installing Docker..."
        
        # Remove any old Docker packages
        log "Removing old Docker packages if any..."
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Add Docker GPG key
        log "Adding Docker GPG key..."
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        
        # Add Docker repository
        log "Adding Docker repository..."
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Update package index
        apt-get update
        
        # Install Docker
        log "Installing Docker packages..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            docker-ce \
            docker-ce-cli \
            containerd.io \
            docker-buildx-plugin \
            docker-compose-plugin
    fi
    
    # Configure Docker
    log "Configuring Docker..."
    
    # Docker daemon configuration
    cat << 'EOF' > /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  },
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ],
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "live-restore": true,
  "userland-proxy": false,
  "ip-forward": true,
  "iptables": true,
  "ipv6": false
}
EOF
    
    # Add users to docker group
    usermod -aG docker mikrotik-vpn
    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG docker "$SUDO_USER"
    fi
    
    # Try different methods to start Docker
    log "Attempting to start Docker service..."
    
    # Method 1: Try systemctl
    if systemctl start docker 2>/dev/null; then
        log "Docker started with systemctl"
    else
        # Method 2: Try service command
        if service docker start 2>/dev/null; then
            log "Docker started with service command"
        else
            # Method 3: Try starting dockerd directly
            log_warning "Starting Docker daemon manually..."
            
            # Kill any existing dockerd processes
            pkill -f dockerd || true
            sleep 2
            
            # Start dockerd in background
            dockerd > /var/log/docker-manual.log 2>&1 &
            DOCKER_PID=$!
            
            # Wait for Docker to start
            local count=0
            while [[ $count -lt 30 ]]; do
                if docker version &>/dev/null; then
                    log "Docker daemon started successfully (PID: $DOCKER_PID)"
                    break
                fi
                sleep 1
                count=$((count + 1))
            done
            
            if [[ $count -ge 30 ]]; then
                log_error "Docker daemon failed to start after 30 seconds"
                cat /var/log/docker-manual.log | tail -50 >> "$LOG_FILE"
                exit 1
            fi
        fi
    fi
    
    # Verify Docker is working
    log "Verifying Docker installation..."
    if docker run --rm hello-world &>/dev/null; then
        log "Docker is working correctly"
    else
        log_error "Docker test failed"
        
        # Check what's wrong
        if ! docker version &>/dev/null; then
            log_error "Docker client cannot connect to daemon"
            log_error "Trying to diagnose..."
            
            # Check if dockerd is running
            if ! pgrep -f dockerd > /dev/null; then
                log_error "Docker daemon is not running"
            else
                log_error "Docker daemon is running but not responding"
            fi
            
            # Show docker info for debugging
            docker version 2>&1 | tee -a "$LOG_FILE" || true
            
            exit 1
        fi
    fi
    
    # Create Docker network
    create_docker_network
    
    # Show versions
    docker --version
    docker compose version
    
    log "Phase 3 completed successfully!"
}

# =============================================================================
# PHASE 4: DIRECTORY STRUCTURE
# =============================================================================

phase4_directory_structure() {
    log "==================================================================="
    log "PHASE 4: CREATING DIRECTORY STRUCTURE"
    log "==================================================================="
    
    # Create all necessary directories
    local directories=(
        "$SYSTEM_DIR"
        "$CONFIG_DIR"
        "$SCRIPT_DIR"
        "$BACKUP_DIR/daily"
        "$BACKUP_DIR/weekly"
        "$BACKUP_DIR/monthly"
        "$LOG_DIR"
        "$SYSTEM_DIR/app/src"
        "$SYSTEM_DIR/app/routes"
        "$SYSTEM_DIR/app/models"
        "$SYSTEM_DIR/app/controllers"
        "$SYSTEM_DIR/app/middleware"
        "$SYSTEM_DIR/app/utils"
        "$SYSTEM_DIR/app/public"
        "$SYSTEM_DIR/app/views"
        "$SYSTEM_DIR/app/config"
        "$SYSTEM_DIR/mongodb/data"
        "$SYSTEM_DIR/mongodb/logs"
        "$SYSTEM_DIR/mongodb/backups"
        "$SYSTEM_DIR/redis/data"
        "$SYSTEM_DIR/redis/logs"
        "$SYSTEM_DIR/nginx/conf.d"
        "$SYSTEM_DIR/nginx/ssl"
        "$SYSTEM_DIR/nginx/html"
        "$SYSTEM_DIR/nginx/logs"
        "$SYSTEM_DIR/openvpn/server"
        "$SYSTEM_DIR/openvpn/client-configs"
        "$SYSTEM_DIR/openvpn/easy-rsa"
        "$SYSTEM_DIR/openvpn/ccd"
        "$SYSTEM_DIR/l2tp"
        "$SYSTEM_DIR/monitoring/prometheus/rules"
        "$SYSTEM_DIR/monitoring/grafana/provisioning/datasources"
        "$SYSTEM_DIR/monitoring/grafana/provisioning/dashboards"
        "$SYSTEM_DIR/monitoring/grafana/provisioning/notifiers"
        "$SYSTEM_DIR/monitoring/grafana/dashboards"
        "$SYSTEM_DIR/monitoring/alertmanager"
        "$SYSTEM_DIR/clients"
        "$SYSTEM_DIR/data"
        "$SYSTEM_DIR/ssl"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log "Created directory: $dir"
    done
    
    # Set ownership and permissions
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR"
    chown -R mikrotik-vpn:mikrotik-vpn "$LOG_DIR"
    chmod -R 755 "$SYSTEM_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$SYSTEM_DIR/ssl"
    
    log "Phase 4 completed successfully!"
}

# =============================================================================
# PHASE 5: NODE.JS APPLICATION
# =============================================================================

phase5_nodejs_application() {
    log "==================================================================="
    log "PHASE 5: SETTING UP NODE.JS APPLICATION"
    log "==================================================================="
    
    # Install Node.js
    log "Installing Node.js 20 LTS..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    # Install global packages
    npm install -g pm2@latest nodemon
    
    # Verify installation
    node --version
    npm --version
    pm2 --version
    
    # Create package.json
    cat << 'EOF' > "$SYSTEM_DIR/app/package.json"
{
  "name": "mikrotik-vpn-management",
  "version": "4.2.0",
  "description": "MikroTik VPN-based Hotspot Management System",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "lint": "eslint ."
  },
  "keywords": [
    "mikrotik",
    "vpn",
    "hotspot",
    "management"
  ],
  "author": "MikroTik VPN Team",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "express-rate-limit": "^6.10.0",
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "compression": "^1.7.4",
    "mongoose": "^7.5.0",
    "redis": "^4.6.8",
    "ioredis": "^5.3.2",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "passport": "^0.6.0",
    "passport-jwt": "^4.0.1",
    "passport-local": "^1.0.0",
    "dotenv": "^16.3.1",
    "winston": "^3.10.0",
    "morgan": "^1.10.0",
    "socket.io": "^4.7.2",
    "axios": "^1.5.0",
    "node-fetch": "^3.3.2",
    "joi": "^17.10.1",
    "moment": "^2.29.4",
    "moment-timezone": "^0.5.43",
    "nodemailer": "^6.9.4",
    "uuid": "^9.0.1",
    "multer": "^1.4.5-lts.1",
    "sharp": "^0.32.5",
    "qrcode": "^1.5.3",
    "speakeasy": "^2.0.0",
    "node-cron": "^3.0.2",
    "bull": "^4.11.3",
    "swagger-jsdoc": "^6.2.8",
    "swagger-ui-express": "^5.0.0",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "eslint": "^8.48.0",
    "jest": "^29.6.4",
    "supertest": "^6.3.3"
  },
  "engines": {
    "node": ">=20.0.0",
    "npm": ">=10.0.0"
  }
}
EOF

    # Install dependencies
    log "Installing Node.js dependencies..."
    cd "$SYSTEM_DIR/app"
    npm install
    
    # Create main server file
    create_server_js
    
    # Create route files
    create_route_files
    
    # Create model files
    create_model_files
    
    # Create middleware files
    create_middleware_files
    
    # Create utility files
    create_utility_files
    
    # Create configuration files
    create_app_config_files
    
    # Create Dockerfile
    create_app_dockerfile
    
    # Set permissions
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/app"
    
    log "Phase 5 completed successfully!"
}

# Create server.js
create_server_js() {
    cat << 'EOF' > "$SYSTEM_DIR/app/server.js"
const express = require('express');
const mongoose = require('mongoose');
const redis = require('redis');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const winston = require('winston');
const { createServer } = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '.env') });

// Initialize Express app
const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE']
    }
});

// Configure logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'mikrotik-vpn' },
    transports: [
        new winston.transports.File({ 
            filename: '/var/log/mikrotik-vpn/error.log', 
            level: 'error',
            maxsize: 10485760, // 10MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: '/var/log/mikrotik-vpn/combined.log',
            maxsize: 10485760,
            maxFiles: 5
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Global error handlers
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Database connections
let redisClient;

const connectMongoDB = async () => {
    try {
        const mongoUri = process.env.MONGODB_URI || 
            `mongodb://mikrotik_app:${process.env.MONGO_APP_PASSWORD}@mongodb:27017/mikrotik_vpn?authSource=mikrotik_vpn&authMechanism=SCRAM-SHA-256`;
        
        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        
        logger.info('MongoDB connected successfully');
        
        // Handle connection events
        mongoose.connection.on('error', (err) => {
            logger.error('MongoDB connection error:', err);
        });
        
        mongoose.connection.on('disconnected', () => {
            logger.warn('MongoDB disconnected');
        });
        
    } catch (error) {
        logger.error('MongoDB connection failed:', error);
        setTimeout(connectMongoDB, 5000);
    }
};

const connectRedis = async () => {
    try {
        redisClient = redis.createClient({
            socket: {
                host: process.env.REDIS_HOST || 'redis',
                port: process.env.REDIS_PORT || 6379,
                reconnectStrategy: (retries) => {
                    if (retries > 10) {
                        logger.error('Redis reconnection limit reached');
                        return new Error('Too many retries');
                    }
                    return Math.min(retries * 100, 3000);
                }
            },
            password: process.env.REDIS_PASSWORD
        });
        
        redisClient.on('error', (err) => {
            logger.error('Redis Client Error:', err);
        });
        
        redisClient.on('connect', () => {
            logger.info('Redis client connected');
        });
        
        redisClient.on('ready', () => {
            logger.info('Redis client ready');
        });
        
        await redisClient.connect();
        
        // Make redis client available globally
        app.locals.redis = redisClient;
        global.redisClient = redisClient;
        
    } catch (error) {
        logger.error('Redis connection failed:', error);
        setTimeout(connectRedis, 5000);
    }
};

// Middleware setup
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "wss:", "https:"],
        },
    },
}));

app.use(cors({
    origin: process.env.CORS_ORIGIN?.split(',') || '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'default-secret-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict'
    }
}));

// Static files
app.use('/static', express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: true
}));

// API Documentation
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'MikroTik VPN Management API',
            version: '4.2.0',
            description: 'Comprehensive API for MikroTik VPN-based Hotspot Management',
        },
        servers: [
            {
                url: `http://localhost:${process.env.PORT || 3000}`,
                description: 'Development server',
            },
            {
                url: `https://${process.env.DOMAIN_NAME}`,
                description: 'Production server',
            },
        ],
    },
    apis: ['./routes/*.js'],
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// Health check endpoint
app.get('/health', async (req, res) => {
    try {
        const healthCheck = {
            status: 'OK',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            service: 'mikrotik-vpn-api',
            version: '4.2.0',
            checks: {
                mongodb: mongoose.connection.readyState === 1 ? 'healthy' : 'unhealthy',
                redis: redisClient && redisClient.isOpen ? 'healthy' : 'unhealthy',
                memory: process.memoryUsage(),
                cpu: process.cpuUsage()
            }
        };
        
        // Additional health checks
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.db.admin().ping();
        }
        
        if (redisClient && redisClient.isOpen) {
            await redisClient.ping();
        }
        
        res.status(200).json(healthCheck);
    } catch (error) {
        res.status(503).json({
            status: 'ERROR',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Metrics endpoint for Prometheus
app.get('/metrics', (req, res) => {
    const metrics = [];
    
    // Basic metrics
    metrics.push(`# HELP app_info Application information`);
    metrics.push(`# TYPE app_info gauge`);
    metrics.push(`app_info{version="4.2.0",node_version="${process.version}"} 1`);
    
    metrics.push(`# HELP app_uptime_seconds Application uptime in seconds`);
    metrics.push(`# TYPE app_uptime_seconds gauge`);
    metrics.push(`app_uptime_seconds ${process.uptime()}`);
    
    // Memory metrics
    const memUsage = process.memoryUsage();
    metrics.push(`# HELP app_memory_usage_bytes Memory usage in bytes`);
    metrics.push(`# TYPE app_memory_usage_bytes gauge`);
    metrics.push(`app_memory_usage_bytes{type="rss"} ${memUsage.rss}`);
    metrics.push(`app_memory_usage_bytes{type="heap_total"} ${memUsage.heapTotal}`);
    metrics.push(`app_memory_usage_bytes{type="heap_used"} ${memUsage.heapUsed}`);
    metrics.push(`app_memory_usage_bytes{type="external"} ${memUsage.external}`);
    
    // Connection metrics
    metrics.push(`# HELP app_connections_total Total number of connections`);
    metrics.push(`# TYPE app_connections_total gauge`);
    metrics.push(`app_connections_total ${io.engine.clientsCount || 0}`);
    
    // Database metrics
    metrics.push(`# HELP app_mongodb_connected MongoDB connection status`);
    metrics.push(`# TYPE app_mongodb_connected gauge`);
    metrics.push(`app_mongodb_connected ${mongoose.connection.readyState === 1 ? 1 : 0}`);
    
    metrics.push(`# HELP app_redis_connected Redis connection status`);
    metrics.push(`# TYPE app_redis_connected gauge`);
    metrics.push(`app_redis_connected ${redisClient && redisClient.isOpen ? 1 : 0}`);
    
    res.set('Content-Type', 'text/plain');
    res.send(metrics.join('\n'));
});

// API version endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'MikroTik VPN Management API',
        version: '4.2.0',
        status: 'operational',
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/health',
            metrics: '/metrics',
            documentation: '/api-docs',
            auth: '/api/v1/auth',
            devices: '/api/v1/devices',
            users: '/api/v1/users',
            vouchers: '/api/v1/vouchers',
            monitoring: '/api/v1/monitoring',
            admin: '/api/v1/admin'
        }
    });
});

// Load routes
const authRoutes = require('./routes/auth');
const deviceRoutes = require('./routes/devices');
const userRoutes = require('./routes/users');
const voucherRoutes = require('./routes/vouchers');
const monitoringRoutes = require('./routes/monitoring');
const adminRoutes = require('./routes/admin');

// API routes with versioning
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/devices', deviceRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/vouchers', voucherRoutes);
app.use('/api/v1/monitoring', monitoringRoutes);
app.use('/api/v1/admin', adminRoutes);

// Socket.IO for real-time features
io.on('connection', (socket) => {
    logger.info(`Socket connected: ${socket.id}`);
    
    // Join organization room
    socket.on('join:organization', (organizationId) => {
        socket.join(`org:${organizationId}`);
        logger.info(`Socket ${socket.id} joined organization ${organizationId}`);
    });
    
    // Join device room
    socket.on('join:device', (deviceId) => {
        socket.join(`device:${deviceId}`);
        logger.info(`Socket ${socket.id} joined device ${deviceId}`);
    });
    
    // Handle device status updates
    socket.on('device:status', async (data) => {
        try {
            io.to(`org:${data.organizationId}`).emit('device:status:update', data);
            logger.info(`Device status update: ${data.deviceId}`);
        } catch (error) {
            logger.error('Socket error:', error);
        }
    });
    
    // Handle disconnection
    socket.on('disconnect', () => {
        logger.info(`Socket disconnected: ${socket.id}`);
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: 'The requested resource was not found',
        path: req.originalUrl,
        timestamp: new Date().toISOString()
    });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error({
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip
    });
    
    const status = err.status || 500;
    const message = err.message || 'Internal Server Error';
    
    res.status(status).json({
        error: {
            message: process.env.NODE_ENV === 'production' ? 'Something went wrong!' : message,
            status: status,
            timestamp: new Date().toISOString()
        },
        ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
    });
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
    logger.info(`Received ${signal}, starting graceful shutdown...`);
    
    // Stop accepting new connections
    server.close(() => {
        logger.info('HTTP server closed');
    });
    
    // Close socket.io connections
    io.close(() => {
        logger.info('Socket.IO closed');
    });
    
    try {
        // Close database connections
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
        
        if (redisClient) {
            await redisClient.quit();
            logger.info('Redis connection closed');
        }
        
        logger.info('Graceful shutdown completed');
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown:', error);
        process.exit(1);
    }
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const startServer = async () => {
    try {
        // Connect to databases
        await connectMongoDB();
        await connectRedis();
        
        // Start listening
        const PORT = process.env.PORT || 3000;
        const HOST = '0.0.0.0';
        
        server.listen(PORT, HOST, () => {
            logger.info(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║          MikroTik VPN Management System v4.2                  ║
║                                                               ║
║  Server running at: http://${HOST}:${PORT}                        ║
║  Environment: ${process.env.NODE_ENV || 'development'}                               ║
║  Process ID: ${process.pid}                                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
            `);
        });
        
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Export for testing
module.exports = { app, io, server };

// Start server if not in test mode
if (process.env.NODE_ENV !== 'test') {
    startServer();
}
EOF
}

# Create route files
create_route_files() {
    local routes=("auth" "devices" "users" "vouchers" "monitoring" "admin")
    
    for route in "${routes[@]}"; do
        cat << EOF > "$SYSTEM_DIR/app/routes/$route.js"
const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');

/**
 * @swagger
 * tags:
 *   name: ${route^}
 *   description: ${route^} management endpoints
 */

/**
 * @swagger
 * /api/v1/${route}:
 *   get:
 *     summary: Get all ${route}
 *     tags: [${route^}]
 *     responses:
 *       200:
 *         description: Success
 *       500:
 *         description: Server error
 */
router.get('/', async (req, res, next) => {
    try {
        // TODO: Implement get all ${route}
        res.json({
            success: true,
            message: 'Get all ${route}',
            data: []
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /api/v1/${route}/{id}:
 *   get:
 *     summary: Get ${route} by ID
 *     tags: [${route^}]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Success
 *       404:
 *         description: Not found
 *       500:
 *         description: Server error
 */
router.get('/:id', 
    param('id').isMongoId().withMessage('Invalid ID format'),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            // TODO: Implement get ${route} by ID
            res.json({
                success: true,
                message: 'Get ${route} by ID',
                data: { id: req.params.id }
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/${route}:
 *   post:
 *     summary: Create new ${route}
 *     tags: [${route^}]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       201:
 *         description: Created
 *       400:
 *         description: Bad request
 *       500:
 *         description: Server error
 */
router.post('/', async (req, res, next) => {
    try {
        // TODO: Implement create ${route}
        res.status(201).json({
            success: true,
            message: 'Create new ${route}',
            data: req.body
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /api/v1/${route}/{id}:
 *   put:
 *     summary: Update ${route}
 *     tags: [${route^}]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Updated
 *       400:
 *         description: Bad request
 *       404:
 *         description: Not found
 *       500:
 *         description: Server error
 */
router.put('/:id',
    param('id').isMongoId().withMessage('Invalid ID format'),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            // TODO: Implement update ${route}
            res.json({
                success: true,
                message: 'Update ${route}',
                data: { id: req.params.id, ...req.body }
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/${route}/{id}:
 *   delete:
 *     summary: Delete ${route}
 *     tags: [${route^}]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Deleted
 *       404:
 *         description: Not found
 *       500:
 *         description: Server error
 */
router.delete('/:id',
    param('id').isMongoId().withMessage('Invalid ID format'),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            // TODO: Implement delete ${route}
            res.json({
                success: true,
                message: 'Delete ${route}',
                data: { id: req.params.id }
            });
        } catch (error) {
            next(error);
        }
    }
);

module.exports = router;
EOF
    done
}

# Create model files
create_model_files() {
    # Organization model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/Organization.js"
const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    domain: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true
    },
    phone: {
        type: String,
        trim: true
    },
    address: {
        street: String,
        city: String,
        state: String,
        country: String,
        postalCode: String
    },
    settings: {
        timezone: {
            type: String,
            default: 'Asia/Bangkok'
        },
        currency: {
            type: String,
            default: 'THB'
        },
        language: {
            type: String,
            default: 'th'
        }
    },
    subscription: {
        plan: {
            type: String,
            enum: ['free', 'basic', 'pro', 'enterprise'],
            default: 'free'
        },
        status: {
            type: String,
            enum: ['active', 'inactive', 'suspended'],
            default: 'active'
        },
        expiresAt: Date
    },
    limits: {
        maxDevices: {
            type: Number,
            default: 10
        },
        maxUsers: {
            type: Number,
            default: 100
        },
        maxVouchers: {
            type: Number,
            default: 1000
        }
    },
    stats: {
        totalDevices: {
            type: Number,
            default: 0
        },
        totalUsers: {
            type: Number,
            default: 0
        },
        totalVouchers: {
            type: Number,
            default: 0
        }
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Indexes
organizationSchema.index({ domain: 1 });
organizationSchema.index({ email: 1 });
organizationSchema.index({ 'subscription.status': 1 });

module.exports = mongoose.model('Organization', organizationSchema);
EOF

    # Device model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/Device.js"
const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    serialNumber: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    model: {
        type: String,
        required: true
    },
    firmwareVersion: String,
    macAddress: {
        type: String,
        required: true,
        unique: true,
        uppercase: true
    },
    ipAddress: String,
    vpnIpAddress: String,
    location: {
        name: String,
        address: String,
        coordinates: {
            lat: Number,
            lng: Number
        }
    },
    configuration: {
        hotspotName: String,
        hotspotInterface: String,
        hotspotProfile: String,
        vpnProfile: String,
        managementVlan: Number
    },
    status: {
        type: String,
        enum: ['online', 'offline', 'maintenance', 'error'],
        default: 'offline'
    },
    lastSeen: Date,
    vpnStatus: {
        connected: {
            type: Boolean,
            default: false
        },
        connectedAt: Date,
        disconnectedAt: Date,
        bytesIn: Number,
        bytesOut: Number
    },
    health: {
        cpuUsage: Number,
        memoryUsage: Number,
        diskUsage: Number,
        temperature: Number,
        uptime: Number
    },
    alerts: [{
        type: {
            type: String,
            enum: ['warning', 'error', 'critical']
        },
        message: String,
        timestamp: Date,
        resolved: {
            type: Boolean,
            default: false
        }
    }],
    tags: [String],
    notes: String,
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Indexes
deviceSchema.index({ organization: 1 });
deviceSchema.index({ serialNumber: 1 });
deviceSchema.index({ macAddress: 1 });
deviceSchema.index({ status: 1 });
deviceSchema.index({ 'vpnStatus.connected': 1 });

module.exports = mongoose.model('Device', deviceSchema);
EOF

    # User model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/User.js"
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['superadmin', 'admin', 'operator', 'viewer'],
        default: 'operator'
    },
    profile: {
        firstName: String,
        lastName: String,
        phone: String,
        avatar: String
    },
    permissions: [{
        resource: String,
        actions: [String]
    }],
    twoFactorAuth: {
        enabled: {
            type: Boolean,
            default: false
        },
        secret: String,
        backupCodes: [String]
    },
    loginHistory: [{
        timestamp: Date,
        ipAddress: String,
        userAgent: String,
        success: Boolean
    }],
    apiKeys: [{
        key: String,
        name: String,
        permissions: [String],
        lastUsed: Date,
        createdAt: Date,
        expiresAt: Date
    }],
    preferences: {
        language: {
            type: String,
            default: 'en'
        },
        timezone: {
            type: String,
            default: 'UTC'
        },
        notifications: {
            email: {
                type: Boolean,
                default: true
            },
            sms: {
                type: Boolean,
                default: false
            },
            push: {
                type: Boolean,
                default: true
            }
        }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    lastLogin: Date
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Hide sensitive fields
userSchema.methods.toJSON = function() {
    const obj = this.toObject();
    delete obj.password;
    delete obj.twoFactorAuth.secret;
    delete obj.twoFactorAuth.backupCodes;
    delete obj.verificationToken;
    delete obj.resetPasswordToken;
    delete obj.apiKeys;
    return obj;
};

// Indexes
userSchema.index({ organization: 1 });
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });

module.exports = mongoose.model('User', userSchema);
EOF

    # Voucher model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/Voucher.js"
const mongoose = require('mongoose');

const voucherSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },
    device: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Device'
    },
    code: {
        type: String,
        required: true,
        unique: true,
        uppercase: true
    },
    profile: {
        name: String,
        duration: {
            value: Number,
            unit: {
                type: String,
                enum: ['minutes', 'hours', 'days', 'weeks', 'months']
            }
        },
        bandwidth: {
            upload: Number, // in Mbps
            download: Number // in Mbps
        },
        dataLimit: Number, // in MB
        accessTime: {
            start: String, // HH:MM format
            end: String // HH:MM format
        },
        simultaneousUse: {
            type: Number,
            default: 1
        }
    },
    status: {
        type: String,
        enum: ['active', 'used', 'expired', 'suspended'],
        default: 'active'
    },
    price: {
        amount: Number,
        currency: {
            type: String,
            default: 'THB'
        }
    },
    usage: {
        activatedAt: Date,
        expiresAt: Date,
        lastUsedAt: Date,
        totalTime: Number, // in seconds
        totalData: Number, // in MB
        macAddress: String,
        ipAddress: String,
        deviceInfo: String
    },
    batch: {
        id: String,
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        createdAt: Date
    },
    qrCode: String,
    notes: String,
    tags: [String]
}, {
    timestamps: true
});

// Generate voucher code
voucherSchema.statics.generateCode = function(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < length; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
};

// Check if voucher is valid
voucherSchema.methods.isValid = function() {
    if (this.status !== 'active') return false;
    if (this.usage.expiresAt && new Date() > this.usage.expiresAt) return false;
    return true;
};

// Indexes
voucherSchema.index({ organization: 1 });
voucherSchema.index({ device: 1 });
voucherSchema.index({ code: 1 });
voucherSchema.index({ status: 1 });
voucherSchema.index({ 'batch.id': 1 });

module.exports = mongoose.model('Voucher', voucherSchema);
EOF

    # Session model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/Session.js"
const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },
    device: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Device',
        required: true
    },
    voucher: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Voucher'
    },
    user: {
        username: String,
        macAddress: String,
        ipAddress: String,
        deviceInfo: String
    },
    startTime: {
        type: Date,
        default: Date.now
    },
    endTime: Date,
    duration: Number, // in seconds
    dataUsage: {
        upload: Number, // in bytes
        download: Number, // in bytes
        total: Number // in bytes
    },
    status: {
        type: String,
        enum: ['active', 'completed', 'terminated', 'idle'],
        default: 'active'
    },
    terminationReason: String,
    quality: {
        avgLatency: Number,
        packetLoss: Number,
        jitter: Number
    }
}, {
    timestamps: true
});

// Indexes
sessionSchema.index({ organization: 1 });
sessionSchema.index({ device: 1 });
sessionSchema.index({ voucher: 1 });
sessionSchema.index({ startTime: -1 });
sessionSchema.index({ status: 1 });
sessionSchema.index({ 'user.macAddress': 1 });

module.exports = mongoose.model('Session', sessionSchema);
EOF
}

# Create middleware files
create_middleware_files() {
    # Authentication middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/auth.js"
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            throw new Error();
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ 
            _id: decoded._id, 
            isActive: true 
        }).select('-password');
        
        if (!user) {
            throw new Error();
        }
        
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: 'Access denied. Insufficient permissions.' 
            });
        }
        next();
    };
};

module.exports = { auth, authorize };
EOF

    # Rate limiting middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/rateLimiter.js"
const rateLimit = require('express-rate-limit');

const createLimiter = (options = {}) => {
    const defaults = {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: 'Too many requests from this IP, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
    };
    
    return rateLimit({ ...defaults, ...options });
};

// Different limiters for different endpoints
const loginLimiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.'
});

const apiLimiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 100
});

const strictLimiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 10
});

module.exports = {
    createLimiter,
    loginLimiter,
    apiLimiter,
    strictLimiter
};
EOF

    # Validation middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/validation.js"
const { validationResult } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array().map(err => ({
                field: err.param,
                message: err.msg,
                value: err.value
            }))
        });
    }
    
    next();
};

module.exports = { handleValidationErrors };
EOF
}

# Create utility files
create_utility_files() {
    # Logger utility
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/logger.js"
const winston = require('winston');
const path = require('path');

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'mikrotik-vpn' },
    transports: [
        new winston.transports.File({ 
            filename: path.join('/var/log/mikrotik-vpn', 'error.log'),
            level: 'error',
            maxsize: 10485760,
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: path.join('/var/log/mikrotik-vpn', 'combined.log'),
            maxsize: 10485760,
            maxFiles: 5
        })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

module.exports = logger;
EOF

    # Email utility
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/email.js"
const nodemailer = require('nodemailer');
const logger = require('./logger');

class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransporter({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: process.env.SMTP_PORT || 587,
            secure: false,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });
        
        this.verifyConnection();
    }
    
    async verifyConnection() {
        try {
            await this.transporter.verify();
            logger.info('Email service ready');
        } catch (error) {
            logger.error('Email service error:', error);
        }
    }
    
    async sendEmail({ to, subject, html, text }) {
        try {
            const info = await this.transporter.sendMail({
                from: process.env.FROM_EMAIL || '"MikroTik VPN" <noreply@example.com>',
                to,
                subject,
                text,
                html
            });
            
            logger.info(`Email sent: ${info.messageId}`);
            return info;
        } catch (error) {
            logger.error('Email send error:', error);
            throw error;
        }
    }
    
    async sendWelcomeEmail(user) {
        const subject = 'Welcome to MikroTik VPN Management System';
        const html = `
            <h1>Welcome ${user.profile.firstName}!</h1>
            <p>Your account has been created successfully.</p>
            <p>Username: ${user.username}</p>
            <p>Please verify your email by clicking the link below:</p>
            <a href="${process.env.APP_URL}/verify/${user.verificationToken}">Verify Email</a>
        `;
        
        return this.sendEmail({
            to: user.email,
            subject,
            html
        });
    }
}

module.exports = new EmailService();
EOF

    # QR Code utility
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/qrcode.js"
const QRCode = require('qrcode');
const logger = require('./logger');

class QRCodeService {
    async generateVoucherQR(voucher) {
        try {
            const data = {
                code: voucher.code,
                url: `${process.env.APP_URL}/voucher/${voucher.code}`
            };
            
            const qrCodeDataURL = await QRCode.toDataURL(JSON.stringify(data), {
                errorCorrectionLevel: 'M',
                type: 'image/png',
                width: 300,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#FFFFFF'
                }
            });
            
            return qrCodeDataURL;
        } catch (error) {
            logger.error('QR Code generation error:', error);
            throw error;
        }
    }
    
    async generateDeviceQR(device) {
        try {
            const data = {
                id: device._id,
                serial: device.serialNumber,
                vpn: device.vpnIpAddress
            };
            
            return await QRCode.toDataURL(JSON.stringify(data));
        } catch (error) {
            logger.error('QR Code generation error:', error);
            throw error;
        }
    }
}

module.exports = new QRCodeService();
EOF
}

# Create application config files
create_app_config_files() {
    # Application .env file
    cat << EOF > "$SYSTEM_DIR/app/.env"
# Application Configuration
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# URLs
APP_URL=https://$DOMAIN_NAME
CORS_ORIGIN=https://$DOMAIN_NAME,https://admin.$DOMAIN_NAME

# Database Configuration
MONGODB_URI=mongodb://mikrotik_app:$MONGO_APP_PASSWORD@mongodb:27017/mikrotik_vpn?authSource=mikrotik_vpn&authMechanism=SCRAM-SHA-256
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=$REDIS_PASSWORD

# Security
JWT_SECRET=$JWT_SECRET
SESSION_SECRET=$SESSION_SECRET
API_KEY=$API_KEY

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=$ADMIN_EMAIL
SMTP_PASS=your-app-password
FROM_EMAIL="MikroTik VPN" <$ADMIN_EMAIL>

# VPN Configuration
VPN_NETWORK=$VPN_NETWORK
OPENVPN_HOST=$DOMAIN_NAME
OPENVPN_PORT=1194

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_URL=http://grafana:3000

# Logging
LOG_LEVEL=info
LOG_DIR=/var/log/mikrotik-vpn

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
EOF

    # PM2 ecosystem file
    cat << 'EOF' > "$SYSTEM_DIR/app/ecosystem.config.js"
module.exports = {
    apps: [{
        name: 'mikrotik-vpn-api',
        script: './server.js',
        instances: 'max',
        exec_mode: 'cluster',
        env: {
            NODE_ENV: 'production',
            PORT: 3000
        },
        error_file: '/var/log/mikrotik-vpn/pm2-error.log',
        out_file: '/var/log/mikrotik-vpn/pm2-out.log',
        log_file: '/var/log/mikrotik-vpn/pm2-combined.log',
        time: true,
        max_memory_restart: '1G',
        exp_backoff_restart_delay: 100,
        max_restarts: 10,
        min_uptime: '10s',
        watch: false,
        ignore_watch: ['node_modules', 'logs', 'public'],
        env_production: {
            NODE_ENV: 'production',
            PORT: 3000
        }
    }]
};
EOF
}

# Create Dockerfile for application
create_app_dockerfile() {
    cat << 'EOF' > "$SYSTEM_DIR/app/Dockerfile"
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Production stage
FROM node:20-alpine

# Install runtime dependencies
RUN apk add --no-cache curl bash tini

# Create app directory
WORKDIR /usr/src/app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mikrotik -u 1001

# Copy from builder
COPY --from=builder --chown=mikrotik:nodejs /usr/src/app .

# Create necessary directories
RUN mkdir -p /var/log/mikrotik-vpn && \
    chown -R mikrotik:nodejs /var/log/mikrotik-vpn

# Switch to non-root user
USER mikrotik

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start application
CMD ["node", "server.js"]
EOF
}

# =============================================================================
# PHASE 6: CONFIGURATION FILES
# =============================================================================

phase6_configuration_files() {
    log "==================================================================="
    log "PHASE 6: CREATING CONFIGURATION FILES"
    log "==================================================================="
    
    # MongoDB initialization script
    cat << EOF > "$SYSTEM_DIR/mongodb/mongo-init.js"
// Switch to admin database
db = db.getSiblingDB('admin');

// Create admin user if not exists
if (!db.getUser('admin')) {
    db.createUser({
        user: 'admin',
        pwd: '$MONGO_ROOT_PASSWORD',
        roles: ['root']
    });
}

// Switch to application database
db = db.getSiblingDB('mikrotik_vpn');

// Create application user
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

// Create collections with validation
db.createCollection('organizations', {
    validator: {
        \$jsonSchema: {
            bsonType: 'object',
            required: ['name', 'domain', 'email'],
            properties: {
                name: { bsonType: 'string' },
                domain: { bsonType: 'string' },
                email: { bsonType: 'string' }
            }
        }
    }
});

db.createCollection('devices', {
    validator: {
        \$jsonSchema: {
            bsonType: 'object',
            required: ['organization', 'name', 'serialNumber', 'macAddress'],
            properties: {
                organization: { bsonType: 'objectId' },
                name: { bsonType: 'string' },
                serialNumber: { bsonType: 'string' },
                macAddress: { bsonType: 'string' }
            }
        }
    }
});

db.createCollection('users');
db.createCollection('vouchers');
db.createCollection('sessions');
db.createCollection('logs');
db.createCollection('settings');

// Create indexes
db.organizations.createIndex({ domain: 1 }, { unique: true });
db.organizations.createIndex({ email: 1 });

db.devices.createIndex({ organization: 1 });
db.devices.createIndex({ serialNumber: 1 }, { unique: true });
db.devices.createIndex({ macAddress: 1 }, { unique: true });
db.devices.createIndex({ status: 1 });

db.users.createIndex({ organization: 1 });
db.users.createIndex({ username: 1 }, { unique: true });
db.users.createIndex({ email: 1 }, { unique: true });

db.vouchers.createIndex({ organization: 1 });
db.vouchers.createIndex({ code: 1 }, { unique: true });
db.vouchers.createIndex({ status: 1 });
db.vouchers.createIndex({ 'batch.id': 1 });

db.sessions.createIndex({ organization: 1 });
db.sessions.createIndex({ device: 1 });
db.sessions.createIndex({ startTime: -1 });
db.sessions.createIndex({ status: 1 });

db.logs.createIndex({ timestamp: -1 });
db.logs.createIndex({ level: 1 });
db.logs.createIndex({ device: 1 });

// Insert default data
db.organizations.insertOne({
    name: 'Default Organization',
    domain: '$DOMAIN_NAME',
    email: '$ADMIN_EMAIL',
    settings: {
        timezone: 'Asia/Bangkok',
        currency: 'THB',
        language: 'th'
    },
    subscription: {
        plan: 'enterprise',
        status: 'active'
    },
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date()
});

print('MongoDB initialization completed successfully');
EOF

    # Redis configuration
    cat << EOF > "$SYSTEM_DIR/redis/redis.conf"
# Redis Configuration for MikroTik VPN System

# Network
bind 0.0.0.0
protected-mode yes
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300

# General
daemonize no
supervised no
pidfile /var/run/redis_6379.pid
loglevel notice
logfile ""
databases 16

# Snapshotting
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /data

# Replication
replica-read-only yes

# Security
requirepass $REDIS_PASSWORD

# Limits
maxclients 10000
maxmemory ${REDIS_MAX_MEM}mb
maxmemory-policy allkeys-lru

# Append only mode
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# Slow log
slowlog-log-slower-than 10000
slowlog-max-len 128

# Event notification
notify-keyspace-events ""

# Advanced config
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
stream-node-max-bytes 4096
stream-node-max-entries 100
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
dynamic-hz yes
aof-rewrite-incremental-fsync yes
rdb-save-incremental-fsync yes
EOF

    # Nginx configuration
    create_nginx_configs
    
    # OpenVPN configuration
    create_openvpn_configs
    
    # Prometheus configuration
    create_prometheus_configs
    
    # Grafana configuration
    create_grafana_configs
    
    # Alertmanager configuration
    create_alertmanager_config
    
    log "Phase 6 completed successfully!"
}

# Create Nginx configurations
create_nginx_configs() {
    # Main nginx.conf
    cat << 'EOF' > "$SYSTEM_DIR/nginx/nginx.conf"
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    log_format json_combined escape=json '{'
        '"time_local":"$time_local",'
        '"remote_addr":"$remote_addr",'
        '"remote_user":"$remote_user",'
        '"request":"$request",'
        '"status":"$status",'
        '"body_bytes_sent":"$body_bytes_sent",'
        '"request_time":"$request_time",'
        '"http_referrer":"$http_referer",'
        '"http_user_agent":"$http_user_agent"'
    '}';
    
    access_log /var/log/nginx/access.log json_combined;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100;
    reset_timedout_connection on;
    client_body_timeout 10;
    client_header_timeout 10;
    send_timeout 10;
    
    # Buffers
    client_body_buffer_size 128k;
    client_max_body_size 10m;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 16k;
    output_buffers 1 32k;
    postpone_output 1460;
    
    # Hash tables
    types_hash_max_size 2048;
    server_names_hash_bucket_size 128;
    
    # Hide version
    server_tokens off;
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml application/atom+xml image/svg+xml;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    
    # Include site configurations
    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Site configuration
    cat << EOF > "$SYSTEM_DIR/nginx/conf.d/mikrotik-vpn.conf"
# Upstream configuration
upstream app_backend {
    least_conn;
    server app:3000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME admin.$DOMAIN_NAME;
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        try_files \$uri =404;
    }
    
    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME;
    
    # SSL configuration
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Root location
    location / {
        limit_req zone=general burst=20 nodelay;
        
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # API endpoints
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
        
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }
    
    # WebSocket support
    location /socket.io/ {
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket specific
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static files
    location /static/ {
        alias /var/www/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Health check
    location /health {
        access_log off;
        proxy_pass http://app_backend/health;
    }
    
    # Monitoring endpoints (internal only)
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        allow 172.20.0.0/16;
        deny all;
    }
}

# Admin panel
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name admin.$DOMAIN_NAME;
    
    # SSL configuration (same as main site)
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Enhanced security for admin
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    
    # Admin interface
    location / {
        limit_req zone=general burst=10 nodelay;
        
        # IP whitelist (optional)
        # allow 192.168.1.0/24;
        # deny all;
        
        proxy_pass http://app_backend/admin;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Admin API
    location /api/ {
        limit_req zone=api burst=30 nodelay;
        
        proxy_pass http://app_backend/api/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Monitoring access (Grafana)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name monitor.$DOMAIN_NAME;
    
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    
    location / {
        proxy_pass http://grafana:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

    # Create self-signed SSL certificate with proper links
    log "Creating self-signed SSL certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SYSTEM_DIR/nginx/ssl/privkey.pem" \
        -out "$SYSTEM_DIR/nginx/ssl/fullchain.pem" \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
        -addext "subjectAltName=DNS:$DOMAIN_NAME,DNS:admin.$DOMAIN_NAME,DNS:monitor.$DOMAIN_NAME" \
        2>/dev/null
}

# Create OpenVPN configurations
create_openvpn_configs() {
    # Server configuration
    cat << EOF > "$SYSTEM_DIR/openvpn/server/server.conf"
# OpenVPN Server Configuration
port 1194
proto udp
dev tun

# Certificates and keys
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/easy-rsa/ta.key 0

# Network configuration
server ${VPN_NETWORK%.0/24} 255.255.255.0
push "route ${VPN_NETWORK%.0/24} 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Client configuration
client-config-dir /etc/openvpn/ccd
client-to-client
duplicate-cn
keepalive 10 120

# Encryption
cipher AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

# Compression
comp-lzo

# Security
user nobody
group nogroup
persist-key
persist-tun

# Logging
status /var/log/openvpn-status.log 5
log-append /var/log/openvpn.log
verb 3
mute 20

# Performance
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"

# Limits
max-clients 1000

# Management interface
management localhost 7505
EOF

    # Create Easy-RSA vars
    cat << EOF > "$SYSTEM_DIR/openvpn/easy-rsa/vars"
# Easy-RSA Variables
set_var EASYRSA_REQ_COUNTRY    "TH"
set_var EASYRSA_REQ_PROVINCE   "Bangkok"
set_var EASYRSA_REQ_CITY       "Bangkok"
set_var EASYRSA_REQ_ORG        "MikroTik VPN System"
set_var EASYRSA_REQ_EMAIL      "$ADMIN_EMAIL"
set_var EASYRSA_REQ_OU         "VPN Management"
set_var EASYRSA_ALGO           "rsa"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    1825
set_var EASYRSA_DIGEST         "sha256"
EOF

    # Initialize PKI script
    cat << 'EOF' > "$SYSTEM_DIR/openvpn/init-pki.sh"
#!/bin/bash
cd /etc/openvpn

# Download and setup Easy-RSA if not exists
if [[ ! -d "easy-rsa" ]]; then
    wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz
    tar xzf EasyRSA-3.1.0.tgz
    mv EasyRSA-3.1.0/* easy-rsa/
    rm -rf EasyRSA-3.1.0*
fi

cd easy-rsa

# Copy vars file
cp /etc/openvpn/easy-rsa/vars ./vars

# Clean and init
./easyrsa clean-all 2>/dev/null || true
./easyrsa init-pki

# Build CA
echo "Building CA..."
./easyrsa --batch build-ca nopass

# Generate server certificate
echo "Generating server certificate..."
./easyrsa --batch gen-req server nopass
./easyrsa --batch sign-req server server

# Generate DH parameters
echo "Generating DH parameters..."
./easyrsa gen-dh

# Generate TLS auth key
echo "Generating TLS auth key..."
openvpn --genkey secret ta.key

echo "PKI initialization completed!"
EOF

    chmod +x "$SYSTEM_DIR/openvpn/init-pki.sh"
}

# Create Prometheus configurations
create_prometheus_configs() {
    # Prometheus configuration
    cat << 'EOF' > "$SYSTEM_DIR/monitoring/prometheus/prometheus.yml"
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'mikrotik-vpn-monitor'
    environment: 'production'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

# Load rules
rule_files:
  - '/etc/prometheus/rules/*.yml'

# Scrape configurations
scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Node Exporter
  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

  # Docker containers
  - job_name: 'docker'
    static_configs:
      - targets: ['cadvisor:8080']

  # MongoDB
  - job_name: 'mongodb'
    static_configs:
      - targets: ['mongodb-exporter:9216']

  # Redis
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  # Nginx
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  # Application
  - job_name: 'mikrotik-app'
    static_configs:
      - targets: ['app:3000']
    metrics_path: '/metrics'

  # OpenVPN
  - job_name: 'openvpn'
    static_configs:
      - targets: ['openvpn-exporter:9176']
EOF

    # Alert rules
    cat << 'EOF' > "$SYSTEM_DIR/monitoring/prometheus/rules/alerts.yml"
groups:
  - name: system_alerts
    interval: 30s
    rules:
      - alert: InstanceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} down"
          description: "{{ $labels.instance }} of job {{ $labels.job }} has been down for more than 1 minute."

      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% (current value: {{ $value }}%)"

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 85% (current value: {{ $value }}%)"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 20
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space"
          description: "Disk space is below 20% (current value: {{ $value }}%)"

  - name: service_alerts
    interval: 30s
    rules:
      - alert: MongoDBDown
        expr: mongodb_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "MongoDB is down"
          description: "MongoDB database is not responding"

      - alert: RedisDown
        expr: redis_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Redis is down"
          description: "Redis cache is not responding"

      - alert: NginxDown
        expr: nginx_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Nginx is down"
          description: "Nginx web server is not responding"

      - alert: AppDown
        expr: app_mongodb_connected == 0 or app_redis_connected == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Application database connection lost"
          description: "Application cannot connect to databases"

  - name: vpn_alerts
    interval: 30s
    rules:
      - alert: VPNHighConnections
        expr: openvpn_server_connected_clients > 900
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High VPN connections"
          description: "VPN connections approaching limit (current: {{ $value }})"

      - alert: VPNTrafficSpike
        expr: rate(openvpn_server_route_bytes_sent[5m]) > 100000000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High VPN traffic"
          description: "VPN traffic exceeds 100MB/s"
EOF
}

# Create Grafana configurations
create_grafana_configs() {
    # Datasource provisioning
    cat << 'EOF' > "$SYSTEM_DIR/monitoring/grafana/provisioning/datasources/prometheus.yml"
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
    jsonData:
      timeInterval: '15s'
EOF

    # Dashboard provisioning
    cat << 'EOF' > "$SYSTEM_DIR/monitoring/grafana/provisioning/dashboards/dashboard.yml"
apiVersion: 1

providers:
  - name: 'MikroTik VPN Dashboards'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF

    # Main dashboard
    cat << 'DASHBOARD' > "$SYSTEM_DIR/monitoring/grafana/dashboards/main-dashboard.json"
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 6,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showThresholdLabels": false,
        "showThresholdMarkers": true
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "100 - (avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
          "refId": "A"
        }
      ],
      "title": "CPU Usage",
      "type": "gauge"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 70
              },
              {
                "color": "red",
                "value": 85
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 6,
        "x": 6,
        "y": 0
      },
      "id": 2,
      "options": {
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showThresholdLabels": false,
        "showThresholdMarkers": true
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100",
          "refId": "A"
        }
      ],
      "title": "Memory Usage",
      "type": "gauge"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "tooltip": false,
              "viz": false,
              "legend": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "id": 3,
      "options": {
        "tooltip": {
          "mode": "single"
        },
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        }
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "openvpn_server_connected_clients",
          "legendFormat": "Connected Clients",
          "refId": "A"
        }
      ],
      "title": "VPN Connections",
      "type": "timeseries"
    }
  ],
  "schemaVersion": 27,
  "style": "dark",
  "tags": [
    "mikrotik",
    "vpn",
    "overview"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "MikroTik VPN System Overview",
  "uid": "mikrotik-vpn-overview",
  "version": 0
}
DASHBOARD
}

# Create Alertmanager configuration
create_alertmanager_config() {
    cat << EOF > "$SYSTEM_DIR/monitoring/alertmanager/alertmanager.yml"
global:
  resolve_timeout: 5m
  smtp_from: '$ADMIN_EMAIL'
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_auth_username: '$ADMIN_EMAIL'
  smtp_auth_password: 'your-app-password'
  smtp_require_tls: true

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical'
      continue: true
    - match:
        severity: warning
      receiver: 'warning'

receivers:
  - name: 'default'
    email_configs:
      - to: '$ADMIN_EMAIL'
        headers:
          Subject: '[MikroTik VPN] Alert: {{ .GroupLabels.alertname }}'
        html: |
          <h2>MikroTik VPN System Alert</h2>
          <p><strong>Alert:</strong> {{ .GroupLabels.alertname }}</p>
          <p><strong>Severity:</strong> {{ .CommonLabels.severity }}</p>
          <p><strong>Summary:</strong> {{ .CommonAnnotations.summary }}</p>
          <p><strong>Description:</strong> {{ .CommonAnnotations.description }}</p>
          <p><strong>Time:</strong> {{ .StartsAt.Format "2006-01-02 15:04:05" }}</p>

  - name: 'critical'
    email_configs:
      - to: '$ADMIN_EMAIL'
        headers:
          Subject: '[CRITICAL] MikroTik VPN Alert: {{ .GroupLabels.alertname }}'
        send_resolved: true

  - name: 'warning'
    email_configs:
      - to: '$ADMIN_EMAIL'
        headers:
          Subject: '[WARNING] MikroTik VPN Alert: {{ .GroupLabels.alertname }}'
        send_resolved: false

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
EOF
}

# =============================================================================
# PHASE 7: DOCKER COMPOSE
# =============================================================================

phase7_docker_compose() {
    log "==================================================================="
    log "PHASE 7: CREATING DOCKER COMPOSE CONFIGURATION"
    log "==================================================================="
    
    cat << 'EOF' > "$SYSTEM_DIR/docker-compose.yml"
services:
  # ===========================================
  # Database Services
  # ===========================================
  mongodb:
    image: mongo:7.0
    container_name: mikrotik-mongodb
    restart: unless-stopped
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}
      - MONGO_INITDB_DATABASE=mikrotik_vpn
    volumes:
      - ./mongodb/data:/data/db
      - ./mongodb/logs:/var/log/mongodb
      - ./mongodb/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    ports:
      - "127.0.0.1:27017:27017"
    command: mongod --auth --bind_ip_all --wiredTigerCacheSizeGB ${MONGODB_CACHE_SIZE}
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')", "--quiet"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 40s

  redis:
    image: redis:7-alpine
    container_name: mikrotik-redis
    restart: unless-stopped
    command: redis-server /usr/local/etc/redis/redis.conf
    volumes:
      - ./redis/data:/data
      - ./redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    ports:
      - "127.0.0.1:6379:6379"
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "redis-cli", "--pass", "${REDIS_PASSWORD}", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 20s

  # ===========================================
  # Application Service
  # ===========================================
  app:
    build: 
      context: ./app
      dockerfile: Dockerfile
    container_name: mikrotik-app
    restart: unless-stopped
    env_file:
      - ./app/.env
    environment:
      - NODE_ENV=production
      - PORT=3000
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - ./app:/usr/src/app
      - /usr/src/app/node_modules
      - ./logs:/var/log/mikrotik-vpn
    networks:
      - mikrotik-vpn-net
    depends_on:
      mongodb:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # ===========================================
  # Web Server
  # ===========================================
  nginx:
    image: nginx:alpine
    container_name: mikrotik-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/html:/var/www/html:ro
      - ./logs/nginx:/var/log/nginx
      - certbot_www:/var/www/certbot:ro
    networks:
      - mikrotik-vpn-net
    depends_on:
      app:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ===========================================
  # VPN Services
  # ===========================================
  openvpn:
    build:
      context: ./openvpn
      dockerfile: Dockerfile
    container_name: mikrotik-openvpn
    cap_add:
      - NET_ADMIN
    ports:
      - "1194:1194/udp"
      - "127.0.0.1:7505:7505"
    volumes:
      - ./openvpn:/etc/openvpn
      - ./logs:/var/log
    restart: unless-stopped
    networks:
      - mikrotik-vpn-net
    devices:
      - /dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    environment:
      - OVPN_SERVER=${VPN_NETWORK}

  l2tp-ipsec:
    image: hwdsl2/ipsec-vpn-server:latest
    container_name: mikrotik-l2tp
    cap_add:
      - NET_ADMIN
    environment:
      - VPN_IPSEC_PSK=${L2TP_PSK}
      - VPN_USER=mikrotik
      - VPN_PASSWORD=${MONGO_ROOT_PASSWORD}
      - VPN_ADDITIONAL_USERS=
      - VPN_ADDITIONAL_PASSWORDS=
    ports:
      - "500:500/udp"
      - "4500:4500/udp"
      - "1701:1701/udp"
    volumes:
      - ./l2tp:/etc/ipsec.d
      - /lib/modules:/lib/modules:ro
    restart: unless-stopped
    networks:
      - mikrotik-vpn-net
    privileged: true

  # ===========================================
  # Monitoring Stack
  # ===========================================
  prometheus:
    image: prom/prometheus:latest
    container_name: mikrotik-prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
      - '--web.enable-lifecycle'
      - '--storage.tsdb.retention.time=30d'
    volumes:
      - ./monitoring/prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    ports:
      - "127.0.0.1:9090:9090"
    networks:
      - mikrotik-vpn-net

  grafana:
    image: grafana/grafana:latest
    container_name: mikrotik-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource,grafana-worldmap-panel
      - GF_SERVER_ROOT_URL=https://monitor.${DOMAIN_NAME}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./monitoring/grafana/dashboards:/var/lib/grafana/dashboards:ro
    ports:
      - "127.0.0.1:3001:3000"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - prometheus

  alertmanager:
    image: prom/alertmanager:latest
    container_name: mikrotik-alertmanager
    restart: unless-stopped
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.external-url=http://alertmanager:9093'
    volumes:
      - ./monitoring/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - alertmanager_data:/alertmanager
    ports:
      - "127.0.0.1:9093:9093"
    networks:
      - mikrotik-vpn-net

  # ===========================================
  # Exporters for Monitoring
  # ===========================================
  node-exporter:
    image: prom/node-exporter:latest
    container_name: mikrotik-node-exporter
    restart: unless-stopped
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--path.rootfs=/rootfs'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($|/)'
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    ports:
      - "127.0.0.1:9100:9100"
    networks:
      - mikrotik-vpn-net

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: mikrotik-cadvisor
    restart: unless-stopped
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    devices:
      - /dev/kmsg
    privileged: true
    ports:
      - "127.0.0.1:8080:8080"
    networks:
      - mikrotik-vpn-net

  mongodb-exporter:
    image: percona/mongodb_exporter:0.40
    container_name: mikrotik-mongodb-exporter
    restart: unless-stopped
    command:
      - '--mongodb.uri=mongodb://admin:${MONGO_ROOT_PASSWORD}@mongodb:27017/admin?ssl=false'
      - '--mongodb.direct-connect=true'
      - '--collect-all'
    ports:
      - "127.0.0.1:9216:9216"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - mongodb

  redis-exporter:
    image: oliver006/redis_exporter:latest
    container_name: mikrotik-redis-exporter
    restart: unless-stopped
    environment:
      - REDIS_ADDR=redis:6379
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    ports:
      - "127.0.0.1:9121:9121"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - redis

  nginx-exporter:
    image: nginx/nginx-prometheus-exporter:latest
    container_name: mikrotik-nginx-exporter
    restart: unless-stopped
    command:
      - '-nginx.scrape-uri=http://nginx/nginx_status'
    ports:
      - "127.0.0.1:9113:9113"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - nginx

  # ===========================================
  # Management Tools
  # ===========================================
  mongo-express:
    image: mongo-express:latest
    container_name: mikrotik-mongo-express
    restart: unless-stopped
    environment:
      - ME_CONFIG_MONGODB_ADMINUSERNAME=admin
      - ME_CONFIG_MONGODB_ADMINPASSWORD=${MONGO_ROOT_PASSWORD}
      - ME_CONFIG_MONGODB_SERVER=mongodb
      - ME_CONFIG_MONGODB_PORT=27017
      - ME_CONFIG_BASICAUTH_USERNAME=admin
      - ME_CONFIG_BASICAUTH_PASSWORD=${MONGO_ROOT_PASSWORD}
      - ME_CONFIG_OPTIONS_EDITORTHEME=ambiance
    ports:
      - "127.0.0.1:8081:8081"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - mongodb

  redis-commander:
    image: rediscommander/redis-commander:latest
    container_name: mikrotik-redis-commander
    restart: unless-stopped
    environment:
      - REDIS_HOSTS=local:redis:6379:0:${REDIS_PASSWORD}
      - HTTP_USER=admin
      - HTTP_PASSWORD=${REDIS_PASSWORD}
    ports:
      - "127.0.0.1:8082:8081"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - redis

  # ===========================================
  # SSL Certificate Management
  # ===========================================
  certbot:
    image: certbot/certbot
    container_name: mikrotik-certbot
    volumes:
      - ./nginx/ssl:/etc/letsencrypt
      - certbot_www:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait ${!}; done;'"
    networks:
      - mikrotik-vpn-net

# ===========================================
# Volumes
# ===========================================
volumes:
  prometheus_data:
    driver: local
  grafana_data:
    driver: local
  alertmanager_data:
    driver: local
  certbot_www:
    driver: local

# ===========================================
# Networks
# ===========================================
networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create OpenVPN Dockerfile
    cat << 'EOF' > "$SYSTEM_DIR/openvpn/Dockerfile"
FROM alpine:latest

RUN apk add --no-cache \
    openvpn \
    easy-rsa \
    bash \
    iptables \
    curl

# Copy configuration files
COPY --chown=root:root . /etc/openvpn/

# Create necessary directories
RUN mkdir -p /etc/openvpn/ccd \
    && mkdir -p /var/log

# Make init script executable
RUN chmod +x /etc/openvpn/init-pki.sh

# Expose ports
EXPOSE 1194/udp 7505/tcp

# Entry point
CMD ["openvpn", "--config", "/etc/openvpn/server/server.conf"]
EOF

    log "Phase 7 completed successfully!"
}

# =============================================================================
# PHASE 8: MANAGEMENT SCRIPTS
# =============================================================================

phase8_management_scripts() {
    log "==================================================================="
    log "PHASE 8: CREATING MANAGEMENT SCRIPTS"
    log "==================================================================="
    
    # Main management script
    create_main_management_script
    
    # Service control scripts
    create_service_scripts
    
    # VPN management scripts
    create_vpn_scripts
    
    # Backup scripts
    create_backup_scripts
    
    # Monitoring scripts
    create_monitoring_scripts
    
    # Utility scripts
    create_utility_scripts
    
    # Set permissions
    chmod +x "$SCRIPT_DIR"/*.sh
    
    log "Phase 8 completed successfully!"
}

# Create main management script
create_main_management_script() {
    cat << 'EOF' > "$SYSTEM_DIR/mikrotik-vpn"
#!/bin/bash
# MikroTik VPN System Management Interface

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SYSTEM_DIR="/opt/mikrotik-vpn"
SCRIPT_DIR="/opt/mikrotik-vpn/scripts"

# Load environment
if [[ -f "$SYSTEM_DIR/configs/setup.env" ]]; then
    source "$SYSTEM_DIR/configs/setup.env"
fi

# Print colored output
print_colored() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Show header
show_header() {
    clear
    print_colored "$CYAN" "╔═══════════════════════════════════════════════════════════════╗"
    print_colored "$CYAN" "║          MikroTik VPN Management System v4.2                  ║"
    print_colored "$CYAN" "╚═══════════════════════════════════════════════════════════════╝"
    echo
}

# Show status
show_status() {
    show_header
    print_colored "$BLUE" "System Status"
    print_colored "$BLUE" "═════════════"
    echo
    
    # Check services
    local services=("mongodb" "redis" "app" "nginx" "openvpn" "prometheus" "grafana")
    for service in "${services[@]}"; do
        if docker ps --format "{{.Names}}" | grep -q "mikrotik-$service"; then
            print_colored "$GREEN" "✓ $service is running"
        else
            print_colored "$RED" "✗ $service is not running"
        fi
    done
    
    echo
    print_colored "$BLUE" "System Information"
    print_colored "$BLUE" "═════════════════"
    echo "Domain: $DOMAIN_NAME"
    echo "VPN Network: $VPN_NETWORK"
    echo "Uptime: $(uptime -p)"
    echo
}

# Main menu
main_menu() {
    show_header
    print_colored "$PURPLE" "Main Menu"
    print_colored "$PURPLE" "═════════"
    echo
    echo "1. System Management"
    echo "2. VPN Management"
    echo "3. Service Control"
    echo "4. Monitoring & Logs"
    echo "5. Backup & Restore"
    echo "6. Security"
    echo "7. Quick Actions"
    echo "8. Help & Documentation"
    echo "9. Exit"
    echo
    read -p "Select option (1-9): " choice
    
    case $choice in
        1) system_management_menu ;;
        2) vpn_management_menu ;;
        3) service_control_menu ;;
        4) monitoring_menu ;;
        5) backup_menu ;;
        6) security_menu ;;
        7) quick_actions_menu ;;
        8) help_menu ;;
        9) exit 0 ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; main_menu ;;
    esac
}

# System management menu
system_management_menu() {
    show_header
    print_colored "$PURPLE" "System Management"
    print_colored "$PURPLE" "════════════════"
    echo
    echo "1. Show system status"
    echo "2. Update system"
    echo "3. Configure settings"
    echo "4. Manage users"
    echo "5. View configuration"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) show_status; read -p "Press Enter to continue..."; system_management_menu ;;
        2) $SCRIPT_DIR/update-system.sh; read -p "Press Enter to continue..."; system_management_menu ;;
        3) $SCRIPT_DIR/configure-system.sh; system_management_menu ;;
        4) $SCRIPT_DIR/manage-users.sh; system_management_menu ;;
        5) $SCRIPT_DIR/show-config.sh; read -p "Press Enter to continue..."; system_management_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; system_management_menu ;;
    esac
}

# VPN management menu
vpn_management_menu() {
    show_header
    print_colored "$PURPLE" "VPN Management"
    print_colored "$PURPLE" "═════════════"
    echo
    echo "1. Create VPN client"
    echo "2. List VPN clients"
    echo "3. Revoke VPN client"
    echo "4. Show VPN status"
    echo "5. Export VPN configs"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/create-vpn-client.sh; vpn_management_menu ;;
        2) $SCRIPT_DIR/list-vpn-clients.sh; read -p "Press Enter to continue..."; vpn_management_menu ;;
        3) $SCRIPT_DIR/revoke-vpn-client.sh; vpn_management_menu ;;
        4) $SCRIPT_DIR/vpn-status.sh; read -p "Press Enter to continue..."; vpn_management_menu ;;
        5) $SCRIPT_DIR/export-vpn-configs.sh; vpn_management_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; vpn_management_menu ;;
    esac
}

# Service control menu
service_control_menu() {
    show_header
    print_colored "$PURPLE" "Service Control"
    print_colored "$PURPLE" "══════════════"
    echo
    echo "1. Start all services"
    echo "2. Stop all services"
    echo "3. Restart all services"
    echo "4. Start specific service"
    echo "5. Stop specific service"
    echo "6. Restart specific service"
    echo "7. Back to main menu"
    echo
    read -p "Select option (1-7): " choice
    
    case $choice in
        1) $SCRIPT_DIR/start-services.sh; read -p "Press Enter to continue..."; service_control_menu ;;
        2) $SCRIPT_DIR/stop-services.sh; read -p "Press Enter to continue..."; service_control_menu ;;
        3) $SCRIPT_DIR/restart-services.sh; read -p "Press Enter to continue..."; service_control_menu ;;
        4) $SCRIPT_DIR/start-service.sh; service_control_menu ;;
        5) $SCRIPT_DIR/stop-service.sh; service_control_menu ;;
        6) $SCRIPT_DIR/restart-service.sh; service_control_menu ;;
        7) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; service_control_menu ;;
    esac
}

# Monitoring menu
monitoring_menu() {
    show_header
    print_colored "$PURPLE" "Monitoring & Logs"
    print_colored "$PURPLE" "════════════════"
    echo
    echo "1. View live logs"
    echo "2. View service logs"
    echo "3. System health check"
    echo "4. Performance metrics"
    echo "5. Open Grafana"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/view-logs.sh ;;
        2) $SCRIPT_DIR/service-logs.sh; monitoring_menu ;;
        3) $SCRIPT_DIR/health-check.sh; read -p "Press Enter to continue..."; monitoring_menu ;;
        4) $SCRIPT_DIR/show-metrics.sh; read -p "Press Enter to continue..."; monitoring_menu ;;
        5) echo "Grafana URL: http://localhost:3001"; read -p "Press Enter to continue..."; monitoring_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; monitoring_menu ;;
    esac
}

# Backup menu
backup_menu() {
    show_header
    print_colored "$PURPLE" "Backup & Restore"
    print_colored "$PURPLE" "═══════════════"
    echo
    echo "1. Create backup"
    echo "2. List backups"
    echo "3. Restore from backup"
    echo "4. Schedule automatic backups"
    echo "5. Export backup"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/backup-system.sh; read -p "Press Enter to continue..."; backup_menu ;;
        2) $SCRIPT_DIR/list-backups.sh; read -p "Press Enter to continue..."; backup_menu ;;
        3) $SCRIPT_DIR/restore-system.sh; backup_menu ;;
        4) $SCRIPT_DIR/schedule-backups.sh; backup_menu ;;
        5) $SCRIPT_DIR/export-backup.sh; backup_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; backup_menu ;;
    esac
}

# Security menu
security_menu() {
    show_header
    print_colored "$PURPLE" "Security"
    print_colored "$PURPLE" "════════"
    echo
    echo "1. View security status"
    echo "2. Update SSL certificates"
    echo "3. Manage firewall"
    echo "4. View failed login attempts"
    echo "5. Run security audit"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/security-status.sh; read -p "Press Enter to continue..."; security_menu ;;
        2) $SCRIPT_DIR/update-ssl.sh; security_menu ;;
        3) $SCRIPT_DIR/manage-firewall.sh; security_menu ;;
        4) $SCRIPT_DIR/show-failed-logins.sh; read -p "Press Enter to continue..."; security_menu ;;
        5) $SCRIPT_DIR/security-audit.sh; read -p "Press Enter to continue..."; security_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; security_menu ;;
    esac
}

# Quick actions menu
quick_actions_menu() {
    show_header
    print_colored "$PURPLE" "Quick Actions"
    print_colored "$PURPLE" "════════════"
    echo
    echo "1. Restart application"
    echo "2. Clear logs"
    echo "3. Reset admin password"
    echo "4. Generate API key"
    echo "5. Export configuration"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) docker restart mikrotik-app; print_colored "$GREEN" "Application restarted"; sleep 2; quick_actions_menu ;;
        2) $SCRIPT_DIR/clear-logs.sh; quick_actions_menu ;;
        3) $SCRIPT_DIR/reset-password.sh; quick_actions_menu ;;
        4) $SCRIPT_DIR/generate-api-key.sh; read -p "Press Enter to continue..."; quick_actions_menu ;;
        5) $SCRIPT_DIR/export-config.sh; quick_actions_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; quick_actions_menu ;;
    esac
}

# Help menu
help_menu() {
    show_header
    print_colored "$PURPLE" "Help & Documentation"
    print_colored "$PURPLE" "═══════════════════"
    echo
    echo "System Information:"
    echo "  Version: 4.2"
    echo "  Domain: $DOMAIN_NAME"
    echo "  Admin Email: $ADMIN_EMAIL"
    echo
    echo "Access URLs:"
    echo "  Main: https://$DOMAIN_NAME"
    echo "  Admin: https://admin.$DOMAIN_NAME"
    echo "  Monitor: https://monitor.$DOMAIN_NAME"
    echo "  API Docs: https://$DOMAIN_NAME/api-docs"
    echo
    echo "Configuration Files:"
    echo "  Main: $CONFIG_DIR/setup.env"
    echo "  Docker: $SYSTEM_DIR/docker-compose.yml"
    echo
    echo "Log Files:"
    echo "  Application: $LOG_DIR/app.log"
    echo "  Nginx: $LOG_DIR/nginx/"
    echo
    read -p "Press Enter to continue..."
    main_menu
}

# Handle command line arguments
case "${1:-}" in
    status)
        show_status
        ;;
    start)
        $SCRIPT_DIR/start-services.sh
        ;;
    stop)
        $SCRIPT_DIR/stop-services.sh
        ;;
    restart)
        $SCRIPT_DIR/restart-services.sh
        ;;
    backup)
        $SCRIPT_DIR/backup-system.sh
        ;;
    health)
        $SCRIPT_DIR/health-check.sh
        ;;
    *)
        main_menu
        ;;
esac
EOF

    chmod +x "$SYSTEM_DIR/mikrotik-vpn"
    ln -sf "$SYSTEM_DIR/mikrotik-vpn" /usr/local/bin/mikrotik-vpn
}

# Create service control scripts
create_service_scripts() {
    # Start services
    cat << 'EOF' > "$SCRIPT_DIR/start-services.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Starting MikroTik VPN services..."
cd /opt/mikrotik-vpn || exit 1

# Create network if not exists
docker network ls --format '{{.Name}}' | grep -q "^mikrotik-vpn-net$" || \
    docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16

# Start services in order
docker compose up -d mongodb redis
sleep 10
docker compose up -d app
sleep 5
docker compose up -d

echo "All services started!"
docker compose ps
EOF

    # Stop services
    cat << 'EOF' > "$SCRIPT_DIR/stop-services.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Stopping MikroTik VPN services..."
cd /opt/mikrotik-vpn || exit 1
docker compose down

echo "All services stopped!"
EOF

    # Restart services
    cat << 'EOF' > "$SCRIPT_DIR/restart-services.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Restarting MikroTik VPN services..."
cd /opt/mikrotik-vpn || exit 1
docker compose restart

echo "All services restarted!"
docker compose ps
EOF

    # Health check
    cat << 'EOF' > "$SCRIPT_DIR/health-check.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== MikroTik VPN System Health Check ==="
echo "Timestamp: $(date)"
echo

# Function to check service
check_service() {
    local service=$1
    local container="mikrotik-$service"
    
    if docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
        # Get container health status
        health=$(docker inspect --format='{{.State.Health.Status}}' $container 2>/dev/null || echo "none")
        
        if [[ "$health" == "healthy" ]] || [[ "$health" == "none" ]]; then
            echo -e "${GREEN}✓${NC} $service is running"
            
            # Additional checks for specific services
            case $service in
                "mongodb")
                    if docker exec $container mongosh --eval "db.adminCommand('ping')" --quiet &>/dev/null; then
                        echo -e "  ${GREEN}✓${NC} MongoDB responding to queries"
                    else
                        echo -e "  ${RED}✗${NC} MongoDB not responding"
                    fi
                    ;;
                "redis")
                    if docker exec $container redis-cli --pass "$REDIS_PASSWORD" ping 2>/dev/null | grep -q "PONG"; then
                        echo -e "  ${GREEN}✓${NC} Redis responding to queries"
                    else
                        echo -e "  ${RED}✗${NC} Redis not responding"
                    fi
                    ;;
                "app")
                    if curl -s http://localhost:3000/health | grep -q "OK"; then
                        echo -e "  ${GREEN}✓${NC} Application API healthy"
                    else
                        echo -e "  ${RED}✗${NC} Application API not responding"
                    fi
                    ;;
            esac
        else
            echo -e "${YELLOW}⚠${NC} $service is unhealthy"
        fi
    else
        echo -e "${RED}✗${NC} $service is not running"
    fi
}

# Check all services
echo "Checking services..."
services=("mongodb" "redis" "app" "nginx" "openvpn" "prometheus" "grafana")
for service in "${services[@]}"; do
    check_service "$service"
done

echo
echo "Checking system resources..."

# Disk usage
disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ $disk_usage -lt 80 ]]; then
    echo -e "${GREEN}✓${NC} Disk usage: $disk_usage%"
else
    echo -e "${YELLOW}⚠${NC} Disk usage: $disk_usage% (high)"
fi

# Memory usage
mem_total=$(free -m | awk '/^Mem:/{print $2}')
mem_used=$(free -m | awk '/^Mem:/{print $3}')
mem_percent=$((mem_used * 100 / mem_total))
if [[ $mem_percent -lt 80 ]]; then
    echo -e "${GREEN}✓${NC} Memory usage: $mem_percent% ($mem_used MB / $mem_total MB)"
else
    echo -e "${YELLOW}⚠${NC} Memory usage: $mem_percent% (high)"
fi

# CPU load
load_avg=$(uptime | awk -F'load average:' '{print $2}')
echo -e "${GREEN}✓${NC} Load average:$load_avg"

echo
echo "Checking network connectivity..."

# Check internet
if ping -c 1 8.8.8.8 &>/dev/null; then
    echo -e "${GREEN}✓${NC} Internet connectivity OK"
else
    echo -e "${RED}✗${NC} No internet connectivity"
fi

# Check DNS
if nslookup google.com &>/dev/null; then
    echo -e "${GREEN}✓${NC} DNS resolution OK"
else
    echo -e "${RED}✗${NC} DNS resolution failed"
fi

echo
echo "Health check completed!"
EOF
}

# Create VPN management scripts
create_vpn_scripts() {
    # Create VPN client
    cat << 'EOF' > "$SCRIPT_DIR/create-vpn-client.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

read -p "Enter client name (alphanumeric, no spaces): " CLIENT_NAME

# Validate input
if [[ ! $CLIENT_NAME =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Invalid client name. Use only letters, numbers, hyphens, and underscores."
    exit 1
fi

echo "Creating VPN client: $CLIENT_NAME"

# Check if OpenVPN is initialized
if ! docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/ca.crt 2>/dev/null; then
    echo "Initializing OpenVPN PKI..."
    docker exec mikrotik-openvpn /etc/openvpn/init-pki.sh
fi

# Generate client certificate
docker exec mikrotik-openvpn bash -c "
cd /etc/openvpn/easy-rsa
./easyrsa --batch gen-req $CLIENT_NAME nopass
./easyrsa --batch sign-req client $CLIENT_NAME
"

# Create client configuration
cat << OVPN > "/opt/mikrotik-vpn/clients/$CLIENT_NAME.ovpn"
client
dev tun
proto udp
remote $DOMAIN_NAME 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
comp-lzo
verb 3

<ca>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/pki/ca.crt)
</ca>

<cert>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/pki/issued/$CLIENT_NAME.crt | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p')
</cert>

<key>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/pki/private/$CLIENT_NAME.key)
</key>

<tls-auth>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/ta.key)
</tls-auth>
key-direction 1
OVPN

echo "VPN client configuration created: /opt/mikrotik-vpn/clients/$CLIENT_NAME.ovpn"
echo
echo "To use this configuration:"
echo "1. Copy the .ovpn file to your device"
echo "2. Import it into your OpenVPN client"
echo "3. Connect using the imported profile"
EOF

    # List VPN clients
    cat << 'EOF' > "$SCRIPT_DIR/list-vpn-clients.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== VPN Clients ==="
echo

if [[ -d "/opt/mikrotik-vpn/clients" ]]; then
    clients=$(ls -1 /opt/mikrotik-vpn/clients/*.ovpn 2>/dev/null | wc -l)
    
    if [[ $clients -gt 0 ]]; then
        echo "Active client configurations:"
        ls -1 /opt/mikrotik-vpn/clients/*.ovpn | while read file; do
            basename "$file" .ovpn
        done
    else
        echo "No client configurations found."
    fi
else
    echo "Clients directory not found."
fi

echo
echo "=== Connected Clients ==="
if docker exec mikrotik-openvpn test -f /var/log/openvpn-status.log 2>/dev/null; then
    docker exec mikrotik-openvpn cat /var/log/openvpn-status.log | grep "CLIENT_LIST" | awk -F',' '{print $2 " - " $3}'
else
    echo "No status information available."
fi
EOF

    # VPN status
    cat << 'EOF' > "$SCRIPT_DIR/vpn-status.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== VPN Server Status ==="
echo

# OpenVPN status
echo "OpenVPN Server:"
if docker ps | grep -q mikrotik-openvpn; then
    echo "  Status: Running"
    
    # Get connected clients
    if docker exec mikrotik-openvpn test -f /var/log/openvpn-status.log 2>/dev/null; then
        clients=$(docker exec mikrotik-openvpn grep -c "CLIENT_LIST" /var/log/openvpn-status.log 2>/dev/null || echo "0")
        echo "  Connected clients: $clients"
    fi
    
    # Get traffic stats
    echo "  Port: 1194/udp"
else
    echo "  Status: Not running"
fi

echo
echo "L2TP/IPSec Server:"
if docker ps | grep -q mikrotik-l2tp; then
    echo "  Status: Running"
    echo "  Ports: 500/udp, 4500/udp, 1701/udp"
    
    # Show connection info
    echo "  PSK: Configured"
    echo "  Username: mikrotik"
else
    echo "  Status: Not running"
fi

echo
echo "VPN Network: $VPN_NETWORK"
echo "Public IP: $(curl -s https://api.ipify.org 2>/dev/null || echo "Unable to determine")"
EOF
}

# Create backup scripts
create_backup_scripts() {
    # Backup system
    cat << 'EOF' > "$SCRIPT_DIR/backup-system.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

BACKUP_DIR="/opt/mikrotik-vpn/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="mikrotik-vpn-backup-$DATE"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"

echo "Creating system backup..."
mkdir -p "$BACKUP_PATH"

# Stop services for consistency
echo "Stopping services..."
cd /opt/mikrotik-vpn || exit 1
docker compose stop app

# Backup databases
echo "Backing up MongoDB..."
docker exec mikrotik-mongodb mongodump \
    --uri="mongodb://admin:$MONGO_ROOT_PASSWORD@localhost:27017/admin" \
    --archive="/tmp/mongodb-backup.gz" \
    --gzip

docker cp mikrotik-mongodb:/tmp/mongodb-backup.gz "$BACKUP_PATH/"
docker exec mikrotik-mongodb rm /tmp/mongodb-backup.gz

echo "Backing up Redis..."
docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" BGSAVE
sleep 5
docker cp mikrotik-redis:/data/dump.rdb "$BACKUP_PATH/redis-dump.rdb"

# Backup configurations
echo "Backing up configurations..."
tar -czf "$BACKUP_PATH/configs.tar.gz" \
    /opt/mikrotik-vpn/configs \
    /opt/mikrotik-vpn/nginx \
    /opt/mikrotik-vpn/app/.env \
    /opt/mikrotik-vpn/docker-compose.yml \
    2>/dev/null

# Backup VPN configs
echo "Backing up VPN configurations..."
tar -czf "$BACKUP_PATH/vpn.tar.gz" \
    /opt/mikrotik-vpn/openvpn \
    /opt/mikrotik-vpn/clients \
    2>/dev/null

# Start services
echo "Starting services..."
docker compose start app

# Create backup info
cat << INFO > "$BACKUP_PATH/backup-info.txt"
Backup Information
==================
Date: $(date)
System: MikroTik VPN Management System
Version: 4.2
Domain: $DOMAIN_NAME

Contents:
- MongoDB database
- Redis database
- System configurations
- VPN configurations
- SSL certificates

Restore Instructions:
1. Run: mikrotik-vpn restore
2. Select this backup: $BACKUP_NAME
3. Confirm restoration
INFO

# Compress backup
echo "Compressing backup..."
cd "$BACKUP_DIR"
tar -czf "$BACKUP_NAME.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

# Clean old backups (keep last 7)
echo "Cleaning old backups..."
ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -n +8 | xargs -r rm

echo "Backup completed: $BACKUP_DIR/$BACKUP_NAME.tar.gz"
echo "Size: $(du -h "$BACKUP_DIR/$BACKUP_NAME.tar.gz" | cut -f1)"
EOF

    # List backups
    cat << 'EOF' > "$SCRIPT_DIR/list-backups.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

BACKUP_DIR="/opt/mikrotik-vpn/backups"

echo "=== Available Backups ==="
echo

if [[ -d "$BACKUP_DIR" ]]; then
    backups=$(ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null | wc -l)
    
    if [[ $backups -gt 0 ]]; then
        echo "Found $backups backup(s):"
        echo
        ls -lh "$BACKUP_DIR"/*.tar.gz | awk '{print $9 " (" $5 ")"}'
    else
        echo "No backups found."
    fi
else
    echo "Backup directory not found."
fi

echo
echo "Backup location: $BACKUP_DIR"
EOF

    # Restore system
    cat << 'EOF' > "$SCRIPT_DIR/restore-system.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

BACKUP_DIR="/opt/mikrotik-vpn/backups"

echo "=== System Restore ==="
echo

# List available backups
echo "Available backups:"
select backup in $(ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null); do
    if [[ -n "$backup" ]]; then
        break
    fi
done

if [[ -z "$backup" ]]; then
    echo "No backup selected."
    exit 1
fi

echo
echo "Selected backup: $(basename "$backup")"
echo
echo "WARNING: This will restore the system to the backup state."
echo "Current data will be overwritten!"
echo
read -p "Are you sure you want to continue? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Restore cancelled."
    exit 0
fi

# Create temporary directory
TEMP_DIR="/tmp/restore-$"
mkdir -p "$TEMP_DIR"

# Extract backup
echo "Extracting backup..."
tar -xzf "$backup" -C "$TEMP_DIR"

BACKUP_NAME=$(basename "$backup" .tar.gz)
RESTORE_PATH="$TEMP_DIR/$BACKUP_NAME"

# Stop all services
echo "Stopping all services..."
cd /opt/mikrotik-vpn || exit 1
docker compose down

# Restore MongoDB
echo "Restoring MongoDB..."
docker compose up -d mongodb
sleep 10

docker cp "$RESTORE_PATH/mongodb-backup.gz" mikrotik-mongodb:/tmp/
docker exec mikrotik-mongodb mongorestore \
    --uri="mongodb://admin:$MONGO_ROOT_PASSWORD@localhost:27017/admin" \
    --archive="/tmp/mongodb-backup.gz" \
    --gzip \
    --drop

# Restore Redis
echo "Restoring Redis..."
docker compose stop redis
docker cp "$RESTORE_PATH/redis-dump.rdb" mikrotik-redis:/data/dump.rdb
docker compose start redis

# Restore configurations
echo "Restoring configurations..."
tar -xzf "$RESTORE_PATH/configs.tar.gz" -C / 2>/dev/null || true
tar -xzf "$RESTORE_PATH/vpn.tar.gz" -C / 2>/dev/null || true

# Start all services
echo "Starting all services..."
docker compose up -d

# Cleanup
rm -rf "$TEMP_DIR"

echo
echo "Restore completed successfully!"
echo "Please verify all services are working correctly."
EOF
}

# Create monitoring scripts
create_monitoring_scripts() {
    # View logs
    cat << 'EOF' > "$SCRIPT_DIR/view-logs.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Select service to view logs:"
echo "1. All services"
echo "2. Application"
echo "3. MongoDB"
echo "4. Redis"
echo "5. Nginx"
echo "6. OpenVPN"
echo "7. Exit"
echo

read -p "Enter choice (1-7): " choice

cd /opt/mikrotik-vpn || exit 1

case $choice in
    1) docker compose logs -f ;;
    2) docker compose logs -f app ;;
    3) docker compose logs -f mongodb ;;
    4) docker compose logs -f redis ;;
    5) docker compose logs -f nginx ;;
    6) docker compose logs -f openvpn ;;
    7) exit 0 ;;
    *) echo "Invalid choice"; exit 1 ;;
esac
EOF

    # Show metrics
    cat << 'EOF' > "$SCRIPT_DIR/show-metrics.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== System Metrics ==="
echo

# CPU usage
echo "CPU Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}" | grep mikrotik

echo
echo "Memory Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}" | grep mikrotik

echo
echo "Network I/O:"
docker stats --no-stream --format "table {{.Container}}\t{{.NetIO}}" | grep mikrotik

echo
echo "Disk I/O:"
docker stats --no-stream --format "table {{.Container}}\t{{.BlockIO}}" | grep mikrotik

echo
echo "For detailed metrics, visit Grafana: http://localhost:3001"
EOF
}

# Create utility scripts
create_utility_scripts() {
    # Update system
    cat << 'EOF' > "$SCRIPT_DIR/update-system.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== System Update ==="
echo

echo "Pulling latest Docker images..."
cd /opt/mikrotik-vpn || exit 1
docker compose pull

echo
echo "Rebuilding application..."
docker compose build app

echo
echo "Restarting services with new images..."
docker compose up -d

echo
echo "Cleaning up old images..."
docker image prune -f

echo
echo "Update completed!"
docker compose ps
EOF

    # Show configuration
    cat << 'EOF' > "$SCRIPT_DIR/show-config.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== System Configuration ==="
echo

echo "Basic Information:"
echo "  Domain: $DOMAIN_NAME"
echo "  Admin Email: $ADMIN_EMAIL"
echo "  VPN Network: $VPN_NETWORK"
echo "  SSH Port: $SSH_PORT"
echo

echo "Service URLs:"
echo "  Main: https://$DOMAIN_NAME"
echo "  Admin: https://admin.$DOMAIN_NAME"
echo "  Monitor: https://monitor.$DOMAIN_NAME"
echo "  API Docs: https://$DOMAIN_NAME/api-docs"
echo

echo "Database Access:"
echo "  MongoDB: mongodb://localhost:27017"
echo "  Redis: redis://localhost:6379"
echo

echo "Management Tools:"
echo "  Mongo Express: http://localhost:8081"
echo "  Redis Commander: http://localhost:8082"
echo "  Prometheus: http://localhost:9090"
echo "  Grafana: http://localhost:3001"
echo

echo "Configuration Files:"
echo "  Environment: $CONFIG_DIR/setup.env"
echo "  Docker Compose: $SYSTEM_DIR/docker-compose.yml"
echo "  Nginx: $SYSTEM_DIR/nginx/conf.d/"
echo "  Application: $SYSTEM_DIR/app/.env"
EOF

    # Security status
    cat << 'EOF' > "$SCRIPT_DIR/security-status.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== Security Status ==="
echo

# SSL Certificate
echo "SSL Certificate:"
if [[ -f "/opt/mikrotik-vpn/nginx/ssl/fullchain.pem" ]]; then
    expiry=$(openssl x509 -enddate -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | cut -d= -f2)
    echo "  Status: Installed"
    echo "  Expires: $expiry"
else
    echo "  Status: Not found"
fi

echo

# Firewall
echo "Firewall (UFW):"
if systemctl is-active --quiet ufw; then
    echo "  Status: Active"
    ufw status numbered | grep -E "^\[[0-9]+\]" | head -5
else
    echo "  Status: Inactive"
fi

echo

# Fail2ban
echo "Fail2ban:"
if systemctl is-active --quiet fail2ban; then
    echo "  Status: Active"
    fail2ban-client status | grep "Jail list" | cut -d: -f2
else
    echo "  Status: Inactive"
fi

echo

# SSH
echo "SSH Configuration:"
echo "  Port: $SSH_PORT"
echo "  Root Login: $(grep "^PermitRootLogin" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | head -1 || echo "not configured")"
echo "  Password Auth: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | head -1 || echo "not configured")"
EOF

    # Clear logs
    cat << 'EOF' > "$SCRIPT_DIR/clear-logs.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "This will clear all application logs."
read -p "Are you sure? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Cancelled."
    exit 0
fi

echo "Clearing logs..."

# Application logs
find /opt/mikrotik-vpn/logs -name "*.log" -type f -exec truncate -s 0 {} \;

# Docker logs
docker ps --format "{{.Names}}" | grep mikrotik | while read container; do
    echo "Clearing logs for $container..."
    docker exec $container sh -c 'find /var/log -name "*.log" -type f -exec truncate -s 0 {} \; 2>/dev/null' || true
done

echo "Logs cleared!"
EOF
}

# =============================================================================
# PHASE 9: SECURITY CONFIGURATION
# =============================================================================

phase9_security_configuration() {
    log "==================================================================="
    log "PHASE 9: SECURITY CONFIGURATION"
    log "==================================================================="
    
    # Configure firewall
    setup_firewall
    
    # Configure Fail2ban
    setup_fail2ban
    
    # Configure SSH hardening
    harden_ssh
    
    # Setup intrusion detection
    setup_intrusion_detection
    
    # Create security cron jobs
    setup_security_crons
    
    log "Phase 9 completed successfully!"
}

# Setup firewall
setup_firewall() {
    log "Configuring UFW firewall..."
    
    # Reset firewall
    ufw --force disable
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow "$SSH_PORT/tcp" comment 'SSH'
    
    # Allow web traffic
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow VPN
    ufw allow 1194/udp comment 'OpenVPN'
    ufw allow 500/udp comment 'IPSec'
    ufw allow 4500/udp comment 'IPSec NAT-T'
    ufw allow 1701/udp comment 'L2TP'
    
    # Allow Docker network
    ufw allow from 172.20.0.0/16 comment 'Docker network'
    
    # Enable firewall
    ufw --force enable
    
    log "Firewall configured successfully"
}

# Setup Fail2ban
setup_fail2ban() {
    log "Configuring Fail2ban..."
    
    # Create jail configuration
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = $ADMIN_EMAIL
sender = fail2ban@$DOMAIN_NAME
action = %(action_mwl)s
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /opt/mikrotik-vpn/logs/nginx/error.log
maxretry = 5

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /opt/mikrotik-vpn/logs/nginx/error.log
maxretry = 10

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /opt/mikrotik-vpn/logs/nginx/access.log
maxretry = 2

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /opt/mikrotik-vpn/logs/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = apache-badbots
action = iptables-multiport[name=BadBots, port="http,https"]
logpath = /opt/mikrotik-vpn/logs/nginx/access.log
maxretry = 2

[mongodb-auth]
enabled = false
filter = mongodb-auth
port = 27017
logpath = /opt/mikrotik-vpn/mongodb/logs/mongod.log
maxretry = 3
EOF

    # Create MongoDB filter
    cat << 'EOF' > /etc/fail2ban/filter.d/mongodb-auth.conf
[Definition]
failregex = ^.*authentication failed.*from client <HOST>.*$
            ^.*Failed to authenticate.*from client <HOST>.*$
ignoreregex =
EOF

    # Restart Fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log "Fail2ban configured successfully"
}

# SSH hardening
harden_ssh() {
    log "Hardening SSH configuration..."
    
    # Create required directories
    mkdir -p /run/sshd
    chmod 755 /run/sshd
    
    # Backup original SSH config
    if [[ ! -f /etc/ssh/sshd_config.backup ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    fi
    
    # Create SSH config
    cat << EOF > /etc/ssh/sshd_config.d/99-mikrotik-vpn-hardening.conf
# MikroTik VPN SSH Hardening
Port $SSH_PORT
Protocol 2

# Host keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Security
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no

# Restrict users
AllowUsers mikrotik-vpn ${SUDO_USER:-root}

# Logging
SyslogFacility AUTH
LogLevel INFO

# Ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
EOF

    # Test configuration
    if sshd -t; then
        # Only restart SSH if systemctl is working
        if systemctl is-system-running &>/dev/null; then
            # Try different service names
            if systemctl list-units --type=service | grep -q "^ssh.service"; then
                systemctl restart ssh
                log "SSH hardening completed successfully (using ssh service)"
            elif systemctl list-units --type=service | grep -q "^sshd.service"; then
                systemctl restart sshd
                log "SSH hardening completed successfully (using sshd service)"
            else
                log_warning "SSH service not found, trying service command..."
                service ssh restart || service sshd restart || {
                    log_warning "Could not restart SSH service, but configuration is updated"
                    log_warning "You may need to manually restart SSH service"
                }
            fi
        else
            log_warning "SSH configuration updated but service not restarted (systemctl not available)"
            log "SSH hardening configuration saved"
        fi
    else
        log_error "SSH configuration test failed, reverting changes..."
        rm -f /etc/ssh/sshd_config.d/99-mikrotik-vpn-hardening.conf
        return 1
    fi
}

# Setup intrusion detection
setup_intrusion_detection() {
    log "Setting up intrusion detection..."
    
    # Initialize AIDE
    if command -v aide &> /dev/null; then
        if [[ ! -f "/var/lib/aide/aide.db" ]]; then
            log "Initializing AIDE database..."
            # Create aide config directory if not exists
            mkdir -p /var/lib/aide
            
            # Initialize AIDE
            if command -v aideinit &> /dev/null; then
                aideinit -y -f || {
                    log_warning "AIDE initialization failed, trying alternative method..."
                    aide --init || log_warning "AIDE initialization failed"
                }
                
                # Copy database if created
                if [[ -f /var/lib/aide/aide.db.new ]]; then
                    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
                fi
            else
                log_warning "aideinit not found, using aide --init"
                aide --init || log_warning "AIDE initialization failed"
            fi
        else
            log "AIDE database already exists"
        fi
    else
        log_warning "AIDE not installed, skipping"
    fi
    
    # Configure ClamAV
    if command -v clamscan &> /dev/null; then
        if systemctl is-system-running &>/dev/null; then
            systemctl stop clamav-freshclam 2>/dev/null || true
            freshclam || log_warning "ClamAV database update failed"
            systemctl start clamav-freshclam 2>/dev/null || true
            systemctl enable clamav-daemon 2>/dev/null || true
        else
            log_warning "Cannot manage ClamAV services without systemctl"
            freshclam || log_warning "ClamAV database update failed"
        fi
    else
        log_warning "ClamAV not installed, skipping"
    fi
    
    # Update rkhunter
    if command -v rkhunter &> /dev/null; then
        rkhunter --update || log_warning "rkhunter update failed"
        rkhunter --propupd || log_warning "rkhunter property update failed"
    else
        log_warning "rkhunter not installed, skipping"
    fi
    
    log "Intrusion detection setup completed"
}

# Setup security cron jobs
setup_security_crons() {
    # Security audit cron
    cat << 'EOF' > /etc/cron.d/mikrotik-vpn-security
# MikroTik VPN Security Tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily security audit
0 3 * * * root /opt/mikrotik-vpn/scripts/security-audit.sh >> /var/log/mikrotik-vpn/security-audit.log 2>&1

# Weekly virus scan
0 4 * * 0 root clamscan -r -i /opt/mikrotik-vpn >> /var/log/mikrotik-vpn/virus-scan.log 2>&1

# Daily AIDE check
0 5 * * * root aide --check >> /var/log/mikrotik-vpn/aide-check.log 2>&1

# Daily backup
0 2 * * * root /opt/mikrotik-vpn/scripts/backup-system.sh >> /var/log/mikrotik-vpn/backup.log 2>&1
EOF

    # Create security audit script
    cat << 'EOF' > "$SCRIPT_DIR/security-audit.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== Security Audit $(date) ==="
echo

# Check for suspicious users
echo "Checking for suspicious users..."
awk -F: '$3 == 0 && $1 != "root" {print "WARNING: User " $1 " has UID 0"}' /etc/passwd

# Check for world-writable files
echo "Checking for world-writable files..."
find /opt/mikrotik-vpn -type f -perm -002 2>/dev/null | head -20

# Check failed login attempts
echo "Recent failed login attempts:"
grep "Failed password" /var/log/auth.log | tail -10

# Check listening ports
echo "Listening ports:"
ss -tulpn | grep LISTEN

echo
echo "Audit completed"
EOF

    chmod +x "$SCRIPT_DIR/security-audit.sh"
}

# =============================================================================
# PHASE 10: FINAL SETUP AND VERIFICATION
# =============================================================================

phase10_final_setup() {
    log "==================================================================="
    log "PHASE 10: FINAL SETUP AND VERIFICATION"
    log "==================================================================="
    
    # Create systemd service
    create_systemd_service
    
    # Set final permissions
    set_final_permissions
    
    # Initialize OpenVPN PKI
    initialize_openvpn
    
    # Start all services
    start_all_services
    
    # Run final health check
    run_final_health_check
    
    # Create completion report
    create_completion_report
    
    log "Phase 10 completed successfully!"
}

# Create systemd service
create_systemd_service() {
    if systemctl is-system-running &>/dev/null; then
        cat << EOF > /etc/systemd/system/mikrotik-vpn.service
[Unit]
Description=MikroTik VPN Management System
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/mikrotik-vpn
ExecStart=/opt/mikrotik-vpn/scripts/start-services.sh
ExecStop=/opt/mikrotik-vpn/scripts/stop-services.sh
TimeoutStartSec=300
TimeoutStopSec=120
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable mikrotik-vpn.service
        
        log "Systemd service created and enabled"
    else
        log_warning "systemd not available, creating init script instead..."
        
        # Create a simple init script for non-systemd systems
        cat << 'EOF' > /etc/init.d/mikrotik-vpn
#!/bin/bash
### BEGIN INIT INFO
# Provides:          mikrotik-vpn
# Required-Start:    $docker $network
# Required-Stop:     $docker $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: MikroTik VPN Management System
### END INIT INFO

case "$1" in
    start)
        echo "Starting MikroTik VPN Management System..."
        /opt/mikrotik-vpn/scripts/start-services.sh
        ;;
    stop)
        echo "Stopping MikroTik VPN Management System..."
        /opt/mikrotik-vpn/scripts/stop-services.sh
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    status)
        /opt/mikrotik-vpn/scripts/health-check.sh
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF
        
        chmod +x /etc/init.d/mikrotik-vpn
        
        # Try to enable with update-rc.d if available
        if command -v update-rc.d &> /dev/null; then
            update-rc.d mikrotik-vpn defaults
            log "Init script created and enabled"
        else
            log "Init script created at /etc/init.d/mikrotik-vpn"
        fi
    fi
}

# Set final permissions
set_final_permissions() {
    # Set ownership
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR"
    chown -R mikrotik-vpn:mikrotik-vpn "$LOG_DIR"
    
    # Set permissions
    chmod -R 755 "$SYSTEM_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 600 "$CONFIG_DIR"/*
    chmod 700 "$SYSTEM_DIR/ssl"
    chmod 600 "$SYSTEM_DIR/ssl"/*
    chmod 755 "$SCRIPT_DIR"/*.sh
    
    log "Permissions set successfully"
}

# Initialize OpenVPN
initialize_openvpn() {
    log "Initializing OpenVPN PKI..."
    
    # Start OpenVPN container
    cd "$SYSTEM_DIR" || exit 1
    docker compose up -d openvpn
    sleep 10
    
    # Initialize PKI if needed
    if ! docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/ca.crt 2>/dev/null; then
        docker exec mikrotik-openvpn /etc/openvpn/init-pki.sh
    fi
    
    log "OpenVPN PKI initialized"
}

# Start all services
start_all_services() {
    log "Starting all services..."
    
    cd "$SYSTEM_DIR" || exit 1
    
    # Create network
    create_docker_network
    
    # Start services in order
    docker compose up -d mongodb redis
    sleep 15
    
    docker compose up -d app
    sleep 10
    
    docker compose up -d
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 30
    
    # Show status
    docker compose ps
    
    log "All services started"
}

# Run final health check
run_final_health_check() {
    log "Running final health check..."
    
    "$SCRIPT_DIR/health-check.sh" | tee -a "$LOG_FILE"
}

# Create completion report
create_completion_report() {
    local report_file="$SYSTEM_DIR/INSTALLATION_REPORT.txt"
    
    cat << EOF > "$report_file"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                 MikroTik VPN Management System v4.2                           ║
║                                                                               ║
║                     INSTALLATION COMPLETED SUCCESSFULLY!                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Installation Date: $(date)
System Version: 4.2
Domain: $DOMAIN_NAME
Admin Email: $ADMIN_EMAIL

═══════════════════════════════════════════════════════════════════════════════
ACCESS INFORMATION
═══════════════════════════════════════════════════════════════════════════════

Web Interfaces:
  Main Application:     https://$DOMAIN_NAME
  Admin Panel:          https://admin.$DOMAIN_NAME
  Monitoring:           https://monitor.$DOMAIN_NAME
  API Documentation:    https://$DOMAIN_NAME/api-docs

Management Tools:
  Mongo Express:        http://localhost:8081 (admin / $MONGO_ROOT_PASSWORD)
  Redis Commander:      http://localhost:8082 (admin / $REDIS_PASSWORD)
  Prometheus:           http://localhost:9090
  Grafana:              http://localhost:3001 (admin / $GRAFANA_PASSWORD)

SSH Access:
  Port:                 $SSH_PORT
  Users:                mikrotik-vpn, ${SUDO_USER:-root}

VPN Access:
  OpenVPN:              $DOMAIN_NAME:1194
  L2TP/IPSec:           $DOMAIN_NAME
    PSK:                $L2TP_PSK
    Username:           mikrotik
    Password:           $MONGO_ROOT_PASSWORD

═══════════════════════════════════════════════════════════════════════════════
CREDENTIALS
═══════════════════════════════════════════════════════════════════════════════

MongoDB:
  Root User:            admin / $MONGO_ROOT_PASSWORD
  App User:             mikrotik_app / $MONGO_APP_PASSWORD

Redis:
  Password:             $REDIS_PASSWORD

Grafana:
  Admin User:           admin / $GRAFANA_PASSWORD

Application:
  API Key:              $API_KEY

═══════════════════════════════════════════════════════════════════════════════
IMPORTANT FILES
═══════════════════════════════════════════════════════════════════════════════

Configuration:
  Main Config:          $CONFIG_DIR/setup.env
  Docker Compose:       $SYSTEM_DIR/docker-compose.yml
  Application:          $SYSTEM_DIR/app/.env

Logs:
  Application:          $LOG_DIR/app.log
  Error Log:            $LOG_DIR/error.log
  Nginx:                $LOG_DIR/nginx/

Backups:
  Location:             $BACKUP_DIR
  Script:               mikrotik-vpn backup

SSL Certificates:
  Location:             $SYSTEM_DIR/nginx/ssl/
  Note:                 Currently using self-signed certificate

═══════════════════════════════════════════════════════════════════════════════
MANAGEMENT COMMANDS
═══════════════════════════════════════════════════════════════════════════════

System Management:
  mikrotik-vpn          - Open management interface
  mikrotik-vpn status   - Quick status check
  mikrotik-vpn health   - Run health check
  mikrotik-vpn backup   - Create backup
  mikrotik-vpn restore  - Restore from backup

Service Control:
  systemctl status mikrotik-vpn     - Check service status
  systemctl start mikrotik-vpn      - Start all services
  systemctl stop mikrotik-vpn       - Stop all services
  systemctl restart mikrotik-vpn    - Restart all services

Docker Commands:
  cd /opt/mikrotik-vpn && docker compose ps      - Show container status
  cd /opt/mikrotik-vpn && docker compose logs    - View logs
  cd /opt/mikrotik-vpn && docker compose down    - Stop all containers
  cd /opt/mikrotik-vpn && docker compose up -d   - Start all containers

═══════════════════════════════════════════════════════════════════════════════
NEXT STEPS
═══════════════════════════════════════════════════════════════════════════════

1. Configure DNS:
   Point these domains to your server IP:
   - $DOMAIN_NAME
   - admin.$DOMAIN_NAME
   - monitor.$DOMAIN_NAME

2. Install Let's Encrypt SSL Certificate:
   docker run --rm -v /opt/mikrotik-vpn/nginx/ssl:/etc/letsencrypt \
     -v /opt/mikrotik-vpn/nginx/html:/var/www/certbot \
     -p 80:80 certbot/certbot certonly --standalone \
     --email $ADMIN_EMAIL --agree-tos --no-eff-email \
     -d $DOMAIN_NAME -d admin.$DOMAIN_NAME -d monitor.$DOMAIN_NAME

3. Configure Email Settings:
   Edit /opt/mikrotik-vpn/app/.env and update SMTP settings

4. Create First VPN Client:
   mikrotik-vpn
   Then select: VPN Management > Create VPN client

5. Access Web Interface:
   Open https://$DOMAIN_NAME in your browser

6. Review Security Settings:
   - Change default passwords if needed
   - Configure firewall rules
   - Set up regular backups

═══════════════════════════════════════════════════════════════════════════════
TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════

If you encounter issues:

1. Check service status:
   mikrotik-vpn status

2. View logs:
   mikrotik-vpn
   Then select: Monitoring & Logs > View live logs

3. Run health check:
   mikrotik-vpn health

4. Check Docker containers:
   docker ps -a

5. Review system logs:
   journalctl -u mikrotik-vpn -f

For support, check the documentation or contact support with the installation ID:
Installation ID: $(uuidgen)

═══════════════════════════════════════════════════════════════════════════════
EOF

    # Display completion message
    clear
    cat "$report_file"
    
    # Save to log
    cat "$report_file" >> "$LOG_FILE"
    
    # Save credentials file
    cat << EOF > "$CONFIG_DIR/credentials.txt"
MikroTik VPN System Credentials
Generated: $(date)
=====================================

Domain: $DOMAIN_NAME
Admin Email: $ADMIN_EMAIL

Database Passwords:
- MongoDB Root: $MONGO_ROOT_PASSWORD
- MongoDB App: $MONGO_APP_PASSWORD
- Redis: $REDIS_PASSWORD

Application Secrets:
- JWT Secret: $JWT_SECRET
- Session Secret: $SESSION_SECRET
- API Key: $API_KEY

VPN Configuration:
- L2TP PSK: $L2TP_PSK

Monitoring:
- Grafana Password: $GRAFANA_PASSWORD

IMPORTANT: Keep this file secure!
EOF
    
    chmod 600 "$CONFIG_DIR/credentials.txt"
    
    log "Installation completed successfully!"
}

# =============================================================================
# CLEANUP AND ERROR HANDLING
# =============================================================================

# Cleanup function
cleanup() {
    log "Performing cleanup..."
    rm -rf "$TEMP_DIR"
}

# Set trap for cleanup
trap cleanup EXIT

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Initialize
    print_header
    check_root
    
    # Run installation phases
    phase0_system_detection
    phase1_configuration
    phase2_system_preparation
    phase3_docker_installation
    phase4_directory_structure
    phase5_nodejs_application
    phase6_configuration_files
    phase7_docker_compose
    phase8_management_scripts
    phase9_security_configuration
    phase10_final_setup
    
    # Success
    log "=================================================================="
    log "MikroTik VPN Management System installation completed successfully!"
    log "=================================================================="
    log ""
    log "To access the management interface, run: mikrotik-vpn"
    log ""
    
    return 0
}

# Execute main function
main "$@"
exit $?
