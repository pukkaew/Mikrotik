#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script
# Version: 5.1 - Enhanced Security and Reliability Edition
# Description: Complete installation with improved security, validation, and monitoring
# Compatible with: Ubuntu 22.04/24.04 LTS, WSL, Container environments
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

# Environment detection
IS_WSL=false
IS_CONTAINER=false
IS_SYSTEMD=false
DOCKER_START_METHOD=""
DOCKER_PID=""

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

# Enhanced secure password generation
generate_secure_password() {
    local length=${1:-16}
    local charset=${2:-'A-Za-z0-9!@#$%^&*()_+='}
    
    # Use /dev/urandom for better randomness
    if [[ -r /dev/urandom ]]; then
        tr -dc "$charset" < /dev/urandom | head -c "$length"
    else
        # Fallback to openssl
        openssl rand -base64 48 | tr -dc "$charset" | head -c "$length"
    fi
}

# Enhanced domain validation
validate_domain() {
    local domain=$1
    
    # Check length
    if [[ ${#domain} -gt 253 ]]; then
        log_error "Domain name too long (max 253 characters)"
        return 1
    fi
    
    # Check format and TLD
    if [[ ! $domain =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid domain format"
        return 1
    fi
    
    # Check for double dots
    if [[ $domain == *..* ]]; then
        log_error "Domain contains consecutive dots"
        return 1
    fi
    
    # Check each label length
    IFS='.' read -ra LABELS <<< "$domain"
    for label in "${LABELS[@]}"; do
        if [[ ${#label} -gt 63 ]]; then
            log_error "Domain label too long (max 63 characters): $label"
            return 1
        fi
    done
    
    return 0
}

# Check network conflicts
check_network_conflicts() {
    local vpn_network=$1
    
    log "Checking for network conflicts..."
    
    # Check existing Docker networks
    if command -v docker &> /dev/null && docker ps &>/dev/null; then
        local docker_networks=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)
        
        for net in $docker_networks; do
            if [[ "$net" == "$vpn_network" ]]; then
                log_error "VPN network conflicts with Docker network: $net"
                return 1
            fi
        done
    fi
    
    # Check host network interfaces
    local host_networks=$(ip route show | grep -v default | awk '{print $1}' | grep '/' 2>/dev/null || true)
    
    for net in $host_networks; do
        if [[ "$net" == "$vpn_network" ]]; then
            log_error "VPN network conflicts with host network: $net"
            return 1
        fi
    done
    
    log "No network conflicts detected"
    return 0
}

# Monitor system resources
monitor_resources() {
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    # Memory usage
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local mem_used=$(free -m | awk '/^Mem:/{print $3}')
    local mem_percent=$((mem_used * 100 / mem_total))
    
    # Disk usage
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    # Alert if resources are high
    if [[ ${cpu_usage%.*} -gt 80 ]]; then
        log_warning "High CPU usage detected: ${cpu_usage}%"
    fi
    
    if [[ $mem_percent -gt 85 ]]; then
        log_warning "High memory usage detected: ${mem_percent}% (${mem_used}MB / ${mem_total}MB)"
    fi
    
    if [[ $disk_usage -gt 85 ]]; then
        log_warning "High disk usage detected: ${disk_usage}%"
    fi
}

# Error handler
error_handler() {
    local line_number=$1
    log_error "Script failed at line $line_number"
    log_error "Last command: $BASH_COMMAND"
    
    # Save error state
    echo "Error at line $line_number: $BASH_COMMAND" > "$TEMP_DIR/error_state.txt"
    
    cleanup_on_error
    exit 1
}

trap 'error_handler $LINENO' ERR

# Cleanup on error
cleanup_on_error() {
    log_warning "Cleaning up after error..."
    cd /
    
    # Save logs before cleanup
    if [[ -f "$LOG_FILE" ]]; then
        cp "$LOG_FILE" "/tmp/mikrotik-vpn-install-error-$(date +%Y%m%d_%H%M%S).log"
        log_info "Error log saved to: /tmp/mikrotik-vpn-install-error-$(date +%Y%m%d_%H%M%S).log"
    fi
    
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    
    # Kill any manually started Docker daemon
    if [[ -n "${DOCKER_PID:-}" ]]; then
        kill $DOCKER_PID 2>/dev/null || true
    fi
}

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect environment with improved checks
detect_environment() {
    log "Detecting system environment..."
    
    # Check if running in WSL
    if grep -qi microsoft /proc/version 2>/dev/null; then
        IS_WSL=true
        log_warning "WSL environment detected"
        
        # Check WSL version
        if [[ -f /proc/sys/fs/binfmt_misc/WSLInterop ]]; then
            log_info "WSL2 detected"
        else
            log_info "WSL1 detected"
        fi
    fi
    
    # Check if running in container
    if [[ -f /.dockerenv ]] || grep -q 'docker\|lxc\|containerd' /proc/1/cgroup 2>/dev/null; then
        IS_CONTAINER=true
        log_warning "Container environment detected"
    fi
    
    # Check if systemd is available
    if systemctl is-system-running &>/dev/null; then
        IS_SYSTEMD=true
        local systemd_state=$(systemctl is-system-running)
        log "systemd is available (state: $systemd_state)"
    else
        log_warning "systemd is not available"
    fi
    
    # Determine Docker start method
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        DOCKER_START_METHOD="systemctl"
    elif command -v service &>/dev/null; then
        DOCKER_START_METHOD="service"
    else
        DOCKER_START_METHOD="manual"
    fi
    
    log "Environment: WSL=$IS_WSL, Container=$IS_CONTAINER, Systemd=$IS_SYSTEMD"
    log "Docker start method: $DOCKER_START_METHOD"
}

# Fix Docker service issues
fix_docker_service() {
    log "Fixing Docker service issues..."
    
    # Stop Docker and related services
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        systemctl stop docker docker.socket containerd 2>/dev/null || true
    else
        service docker stop 2>/dev/null || true
        pkill -f dockerd 2>/dev/null || true
    fi
    
    # Clean up Docker artifacts
    rm -rf /var/run/docker.sock /var/run/docker.pid /var/run/docker/ 2>/dev/null || true
    rm -rf /var/lib/docker/network/files/local-kv.db 2>/dev/null || true
    
    # Fix iptables for WSL/Container
    if [[ "$IS_WSL" == "true" ]] || [[ "$IS_CONTAINER" == "true" ]]; then
        if [[ -f /usr/sbin/iptables-legacy ]]; then
            update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
            update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
        fi
    fi
    
    # Load required kernel modules
    for module in overlay br_netfilter ip_tables iptable_filter iptable_nat nf_nat nf_conntrack; do
        if ! lsmod | grep -q "^$module"; then
            modprobe $module 2>/dev/null || log_warning "Could not load module $module"
        fi
    done
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    
    # Create Docker daemon configuration
    mkdir -p /etc/docker
    
    if [[ "$IS_WSL" == "true" ]] || [[ "$IS_CONTAINER" == "true" ]]; then
        # Special config for WSL/Container
        cat << 'EOF' > /etc/docker/daemon.json
{
  "storage-driver": "overlay2",
  "storage-opts": ["overlay2.override_kernel_check=true"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "labels": "production_status,service_name",
    "env": "os,customer"
  },
  "iptables": false,
  "bridge": "none",
  "dns": ["8.8.8.8", "8.8.4.4"],
  "debug": false,
  "experimental": false
}
EOF
    else
        # Standard config with performance optimizations
        cat << 'EOF' > /etc/docker/daemon.json
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "labels": "production_status,service_name",
    "env": "os,customer"
  },
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
  "ipv6": false,
  "debug": false,
  "experimental": false,
  "metrics-addr": "127.0.0.1:9323",
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 10,
  "default-runtime": "runc",
  "shutdown-timeout": 15
}
EOF
    fi
    
    # Ensure systemd knows about changes
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        systemctl daemon-reload
    fi
    
    sleep 2
}

# Start Docker service with appropriate method
start_docker_service() {
    log "Starting Docker service..."
    
    case "$DOCKER_START_METHOD" in
        "systemctl")
            systemctl enable docker 2>/dev/null || true
            systemctl start docker || {
                log_warning "systemctl start failed, trying manual start"
                DOCKER_START_METHOD="manual"
                start_docker_manual
            }
            ;;
        "service")
            service docker start || {
                log_warning "service start failed, trying manual start"
                DOCKER_START_METHOD="manual"
                start_docker_manual
            }
            ;;
        "manual")
            start_docker_manual
            ;;
    esac
    
    # Wait for Docker to be ready with extended timeout
    local count=0
    while [[ $count -lt 60 ]]; do
        if docker version &>/dev/null; then
            log "Docker is running successfully"
            docker version
            return 0
        fi
        sleep 1
        count=$((count + 1))
        
        # Show progress
        if [[ $((count % 10)) -eq 0 ]]; then
            log_info "Waiting for Docker to start... ${count}s"
        fi
    done
    
    log_error "Docker failed to start after 60 seconds"
    return 1
}

start_docker_manual() {
    log "Starting Docker daemon manually..."
    
    # Kill any existing dockerd
    pkill -f dockerd 2>/dev/null || true
    sleep 2
    
    # Start dockerd in background
    if [[ "$IS_WSL" == "true" ]] || [[ "$IS_CONTAINER" == "true" ]]; then
        dockerd --iptables=false > /var/log/docker-manual.log 2>&1 &
    else
        dockerd > /var/log/docker-manual.log 2>&1 &
    fi
    DOCKER_PID=$!
    
    log "Docker daemon started with PID: $DOCKER_PID"
    echo $DOCKER_PID > /var/run/docker-manual.pid
}

# Create or check docker network with validation
create_docker_network() {
    if ! docker network ls --format '{{.Name}}' | grep -q "^mikrotik-vpn-net$"; then
        log "Creating Docker network..."
        
        # Validate network doesn't conflict
        if ! check_network_conflicts "172.20.0.0/16"; then
            log_error "Network conflict detected, using alternative network"
            # Try alternative networks
            for net in "172.21.0.0/16" "172.22.0.0/16" "172.23.0.0/16"; do
                if check_network_conflicts "$net"; then
                    docker network create mikrotik-vpn-net --driver bridge --subnet="$net"
                    log "Docker network created with subnet: $net"
                    return 0
                fi
            done
            log_error "No suitable network range available"
            return 1
        fi
        
        if [[ "$IS_WSL" == "true" ]] || [[ "$IS_CONTAINER" == "true" ]]; then
            docker network create mikrotik-vpn-net --driver bridge
        else
            docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
        fi
    else
        log "Docker network already exists"
        # Verify network is healthy
        docker network inspect mikrotik-vpn-net >/dev/null 2>&1 || {
            log_warning "Docker network exists but is not healthy, recreating..."
            docker network rm mikrotik-vpn-net 2>/dev/null || true
            create_docker_network
        }
    fi
}

# Print header
print_header() {
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║        MikroTik VPN Management System - Installation v5.1                 ║
║                                                                           ║
║                 Enhanced Security & Reliability Edition                   ║
║                         All Fixes Applied Edition                         ║
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
    
    # Detect environment
    detect_environment
    
    # Check system resources
    CPU_CORES=$(nproc)
    TOTAL_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    # Monitor current resource usage
    monitor_resources
    
    log "System Resources:"
    log "  CPU Cores: $CPU_CORES"
    log "  Total Memory: ${TOTAL_MEM}MB"
    log "  Available Disk: ${TOTAL_DISK}GB"
    log "  MongoDB Cache Size: ${MONGODB_CACHE_SIZE}GB"
    log "  Redis Max Memory: ${REDIS_MAX_MEM}MB"
    
    # Check minimum requirements
    if [[ $TOTAL_MEM -lt 2048 ]]; then
        log_warning "System has less than 2GB RAM. Performance may be affected."
        read -p "Continue anyway? (y/n): " continue_low_mem
        if [[ ! $continue_low_mem =~ ^[Yy]$ ]]; then
            log "Installation cancelled due to low memory"
            exit 1
        fi
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

# Enhanced backup existing installation with verification
backup_existing_installation() {
    local backup_name="backup-$(date +%Y%m%d_%H%M%S)"
    local backup_path="/root/mikrotik-vpn-backups/$backup_name"
    
    mkdir -p "$backup_path"
    
    if [[ -f "$CONFIG_DIR/setup.env" ]]; then
        cp -r "$CONFIG_DIR" "$backup_path/" 2>/dev/null || true
        
        # Backup databases if containers are running
        if docker ps | grep -q mikrotik-mongodb; then
            log "Backing up MongoDB data..."
            docker exec mikrotik-mongodb mongodump \
                --archive="/tmp/mongodb-backup-emergency.gz" \
                --gzip 2>/dev/null || true
            docker cp mikrotik-mongodb:/tmp/mongodb-backup-emergency.gz \
                "$backup_path/" 2>/dev/null || true
        fi
        
        # Create backup manifest
        cat << EOF > "$backup_path/manifest.txt"
Backup Date: $(date)
System Version: 5.1
Domain: ${DOMAIN_NAME:-unknown}
Backup Type: Emergency (before reinstall)
EOF
        
        log "Configuration backed up to: $backup_path"
    fi
}

# Stop all services
stop_all_services() {
    log "Stopping all existing services..."
    
    # Stop systemd service
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        systemctl stop mikrotik-vpn 2>/dev/null || true
        systemctl disable mikrotik-vpn 2>/dev/null || true
    fi
    
    # Stop Docker containers
    if command -v docker &> /dev/null && docker ps &>/dev/null; then
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
    
    # Domain name with enhanced validation
    while true; do
        read -p "Enter domain name (e.g., vpn.company.com): " DOMAIN_NAME
        if validate_domain "$DOMAIN_NAME"; then
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
    while true; do
        read -p "Enter SSH port (default 22): " SSH_PORT
        SSH_PORT=${SSH_PORT:-22}
        
        # Validate port number
        if [[ $SSH_PORT =~ ^[0-9]+$ ]] && [[ $SSH_PORT -ge 1 ]] && [[ $SSH_PORT -le 65535 ]]; then
            # Check if port is already in use
            if ss -tlpn | grep -q ":$SSH_PORT "; then
                log_warning "Port $SSH_PORT is already in use"
                read -p "Use this port anyway? (y/n): " use_port
                if [[ $use_port =~ ^[Yy]$ ]]; then
                    break
                fi
            else
                break
            fi
        else
            echo "Invalid port number. Please enter a number between 1 and 65535."
        fi
    done
    
    # VPN Network configuration
    while true; do
        read -p "Enter VPN network (default 10.8.0.0/24): " VPN_NETWORK
        VPN_NETWORK=${VPN_NETWORK:-10.8.0.0/24}
        
        # Validate network format
        if [[ $VPN_NETWORK =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            # Check for conflicts
            if check_network_conflicts "$VPN_NETWORK"; then
                break
            else
                echo "Network conflicts detected. Please choose a different network."
            fi
        else
            echo "Invalid network format. Use CIDR notation (e.g., 10.8.0.0/24)"
        fi
    done
    
    # Other configurations
    TIMEZONE="Asia/Bangkok"
    
    # Generate secure passwords with enhanced security
    log "Generating secure passwords..."
    MONGO_ROOT_PASSWORD=$(generate_secure_password 20)
    MONGO_APP_PASSWORD=$(generate_secure_password 18)
    REDIS_PASSWORD=$(generate_secure_password 16)
    JWT_SECRET=$(generate_secure_password 32)
    SESSION_SECRET=$(generate_secure_password 32)
    API_KEY=$(generate_secure_password 32)
    L2TP_PSK=$(generate_secure_password 32)
    GRAFANA_PASSWORD=$(generate_secure_password 16)
    
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
    echo "Security: Enhanced passwords generated"
    echo "Monitoring: Resource monitoring enabled"
    echo
    
    read -p "Proceed with installation? (y/n): " proceed
    if [[ ! $proceed =~ ^[Yy]$ ]]; then
        log "Installation cancelled by user"
        exit 0
    fi
    
    log "Phase 1 completed successfully!"
}

# Save configuration with validation
save_configuration() {
    mkdir -p "$CONFIG_DIR"
    
    # Validate all variables before saving
    local required_vars=(
        "DOMAIN_NAME" "ADMIN_EMAIL" "SSH_PORT" "TIMEZONE" "VPN_NETWORK"
        "MONGO_ROOT_PASSWORD" "MONGO_APP_PASSWORD" "REDIS_PASSWORD"
        "JWT_SECRET" "SESSION_SECRET" "API_KEY" "L2TP_PSK" "GRAFANA_PASSWORD"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            log_error "Required variable $var is not set"
            return 1
        fi
    done
    
    cat << EOF > "$CONFIG_DIR/setup.env"
# MikroTik VPN System Configuration
# Generated: $(date)
# Version: 5.1

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

# Environment
export IS_WSL="$IS_WSL"
export IS_CONTAINER="$IS_CONTAINER"
export IS_SYSTEMD="$IS_SYSTEMD"
export DOCKER_START_METHOD="$DOCKER_START_METHOD"

# Installation Info
export INSTALL_DATE="$(date)"
export INSTALL_VERSION="5.1"
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
VPN_NETWORK=$VPN_NETWORK
EOF
    
    chmod 600 "$SYSTEM_DIR/.env"
    
    # Create configuration backup
    cp "$CONFIG_DIR/setup.env" "$CONFIG_DIR/setup.env.$(date +%Y%m%d_%H%M%S).backup"
    
    log "Configuration saved and backed up"
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
    timedatectl set-timezone "$TIMEZONE" 2>/dev/null || ln -sf /usr/share/zoneinfo/$TIMEZONE /etc/localtime
    
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
        iptables \
        sysstat \
        iotop \
        ncdu
    
    # Create system user
    log "Creating system user..."
    if ! id -u mikrotik-vpn &>/dev/null; then
        useradd -r -m -s /bin/bash -d /home/mikrotik-vpn mikrotik-vpn
        usermod -aG sudo mikrotik-vpn 2>/dev/null || true
        
        # Set secure password for the user
        echo "mikrotik-vpn:$(generate_secure_password 20)" | chpasswd
    fi
    
    # Apply system optimizations
    log "Applying system optimizations..."
    apply_system_optimizations
    
    # Monitor resources after preparation
    monitor_resources
    
    log "Phase 2 completed successfully!"
}

# Apply system optimizations with enhanced settings
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
br_netfilter
overlay
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
net.core.somaxconn = 4096

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

# TCP Optimization
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# Memory Tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
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
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60
EOF
        sysctl -p /etc/sysctl.d/99-mikrotik-vpn-conntrack.conf 2>/dev/null || \
            log_warning "Connection tracking settings not applied (not critical)"
    else
        log_info "Connection tracking not available - skipping (system will work normally)"
    fi
    
    # Tune scheduler (if available)
    if [[ -f /sys/block/sda/queue/scheduler ]]; then
        echo noop > /sys/block/sda/queue/scheduler 2>/dev/null || true
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
    
    # Check if Docker is already installed and running
    if command -v docker &> /dev/null && docker ps &>/dev/null; then
        log "Docker is already installed and running"
        docker --version
        docker compose version
        create_docker_network
        log "Phase 3 completed successfully!"
        return 0
    fi
    
    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        log "Installing Docker..."
        
        # Remove old packages
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Add Docker GPG key
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        
        # Add Docker repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            docker-ce \
            docker-ce-cli \
            containerd.io \
            docker-buildx-plugin \
            docker-compose-plugin
    fi
    
    # Fix Docker configuration
    fix_docker_service
    
    # Start Docker
    start_docker_service
    
    # Verify Docker is working
    log "Verifying Docker installation..."
    if docker run --rm hello-world &>/dev/null; then
        log "Docker is working correctly"
    else
        log_error "Docker test failed"
        exit 1
    fi
    
    # Add users to docker group
    usermod -aG docker mikrotik-vpn 2>/dev/null || true
    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG docker "$SUDO_USER"
    fi
    
    # Create Docker network
    create_docker_network
    
    # Show versions
    docker --version
    docker compose version
    
    # Check Docker daemon configuration
    if docker system info | grep -q "WARNING"; then
        log_warning "Docker has some warnings:"
        docker system info | grep "WARNING"
    fi
    
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
        "$SYSTEM_DIR/app/tests"
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
        "$SYSTEM_DIR/monitoring/exporters"
        "$SYSTEM_DIR/clients"
        "$SYSTEM_DIR/data"
        "$SYSTEM_DIR/ssl"
        "$SYSTEM_DIR/tmp"
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
    chmod 1777 "$SYSTEM_DIR/tmp"
    
    # Create .gitignore files
    cat << 'EOF' > "$SYSTEM_DIR/.gitignore"
# Dependencies
node_modules/
vendor/

# Logs
*.log
logs/

# Environment files
.env
.env.*

# Data
mongodb/data/
redis/data/
clients/*.ovpn
ssl/*
!ssl/.gitkeep

# Backups
backups/
*.backup
*.gz
*.tar

# Temporary files
tmp/
*.tmp
*.temp
.DS_Store
EOF
    
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
    
    # Create package.json with updated dependencies
    cat << 'EOF' > "$SYSTEM_DIR/app/package.json"
{
  "name": "mikrotik-vpn-management",
  "version": "5.1.0",
  "description": "MikroTik VPN-based Hotspot Management System",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix"
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
    "express-validator": "^7.0.1",
    "express-mongo-sanitize": "^2.2.0",
    "hpp": "^0.2.3",
    "xss": "^1.0.14"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "eslint": "^8.48.0",
    "jest": "^29.6.4",
    "supertest": "^6.3.3",
    "@types/node": "^20.5.0"
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
    
    # Create main server file with enhanced retry logic and monitoring
    create_enhanced_server_js
    
    # Create route files
    create_route_files
    
    # Create model files
    create_model_files
    
    # Create middleware files
    create_enhanced_middleware_files
    
    # Create utility files
    create_enhanced_utility_files
    
    # Create configuration files
    create_app_config_files
    
    # Create test files
    create_test_files
    
    # Create Dockerfile
    create_app_dockerfile
    
    # Set permissions
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/app"
    
    log "Phase 5 completed successfully!"
}

# Create enhanced server.js with better error handling and monitoring
create_enhanced_server_js() {
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
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xss = require('xss');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '.env') });

// Initialize Express app
const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// Configure logger with enhanced formatting
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.json()
    ),
    defaultMeta: { service: 'mikrotik-vpn' },
    transports: [
        new winston.transports.File({ 
            filename: '/var/log/mikrotik-vpn/error.log', 
            level: 'error',
            maxsize: 10485760,
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
    // Give time to log before exit
    setTimeout(() => {
        process.exit(1);
    }, 1000);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Enhanced MongoDB connection with retry logic and monitoring
let mongoConnectionAttempts = 0;
const maxMongoRetries = 30;

const connectMongoDB = async () => {
    while (mongoConnectionAttempts < maxMongoRetries) {
        try {
            mongoConnectionAttempts++;
            
            const mongoUri = process.env.MONGODB_URI || 
                `mongodb://mikrotik_app:${process.env.MONGO_APP_PASSWORD}@mongodb:27017/mikrotik_vpn?authSource=mikrotik_vpn`;
            
            await mongoose.connect(mongoUri, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000,
                maxPoolSize: 100,
                minPoolSize: 10,
                maxIdleTimeMS: 10000,
                compressors: ['zlib'],
                retryWrites: true,
                w: 'majority',
                readPreference: 'primaryPreferred'
            });
            
            logger.info('MongoDB connected successfully');
            
            // MongoDB connection event handlers
            mongoose.connection.on('error', (err) => {
                logger.error('MongoDB connection error:', err);
            });
            
            mongoose.connection.on('disconnected', () => {
                logger.warn('MongoDB disconnected, attempting to reconnect...');
                setTimeout(connectMongoDB, 5000);
            });
            
            mongoose.connection.on('reconnected', () => {
                logger.info('MongoDB reconnected');
            });
            
            // Monitor MongoDB performance
            setInterval(async () => {
                try {
                    const adminDb = mongoose.connection.db.admin();
                    const serverStatus = await adminDb.serverStatus();
                    
                    if (serverStatus.connections.current > 500) {
                        logger.warn('High MongoDB connections:', serverStatus.connections.current);
                    }
                    
                    if (serverStatus.mem && serverStatus.mem.resident > 4096) {
                        logger.warn('High MongoDB memory usage:', serverStatus.mem.resident, 'MB');
                    }
                } catch (err) {
                    logger.error('MongoDB monitoring error:', err);
                }
            }, 60000); // Check every minute
            
            return;
        } catch (error) {
            logger.error(`MongoDB connection attempt ${mongoConnectionAttempts} failed:`, error.message);
            
            if (mongoConnectionAttempts < maxMongoRetries) {
                const backoffTime = Math.min(5000 * mongoConnectionAttempts, 30000);
                logger.info(`Retrying MongoDB connection in ${backoffTime/1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, backoffTime));
            } else {
                throw new Error('Failed to connect to MongoDB after ' + maxMongoRetries + ' attempts');
            }
        }
    }
};

// Enhanced Redis connection with retry logic
let redisClient;
let redisConnectionAttempts = 0;
const maxRedisRetries = 30;

const connectRedis = async () => {
    while (redisConnectionAttempts < maxRedisRetries) {
        try {
            redisConnectionAttempts++;
            
            redisClient = redis.createClient({
                socket: {
                    host: process.env.REDIS_HOST || 'redis',
                    port: process.env.REDIS_PORT || 6379,
                    reconnectStrategy: (retries) => {
                        if (retries > 10) {
                            logger.error('Redis reconnection limit reached');
                            return new Error('Too many retries');
                        }
                        const delay = Math.min(retries * 100, 3000);
                        logger.info(`Redis reconnecting in ${delay}ms...`);
                        return delay;
                    }
                },
                password: process.env.REDIS_PASSWORD,
                database: 0,
                commandsQueueMaxLength: 1000
            });
            
            // Redis event handlers
            redisClient.on('error', (err) => {
                logger.error('Redis Client Error:', err);
            });
            
            redisClient.on('connect', () => {
                logger.info('Redis client connected');
            });
            
            redisClient.on('ready', () => {
                logger.info('Redis client ready');
            });
            
            redisClient.on('reconnecting', () => {
                logger.info('Redis client reconnecting');
            });
            
            await redisClient.connect();
            
            // Make redis client available globally
            app.locals.redis = redisClient;
            global.redisClient = redisClient;
            
            // Monitor Redis performance
            setInterval(async () => {
                try {
                    const info = await redisClient.info('memory');
                    const memoryUsed = parseInt(info.match(/used_memory:(\d+)/)[1]);
                    const memoryLimit = parseInt(process.env.REDIS_MAX_MEM) * 1024 * 1024;
                    
                    if (memoryUsed > memoryLimit * 0.9) {
                        logger.warn('Redis memory usage high:', (memoryUsed / 1024 / 1024).toFixed(2), 'MB');
                    }
                } catch (err) {
                    logger.error('Redis monitoring error:', err);
                }
            }, 60000); // Check every minute
            
            return;
        } catch (error) {
            logger.error(`Redis connection attempt ${redisConnectionAttempts} failed:`, error.message);
            
            if (redisConnectionAttempts < maxRedisRetries) {
                const backoffTime = Math.min(5000 * redisConnectionAttempts, 30000);
                logger.info(`Retrying Redis connection in ${backoffTime/1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, backoffTime));
            } else {
                throw new Error('Failed to connect to Redis after ' + maxRedisRetries + ' attempts');
            }
        }
    }
};

// Enhanced middleware setup
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "wss:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = process.env.CORS_ORIGIN?.split(',') || ['*'];
        if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

// Security middleware
app.use(mongoSanitize()); // Prevent MongoDB injection
app.use(hpp()); // Prevent HTTP Parameter Pollution

// Body parsing with limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression
app.use(compression());

// Request logging with custom format
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    },
    skip: (req, res) => res.statusCode < 400 // Only log errors
}));

// Session configuration with Redis store
const RedisStore = require('connect-redis').default;
app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET || 'default-secret-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict'
    },
    name: 'sessionId' // Change default session name
}));

// Static files with cache control
app.use('/static', express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache');
        }
    }
}));

// API Documentation
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'MikroTik VPN Management API',
            version: '5.1.0',
            description: 'Comprehensive API for MikroTik VPN-based Hotspot Management',
            contact: {
                name: 'API Support',
                email: process.env.ADMIN_EMAIL
            }
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
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                },
                apiKey: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'X-API-Key'
                }
            }
        },
        security: [{
            bearerAuth: [],
            apiKey: []
        }]
    },
    apis: ['./routes/*.js', './models/*.js'],
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: "MikroTik VPN API Documentation"
}));

// Enhanced health check endpoint
app.get('/health', async (req, res) => {
    try {
        const healthCheck = {
            status: 'OK',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            service: 'mikrotik-vpn-api',
            version: '5.1.0',
            environment: process.env.NODE_ENV,
            checks: {
                mongodb: {
                    status: mongoose.connection.readyState === 1 ? 'healthy' : 'unhealthy',
                    connections: mongoose.connections.length,
                    readyState: mongoose.connection.readyState
                },
                redis: {
                    status: redisClient && redisClient.isOpen ? 'healthy' : 'unhealthy',
                    connected: redisClient?.isOpen || false
                },
                memory: {
                    usage: process.memoryUsage(),
                    percentUsed: (process.memoryUsage().heapUsed / process.memoryUsage().heapTotal * 100).toFixed(2) + '%'
                },
                cpu: process.cpuUsage()
            }
        };
        
        // Additional health checks
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.db.admin().ping();
        } else {
            healthCheck.checks.mongodb.status = 'unhealthy';
            healthCheck.status = 'DEGRADED';
        }
        
        if (redisClient && redisClient.isOpen) {
            await redisClient.ping();
        } else {
            healthCheck.checks.redis.status = 'unhealthy';
            healthCheck.status = 'DEGRADED';
        }
        
        const statusCode = healthCheck.status === 'OK' ? 200 : 503;
        res.status(statusCode).json(healthCheck);
    } catch (error) {
        res.status(503).json({
            status: 'ERROR',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Enhanced metrics endpoint for Prometheus
app.get('/metrics', async (req, res) => {
    const metrics = [];
    
    // Basic metrics
    metrics.push(`# HELP app_info Application information`);
    metrics.push(`# TYPE app_info gauge`);
    metrics.push(`app_info{version="5.1.0",node_version="${process.version}"} 1`);
    
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
    
    // CPU metrics
    const cpuUsage = process.cpuUsage();
    metrics.push(`# HELP app_cpu_usage_microseconds CPU usage in microseconds`);
    metrics.push(`# TYPE app_cpu_usage_microseconds counter`);
    metrics.push(`app_cpu_usage_microseconds{type="user"} ${cpuUsage.user}`);
    metrics.push(`app_cpu_usage_microseconds{type="system"} ${cpuUsage.system}`);
    
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
    
    // Event loop lag (if available)
    if (global.eventLoopLag) {
        metrics.push(`# HELP app_event_loop_lag_ms Event loop lag in milliseconds`);
        metrics.push(`# TYPE app_event_loop_lag_ms gauge`);
        metrics.push(`app_event_loop_lag_ms ${global.eventLoopLag}`);
    }
    
    res.set('Content-Type', 'text/plain; version=0.0.4');
    res.send(metrics.join('\n') + '\n');
});

// API version endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'MikroTik VPN Management API',
        version: '5.1.0',
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
        },
        features: {
            websocket: true,
            api_version: 'v1',
            rate_limiting: true,
            authentication: 'JWT',
            monitoring: 'Prometheus'
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

// Socket.IO for real-time features with authentication
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication required'));
        }
        
        // Verify JWT token
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.userId = decoded._id;
        socket.organizationId = decoded.organizationId;
        
        next();
    } catch (err) {
        next(new Error('Authentication failed'));
    }
});

io.on('connection', (socket) => {
    logger.info(`Socket connected: ${socket.id} (User: ${socket.userId})`);
    
    // Join organization room
    socket.on('join:organization', (organizationId) => {
        if (socket.organizationId === organizationId) {
            socket.join(`org:${organizationId}`);
            logger.info(`Socket ${socket.id} joined organization ${organizationId}`);
        }
    });
    
    // Join device room
    socket.on('join:device', (deviceId) => {
        socket.join(`device:${deviceId}`);
        logger.info(`Socket ${socket.id} joined device ${deviceId}`);
    });
    
    // Handle device status updates
    socket.on('device:status', async (data) => {
        try {
            // Validate data
            if (!data.deviceId || !data.organizationId) {
                socket.emit('error', { message: 'Invalid data' });
                return;
            }
            
            // Broadcast to organization
            io.to(`org:${data.organizationId}`).emit('device:status:update', data);
            
            // Log status update
            logger.info(`Device status update: ${data.deviceId}`);
        } catch (error) {
            logger.error('Socket error:', error);
            socket.emit('error', { message: 'Internal server error' });
        }
    });
    
    // Handle disconnection
    socket.on('disconnect', (reason) => {
        logger.info(`Socket disconnected: ${socket.id} (Reason: ${reason})`);
    });
    
    // Handle errors
    socket.on('error', (error) => {
        logger.error(`Socket error for ${socket.id}:`, error);
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
    // Log error
    logger.error({
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        user: req.user?.id
    });
    
    // Handle specific error types
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Validation Error',
            message: err.message,
            details: err.errors
        });
    }
    
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Authentication required'
        });
    }
    
    if (err.name === 'CastError') {
        return res.status(400).json({
            error: 'Invalid ID',
            message: 'The provided ID is invalid'
        });
    }
    
    // Default error response
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

// Graceful shutdown handler
const gracefulShutdown = async (signal) => {
    logger.info(`Received ${signal}, starting graceful shutdown...`);
    
    // Set shutdown flag
    app.locals.isShuttingDown = true;
    
    // Stop accepting new connections
    server.close(() => {
        logger.info('HTTP server closed');
    });
    
    // Close socket.io connections
    io.close(() => {
        logger.info('Socket.IO closed');
    });
    
    try {
        // Wait for ongoing requests to complete (max 30 seconds)
        await new Promise(resolve => setTimeout(resolve, 30000));
        
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

// Monitor event loop lag
let lastCheck = Date.now();
setInterval(() => {
    const now = Date.now();
    const lag = now - lastCheck - 1000;
    global.eventLoopLag = lag;
    
    if (lag > 50) {
        logger.warn(`Event loop lag detected: ${lag}ms`);
    }
    
    lastCheck = now;
}, 1000);

// Start server
const startServer = async () => {
    try {
        // Connect to databases with retry logic
        await Promise.all([
            connectMongoDB(),
            connectRedis()
        ]);
        
        // Start listening
        const PORT = process.env.PORT || 3000;
        const HOST = '0.0.0.0';
        
        server.listen(PORT, HOST, () => {
            logger.info(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║          MikroTik VPN Management System v5.1                  ║
║                                                               ║
║  Server running at: http://${HOST}:${PORT}                        ║
║  Environment: ${process.env.NODE_ENV || 'development'}                               ║
║  Process ID: ${process.pid}                                        ║
║  Node Version: ${process.version}                                    ║
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

# Create enhanced middleware files with security features
create_enhanced_middleware_files() {
    # Authentication middleware with rate limiting
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/auth.js"
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const rateLimit = require('express-rate-limit');

// Token verification with caching
const tokenCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

const verifyToken = async (token) => {
    // Check cache first
    const cached = tokenCache.get(token);
    if (cached && cached.expires > Date.now()) {
        return cached.data;
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Cache the result
    tokenCache.set(token, {
        data: decoded,
        expires: Date.now() + CACHE_TTL
    });
    
    // Clean old cache entries
    if (tokenCache.size > 1000) {
        const now = Date.now();
        for (const [key, value] of tokenCache.entries()) {
            if (value.expires < now) {
                tokenCache.delete(key);
            }
        }
    }
    
    return decoded;
};

const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '') || 
                     req.header('X-Auth-Token');
        
        if (!token) {
            throw new Error();
        }
        
        const decoded = await verifyToken(token);
        
        const user = await User.findOne({ 
            _id: decoded._id, 
            isActive: true 
        }).select('-password').lean();
        
        if (!user) {
            throw new Error();
        }
        
        // Check if token is blacklisted (for logout)
        const isBlacklisted = await global.redisClient?.get(`blacklist:${token}`);
        if (isBlacklisted) {
            throw new Error('Token has been revoked');
        }
        
        req.user = user;
        req.token = token;
        req.decoded = decoded;
        
        // Add user activity tracking
        req.on('end', () => {
            User.updateOne(
                { _id: user._id },
                { lastActivity: new Date() }
            ).exec().catch(err => console.error('Activity update error:', err));
        });
        
        next();
    } catch (error) {
        res.status(401).json({ 
            error: 'Please authenticate',
            code: 'AUTH_REQUIRED'
        });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: 'Access denied. Insufficient permissions.',
                code: 'INSUFFICIENT_PERMISSIONS',
                required: roles,
                current: req.user.role
            });
        }
        next();
    };
};

// API Key authentication
const apiKeyAuth = async (req, res, next) => {
    try {
        const apiKey = req.header('X-API-Key');
        
        if (!apiKey) {
            throw new Error();
        }
        
        // Verify API key (implement your logic)
        if (apiKey !== process.env.API_KEY) {
            throw new Error();
        }
        
        req.apiKey = apiKey;
        next();
    } catch (error) {
        res.status(401).json({ 
            error: 'Invalid API key',
            code: 'INVALID_API_KEY'
        });
    }
};

// Combined auth (JWT or API Key)
const flexibleAuth = async (req, res, next) => {
    const token = req.header('Authorization');
    const apiKey = req.header('X-API-Key');
    
    if (token) {
        return auth(req, res, next);
    } else if (apiKey) {
        return apiKeyAuth(req, res, next);
    }
    
    res.status(401).json({ 
        error: 'Authentication required',
        code: 'NO_AUTH_PROVIDED'
    });
};

// Rate limiting for auth endpoints
const authRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per window
    message: 'Too many authentication attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            error: 'Too many requests',
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: req.rateLimit.resetTime
        });
    }
});

module.exports = { 
    auth, 
    authorize, 
    apiKeyAuth, 
    flexibleAuth,
    authRateLimit,
    verifyToken
};
EOF

    # Enhanced rate limiting middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/rateLimiter.js"
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

// Create rate limiter with Redis store
const createLimiter = (options = {}) => {
    const defaults = {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: 'Too many requests from this IP, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        // Redis store for distributed rate limiting
        store: new RedisStore({
            client: global.redisClient,
            prefix: 'rl:',
        }),
        // Custom key generator
        keyGenerator: (req) => {
            return req.ip + ':' + (req.user?.id || 'anonymous');
        },
        skip: (req) => {
            // Skip rate limiting for certain conditions
            if (req.user?.role === 'superadmin') {
                return true;
            }
            return false;
        }
    };
    
    return rateLimit({ ...defaults, ...options });
};

// Different limiters for different endpoints
const loginLimiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.',
    skipSuccessfulRequests: true
});

const apiLimiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 100
});

const strictLimiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Rate limit exceeded for this operation'
});

// Heavy operation limiter
const heavyLimiter = createLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,
    message: 'Too many heavy operations, please try again later'
});

// Dynamic rate limiter based on user tier
const dynamicLimiter = (req, res, next) => {
    const limits = {
        free: 50,
        basic: 200,
        pro: 500,
        enterprise: 1000
    };
    
    const userTier = req.user?.subscription?.plan || 'free';
    const maxRequests = limits[userTier] || limits.free;
    
    const limiter = createLimiter({
        max: maxRequests,
        message: `Rate limit exceeded for ${userTier} plan. Upgrade for higher limits.`
    });
    
    limiter(req, res, next);
};

module.exports = {
    createLimiter,
    loginLimiter,
    apiLimiter,
    strictLimiter,
    heavyLimiter,
    dynamicLimiter
};
EOF

    # Enhanced validation middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/validation.js"
const { validationResult } = require('express-validator');
const xss = require('xss');

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        // Format errors for better readability
        const formattedErrors = errors.array().map(err => ({
            field: err.param,
            message: err.msg,
            value: err.value,
            location: err.location
        }));
        
        return res.status(400).json({
            success: false,
            error: 'Validation failed',
            errors: formattedErrors
        });
    }
    
    next();
};

// Sanitize input middleware
const sanitizeInput = (req, res, next) => {
    // Sanitize body
    if (req.body) {
        req.body = sanitizeObject(req.body);
    }
    
    // Sanitize query
    if (req.query) {
        req.query = sanitizeObject(req.query);
    }
    
    // Sanitize params
    if (req.params) {
        req.params = sanitizeObject(req.params);
    }
    
    next();
};

// Recursive object sanitization
const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) {
        return typeof obj === 'string' ? xss(obj) : obj;
    }
    
    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item));
    }
    
    const sanitized = {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            // Skip certain fields from sanitization
            if (['password', 'token', 'secret'].includes(key.toLowerCase())) {
                sanitized[key] = obj[key];
            } else {
                sanitized[key] = sanitizeObject(obj[key]);
            }
        }
    }
    
    return sanitized;
};

// Request size limiter
const requestSizeLimiter = (maxSize = '10mb') => {
    return (req, res, next) => {
        const contentLength = req.headers['content-length'];
        const maxBytes = parseSize(maxSize);
        
        if (contentLength && parseInt(contentLength) > maxBytes) {
            return res.status(413).json({
                error: 'Request entity too large',
                maxSize: maxSize
            });
        }
        
        next();
    };
};

// Parse size string to bytes
const parseSize = (size) => {
    const units = {
        b: 1,
        kb: 1024,
        mb: 1024 * 1024,
        gb: 1024 * 1024 * 1024
    };
    
    const match = size.toLowerCase().match(/^(\d+)([a-z]+)$/);
    if (!match) return parseInt(size);
    
    const [, num, unit] = match;
    return parseInt(num) * (units[unit] || 1);
};

module.exports = { 
    handleValidationErrors,
    sanitizeInput,
    requestSizeLimiter
};
EOF

    # Request ID middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/requestId.js"
const { v4: uuidv4 } = require('uuid');

const requestId = (req, res, next) => {
    // Get or generate request ID
    const id = req.headers['x-request-id'] || uuidv4();
    
    // Attach to request and response
    req.id = id;
    res.setHeader('X-Request-ID', id);
    
    // Add to logging context
    req.log = {
        info: (message, meta = {}) => {
            console.log(JSON.stringify({
                level: 'info',
                message,
                requestId: id,
                timestamp: new Date().toISOString(),
                ...meta
            }));
        },
        error: (message, error, meta = {}) => {
            console.error(JSON.stringify({
                level: 'error',
                message,
                error: error.message,
                stack: error.stack,
                requestId: id,
                timestamp: new Date().toISOString(),
                ...meta
            }));
        }
    };
    
    next();
};

module.exports = requestId;
EOF
}

# Create enhanced utility files
create_enhanced_utility_files() {
    # Enhanced logger utility
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/logger.js"
const winston = require('winston');
const path = require('path');

// Custom format for structured logging
const structuredFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
    const log = {
        timestamp,
        level,
        message,
        ...metadata
    };
    return JSON.stringify(log);
});

// Create logger instance
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        structuredFormat
    ),
    defaultMeta: { 
        service: 'mikrotik-vpn',
        environment: process.env.NODE_ENV
    },
    transports: [
        // Error log
        new winston.transports.File({ 
            filename: path.join('/var/log/mikrotik-vpn', 'error.log'),
            level: 'error',
            maxsize: 10485760, // 10MB
            maxFiles: 5,
            tailable: true
        }),
        // Combined log
        new winston.transports.File({ 
            filename: path.join('/var/log/mikrotik-vpn', 'combined.log'),
            maxsize: 10485760, // 10MB
            maxFiles: 5,
            tailable: true
        }),
        // Audit log for security events
        new winston.transports.File({
            filename: path.join('/var/log/mikrotik-vpn', 'audit.log'),
            level: 'info',
            maxsize: 10485760,
            maxFiles: 10,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        })
    ],
    exceptionHandlers: [
        new winston.transports.File({ 
            filename: path.join('/var/log/mikrotik-vpn', 'exceptions.log')
        })
    ],
    rejectionHandlers: [
        new winston.transports.File({ 
            filename: path.join('/var/log/mikrotik-vpn', 'rejections.log')
        })
    ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

// Audit logging helper
logger.audit = (action, userId, details = {}) => {
    logger.info('AUDIT', {
        action,
        userId,
        timestamp: new Date().toISOString(),
        ip: details.ip,
        userAgent: details.userAgent,
        ...details
    });
};

// Performance logging helper
logger.performance = (operation, duration, details = {}) => {
    logger.info('PERFORMANCE', {
        operation,
        duration,
        timestamp: new Date().toISOString(),
        ...details
    });
};

module.exports = logger;
EOF

    # Enhanced email utility with templates
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/email.js"
const nodemailer = require('nodemailer');
const logger = require('./logger');
const path = require('path');
const fs = require('fs').promises;

class EmailService {
    constructor() {
        this.transporter = null;
        this.templates = new Map();
        this.initializeTransporter();
    }
    
    async initializeTransporter() {
        try {
            this.transporter = nodemailer.createTransporter({
                host: process.env.SMTP_HOST || 'smtp.gmail.com',
                port: process.env.SMTP_PORT || 587,
                secure: false,
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                },
                pool: true,
                maxConnections: 5,
                maxMessages: 100,
                rateDelta: 1000,
                rateLimit: 5
            });
            
            await this.verifyConnection();
        } catch (error) {
            logger.error('Email service initialization error:', error);
        }
    }
    
    async verifyConnection() {
        try {
            await this.transporter.verify();
            logger.info('Email service ready');
        } catch (error) {
            logger.error('Email service verification failed:', error);
        }
    }
    
    async loadTemplate(name) {
        if (this.templates.has(name)) {
            return this.templates.get(name);
        }
        
        try {
            const templatePath = path.join(__dirname, '..', 'templates', `${name}.html`);
            const template = await fs.readFile(templatePath, 'utf8');
            this.templates.set(name, template);
            return template;
        } catch (error) {
            logger.error(`Failed to load email template ${name}:`, error);
            return null;
        }
    }
    
    renderTemplate(template, variables) {
        return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
            return variables[key] || match;
        });
    }
    
    async sendEmail({ to, subject, html, text, template, variables }) {
        try {
            // Use template if provided
            if (template) {
                const templateContent = await this.loadTemplate(template);
                if (templateContent) {
                    html = this.renderTemplate(templateContent, variables || {});
                }
            }
            
            // Generate text version if not provided
            if (!text && html) {
                text = html.replace(/<[^>]*>/g, '');
            }
            
            const info = await this.transporter.sendMail({
                from: `"${process.env.FROM_NAME || 'MikroTik VPN'}" <${process.env.FROM_EMAIL || 'noreply@example.com'}>`,
                to,
                subject,
                text,
                html,
                headers: {
                    'X-Mailer': 'MikroTik VPN System',
                    'X-Priority': '3'
                }
            });
            
            logger.info(`Email sent: ${info.messageId} to ${to}`);
            return info;
        } catch (error) {
            logger.error('Email send error:', error);
            throw error;
        }
    }
    
    async sendWelcomeEmail(user) {
        return this.sendEmail({
            to: user.email,
            subject: 'Welcome to MikroTik VPN Management System',
            template: 'welcome',
            variables: {
                firstName: user.profile.firstName,
                username: user.username,
                verificationUrl: `${process.env.APP_URL}/verify/${user.verificationToken}`,
                supportEmail: process.env.ADMIN_EMAIL
            }
        });
    }
    
    async sendPasswordResetEmail(user, resetToken) {
        return this.sendEmail({
            to: user.email,
            subject: 'Password Reset Request',
            template: 'password-reset',
            variables: {
                firstName: user.profile.firstName,
                resetUrl: `${process.env.APP_URL}/reset-password/${resetToken}`,
                expiresIn: '1 hour'
            }
        });
    }
    
    async sendDeviceAlertEmail(user, device, alert) {
        return this.sendEmail({
            to: user.email,
            subject: `Device Alert: ${device.name}`,
            template: 'device-alert',
            variables: {
                firstName: user.profile.firstName,
                deviceName: device.name,
                alertType: alert.type,
                alertMessage: alert.message,
                timestamp: new Date(alert.timestamp).toLocaleString()
            }
        });
    }
    
    async sendBatchEmail(recipients, subject, template, commonVariables = {}) {
        const results = [];
        
        for (const recipient of recipients) {
            try {
                const result = await this.sendEmail({
                    to: recipient.email,
                    subject,
                    template,
                    variables: {
                        ...commonVariables,
                        ...recipient.variables
                    }
                });
                results.push({ success: true, email: recipient.email, result });
            } catch (error) {
                results.push({ success: false, email: recipient.email, error: error.message });
            }
            
            // Rate limiting
            await new Promise(resolve => setTimeout(resolve, 200));
        }
        
        return results;
    }
}

module.exports = new EmailService();
EOF

    # Enhanced QR Code utility
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/qrcode.js"
const QRCode = require('qrcode');
const logger = require('./logger');
const sharp = require('sharp');

class QRCodeService {
    constructor() {
        this.defaultOptions = {
            errorCorrectionLevel: 'M',
            type: 'image/png',
            width: 300,
            margin: 2,
            color: {
                dark: '#000000',
                light: '#FFFFFF'
            }
        };
    }
    
    async generateVoucherQR(voucher, options = {}) {
        try {
            const data = {
                type: 'voucher',
                code: voucher.code,
                url: `${process.env.APP_URL}/voucher/${voucher.code}`,
                expires: voucher.usage?.expiresAt
            };
            
            const qrOptions = { ...this.defaultOptions, ...options };
            const qrCodeDataURL = await QRCode.toDataURL(JSON.stringify(data), qrOptions);
            
            // Add logo if requested
            if (options.withLogo) {
                return await this.addLogoToQR(qrCodeDataURL);
            }
            
            return qrCodeDataURL;
        } catch (error) {
            logger.error('QR Code generation error:', error);
            throw error;
        }
    }
    
    async generateDeviceQR(device, options = {}) {
        try {
            const data = {
                type: 'device',
                id: device._id,
                serial: device.serialNumber,
                vpn: device.vpnIpAddress,
                management: `${process.env.APP_URL}/device/${device._id}`
            };
            
            const qrOptions = { ...this.defaultOptions, ...options };
            return await QRCode.toDataURL(JSON.stringify(data), qrOptions);
        } catch (error) {
            logger.error('QR Code generation error:', error);
            throw error;
        }
    }
    
    async generateWiFiQR(ssid, password, security = 'WPA', hidden = false) {
        try {
            // WiFi QR code format
            const wifiString = `WIFI:T:${security};S:${ssid};P:${password};H:${hidden};`;
            
            return await QRCode.toDataURL(wifiString, this.defaultOptions);
        } catch (error) {
            logger.error('WiFi QR Code generation error:', error);
            throw error;
        }
    }
    
    async generateBulkQR(items, type = 'voucher') {
        const results = [];
        
        for (const item of items) {
            try {
                let qrCode;
                
                switch (type) {
                    case 'voucher':
                        qrCode = await this.generateVoucherQR(item);
                        break;
                    case 'device':
                        qrCode = await this.generateDeviceQR(item);
                        break;
                    default:
                        throw new Error('Invalid QR code type');
                }
                
                results.push({
                    id: item._id || item.code,
                    qrCode,
                    success: true
                });
            } catch (error) {
                results.push({
                    id: item._id || item.code,
                    error: error.message,
                    success: false
                });
            }
        }
        
        return results;
    }
    
    async addLogoToQR(qrCodeDataURL) {
        try {
            // Convert data URL to buffer
            const qrBuffer = Buffer.from(
                qrCodeDataURL.replace(/^data:image\/png;base64,/, ''),
                'base64'
            );
            
            // Load logo
            const logoPath = path.join(__dirname, '..', 'public', 'logo.png');
            
            // Composite logo onto QR code
            const composite = await sharp(qrBuffer)
                .composite([{
                    input: logoPath,
                    gravity: 'center',
                    blend: 'over'
                }])
                .toBuffer();
            
            return `data:image/png;base64,${composite.toString('base64')}`;
        } catch (error) {
            logger.error('Error adding logo to QR code:', error);
            return qrCodeDataURL; // Return original if logo addition fails
        }
    }
    
    async generateQRSheet(qrCodes, options = {}) {
        try {
            const {
                columns = 4,
                rows = 4,
                pageWidth = 2480,  // A4 at 300 DPI
                pageHeight = 3508, // A4 at 300 DPI
                margin = 100
            } = options;
            
            const qrSize = Math.floor((pageWidth - (margin * 2)) / columns);
            const spacing = Math.floor((pageHeight - (margin * 2)) / rows);
            
            // Create blank page
            const page = sharp({
                create: {
                    width: pageWidth,
                    height: pageHeight,
                    channels: 4,
                    background: { r: 255, g: 255, b: 255, alpha: 1 }
                }
            });
            
            const composites = [];
            
            for (let i = 0; i < qrCodes.length && i < columns * rows; i++) {
                const row = Math.floor(i / columns);
                const col = i % columns;
                
                const x = margin + (col * qrSize);
                const y = margin + (row * spacing);
                
                // Convert QR code to buffer
                const qrBuffer = Buffer.from(
                    qrCodes[i].replace(/^data:image\/png;base64,/, ''),
                    'base64'
                );
                
                composites.push({
                    input: await sharp(qrBuffer)
                        .resize(qrSize - 20, qrSize - 20)
                        .toBuffer(),
                    left: x + 10,
                    top: y + 10
                });
            }
            
            const sheet = await page
                .composite(composites)
                .png()
                .toBuffer();
            
            return `data:image/png;base64,${sheet.toString('base64')}`;
        } catch (error) {
            logger.error('Error generating QR sheet:', error);
            throw error;
        }
    }
}

module.exports = new QRCodeService();
EOF

    # Monitoring utility
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/monitoring.js"
const logger = require('./logger');
const os = require('os');

class MonitoringService {
    constructor() {
        this.metrics = {
            requests: new Map(),
            errors: new Map(),
            performance: new Map()
        };
        
        // Start collecting system metrics
        this.startSystemMetricsCollection();
    }
    
    startSystemMetricsCollection() {
        setInterval(() => {
            this.collectSystemMetrics();
        }, 60000); // Every minute
    }
    
    collectSystemMetrics() {
        const metrics = {
            timestamp: new Date().toISOString(),
            cpu: {
                usage: this.getCPUUsage(),
                loadAverage: os.loadavg()
            },
            memory: {
                total: os.totalmem(),
                free: os.freemem(),
                used: os.totalmem() - os.freemem(),
                percentage: ((os.totalmem() - os.freemem()) / os.totalmem() * 100).toFixed(2)
            },
            uptime: os.uptime(),
            process: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage()
            }
        };
        
        // Log if thresholds exceeded
        if (parseFloat(metrics.memory.percentage) > 85) {
            logger.warn('High memory usage detected:', metrics.memory);
        }
        
        if (metrics.cpu.loadAverage[0] > os.cpus().length) {
            logger.warn('High CPU load detected:', metrics.cpu);
        }
        
        return metrics;
    }
    
    getCPUUsage() {
        const cpus = os.cpus();
        let user = 0;
        let nice = 0;
        let sys = 0;
        let idle = 0;
        let irq = 0;
        
        for (const cpu of cpus) {
            user += cpu.times.user;
            nice += cpu.times.nice;
            sys += cpu.times.sys;
            idle += cpu.times.idle;
            irq += cpu.times.irq;
        }
        
        const total = user + nice + sys + idle + irq;
        
        return {
            user: (100 * user / total).toFixed(2),
            nice: (100 * nice / total).toFixed(2),
            sys: (100 * sys / total).toFixed(2),
            idle: (100 * idle / total).toFixed(2),
            irq: (100 * irq / total).toFixed(2)
        };
    }
    
    recordRequest(endpoint, method, statusCode, duration) {
        const key = `${method}:${endpoint}`;
        
        if (!this.metrics.requests.has(key)) {
            this.metrics.requests.set(key, {
                count: 0,
                totalDuration: 0,
                averageDuration: 0,
                statusCodes: {}
            });
        }
        
        const metric = this.metrics.requests.get(key);
        metric.count++;
        metric.totalDuration += duration;
        metric.averageDuration = metric.totalDuration / metric.count;
        metric.statusCodes[statusCode] = (metric.statusCodes[statusCode] || 0) + 1;
        
        // Alert on slow requests
        if (duration > 5000) {
            logger.warn('Slow request detected:', {
                endpoint,
                method,
                duration,
                statusCode
            });
        }
    }
    
    recordError(error, context = {}) {
        const errorKey = error.name || 'UnknownError';
        
        if (!this.metrics.errors.has(errorKey)) {
            this.metrics.errors.set(errorKey, {
                count: 0,
                lastOccurred: null,
                contexts: []
            });
        }
        
        const metric = this.metrics.errors.get(errorKey);
        metric.count++;
        metric.lastOccurred = new Date();
        metric.contexts.push({
            timestamp: new Date(),
            message: error.message,
            stack: error.stack,
            ...context
        });
        
        // Keep only last 100 contexts
        if (metric.contexts.length > 100) {
            metric.contexts = metric.contexts.slice(-100);
        }
    }
    
    getMetrics() {
        return {
            system: this.collectSystemMetrics(),
            requests: Object.fromEntries(this.metrics.requests),
            errors: Object.fromEntries(this.metrics.errors),
            performance: Object.fromEntries(this.metrics.performance)
        };
    }
    
    reset() {
        this.metrics.requests.clear();
        this.metrics.errors.clear();
        this.metrics.performance.clear();
    }
}

module.exports = new MonitoringService();
EOF

    # Cache utility
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/cache.js"
const logger = require('./logger');

class CacheService {
    constructor(redisClient) {
        this.redis = redisClient;
        this.defaultTTL = 3600; // 1 hour
    }
    
    async get(key) {
        try {
            const value = await this.redis.get(key);
            return value ? JSON.parse(value) : null;
        } catch (error) {
            logger.error('Cache get error:', error);
            return null;
        }
    }
    
    async set(key, value, ttl = this.defaultTTL) {
        try {
            const serialized = JSON.stringify(value);
            if (ttl) {
                await this.redis.setex(key, ttl, serialized);
            } else {
                await this.redis.set(key, serialized);
            }
            return true;
        } catch (error) {
            logger.error('Cache set error:', error);
            return false;
        }
    }
    
    async del(key) {
        try {
            await this.redis.del(key);
            return true;
        } catch (error) {
            logger.error('Cache delete error:', error);
            return false;
        }
    }
    
    async flush(pattern) {
        try {
            const keys = await this.redis.keys(pattern);
            if (keys.length > 0) {
                await this.redis.del(...keys);
            }
            return keys.length;
        } catch (error) {
            logger.error('Cache flush error:', error);
            return 0;
        }
    }
    
    async remember(key, ttl, callback) {
        let value = await this.get(key);
        
        if (value === null) {
            value = await callback();
            await this.set(key, value, ttl);
        }
        
        return value;
    }
    
    // Cache decorators
    static cache(ttl = 3600) {
        return function(target, propertyKey, descriptor) {
            const originalMethod = descriptor.value;
            
            descriptor.value = async function(...args) {
                const cacheKey = `${target.constructor.name}:${propertyKey}:${JSON.stringify(args)}`;
                const cached = await global.cache.get(cacheKey);
                
                if (cached) {
                    return cached;
                }
                
                const result = await originalMethod.apply(this, args);
                await global.cache.set(cacheKey, result, ttl);
                
                return result;
            };
            
            return descriptor;
        };
    }
    
    static invalidate(pattern) {
        return function(target, propertyKey, descriptor) {
            const originalMethod = descriptor.value;
            
            descriptor.value = async function(...args) {
                const result = await originalMethod.apply(this, args);
                await global.cache.flush(pattern);
                return result;
            };
            
            return descriptor;
        };
    }
}

module.exports = CacheService;
EOF
}

# Create test files
create_test_files() {
    # Create test directory structure
    mkdir -p "$SYSTEM_DIR/app/tests/unit"
    mkdir -p "$SYSTEM_DIR/app/tests/integration"
    
    # Jest configuration
    cat << 'EOF' > "$SYSTEM_DIR/app/jest.config.js"
module.exports = {
    testEnvironment: 'node',
    coverageDirectory: 'coverage',
    collectCoverageFrom: [
        'src/**/*.js',
        'routes/**/*.js',
        'models/**/*.js',
        'middleware/**/*.js',
        'utils/**/*.js',
        '!**/node_modules/**',
        '!**/tests/**'
    ],
    testMatch: [
        '**/tests/**/*.test.js'
    ],
    testTimeout: 30000,
    setupFilesAfterEnv: ['./tests/setup.js']
};
EOF

    # Test setup
    cat << 'EOF' > "$SYSTEM_DIR/app/tests/setup.js"
// Set test environment
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';
process.env.SESSION_SECRET = 'test-session-secret';

// Mock logger to reduce noise
jest.mock('../utils/logger', () => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    audit: jest.fn(),
    performance: jest.fn()
}));

// Global test utilities
global.testUtils = {
    generateTestUser: () => ({
        username: `test_${Date.now()}`,
        email: `test_${Date.now()}@example.com`,
        password: 'Test123!@#',
        role: 'operator'
    }),
    
    generateTestDevice: () => ({
        name: `Device_${Date.now()}`,
        serialNumber: `SN_${Date.now()}`,
        macAddress: `AA:BB:CC:${Math.random().toString(16).substr(2, 2)}:EE:FF`,
        model: 'RB750'
    })
};
EOF

    # Sample unit test
    cat << 'EOF' > "$SYSTEM_DIR/app/tests/unit/auth.test.js"
const { verifyToken } = require('../../middleware/auth');
const jwt = require('jsonwebtoken');

describe('Auth Middleware', () => {
    describe('verifyToken', () => {
        it('should verify valid token', async () => {
            const payload = { _id: '123', role: 'admin' };
            const token = jwt.sign(payload, process.env.JWT_SECRET);
            
            const result = await verifyToken(token);
            
            expect(result._id).toBe(payload._id);
            expect(result.role).toBe(payload.role);
        });
        
        it('should throw error for invalid token', async () => {
            const invalidToken = 'invalid.token.here';
            
            await expect(verifyToken(invalidToken)).rejects.toThrow();
        });
        
        it('should cache verified tokens', async () => {
            const payload = { _id: '123', role: 'admin' };
            const token = jwt.sign(payload, process.env.JWT_SECRET);
            
            // First call
            const result1 = await verifyToken(token);
            
            // Second call should use cache
            const result2 = await verifyToken(token);
            
            expect(result1).toEqual(result2);
        });
    });
});
EOF
}

# Continue with the rest of Phase1.sh functions...
