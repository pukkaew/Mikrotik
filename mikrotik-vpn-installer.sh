#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script (Fixed)
# Version: 2.1
# Compatible with: Ubuntu 22.04 LTS
# Description: Complete VPN-based Hotspot Management Solution
# =============================================================================

set -e  # Exit on any error

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
        echo "❌ Installation appears incomplete. Missing: ${missing_files[*]}"
        return 1
    fi
    
    return 0
}

# Create initial directories early to avoid path issues
create_initial_directories() {
    echo "Creating system directories..."
    
    # Create directories with error handling
    mkdir -p $SYSTEM_DIR 2>/dev/null || {
        echo "Error: Cannot create $SYSTEM_DIR - check permissions"
        exit 1
    }
    
    mkdir -p $LOG_DIR 2>/dev/null || {
        echo "Error: Cannot create $LOG_DIR - check permissions"  
        exit 1
    }
    
    mkdir -p $BACKUP_DIR/{daily,weekly,monthly} 2>/dev/null || {
        echo "Warning: Cannot create backup directories"
    }
    
    mkdir -p $SCRIPT_DIR 2>/dev/null || {
        echo "Warning: Cannot create scripts directory"
    }
    
    # Create a basic log file if it doesn't exist
    touch $LOG_DIR/setup.log 2>/dev/null || {
        echo "Warning: Cannot create log file"
    }
    
    chmod 644 $LOG_DIR/setup.log 2>/dev/null || true
    
    echo "System directories created successfully"
}

# Logging function with fallback
log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${message}${NC}"
    
    # Try to write to log file, fallback to stdout if fails
    if [ -w "$LOG_DIR/setup.log" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log
    elif [ -d "$LOG_DIR" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log 2>/dev/null || echo "Warning: Cannot write to log file"
    fi
}

log_error() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}${message}${NC}"
    
    # Try to write to log file, fallback to stdout if fails  
    if [ -w "$LOG_DIR/setup.log" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log
    elif [ -d "$LOG_DIR" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log 2>/dev/null || true
    fi
}

log_warning() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1"
    echo -e "${YELLOW}${message}${NC}"
    
    # Try to write to log file, fallback to stdout if fails
    if [ -w "$LOG_DIR/setup.log" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log
    elif [ -d "$LOG_DIR" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log 2>/dev/null || true
    fi
}

log_info() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1"
    echo -e "${BLUE}${message}${NC}"
    
    # Try to write to log file, fallback to stdout if fails
    if [ -w "$LOG_DIR/setup.log" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log
    elif [ -d "$LOG_DIR" ] 2>/dev/null; then
        echo "$message" >> $LOG_DIR/setup.log 2>/dev/null || true
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_error "Please run this script as root (use sudo)"
        exit 1
    fi
}

# Function to clean up incomplete installation
cleanup_incomplete_installation() {
    echo "Cleaning up incomplete installation..."
    
    # Check if Docker is installed before trying to use it
    if command -v docker >/dev/null 2>&1; then
        # Stop any running containers
        docker stop $(docker ps -q --filter name=mikrotik 2>/dev/null) 2>/dev/null || true
        docker rm $(docker ps -aq --filter name=mikrotik 2>/dev/null) 2>/dev/null || true
        
        # Remove Docker network if exists
        docker network rm mikrotik-vpn-net 2>/dev/null || true
    else
        echo "Docker not found - skipping container cleanup"
    fi
    
    # Remove systemd service if exists
    systemctl stop mikrotik-vpn 2>/dev/null || true
    systemctl disable mikrotik-vpn 2>/dev/null || true
    rm -f /etc/systemd/system/mikrotik-vpn.service
    systemctl daemon-reload 2>/dev/null || true
    
    # Backup existing config if present
    if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
        echo "Backing up existing configuration..."
        mkdir -p /tmp
        cp $SYSTEM_DIR/configs/setup.env /tmp/mikrotik-vpn-backup.env 2>/dev/null || true
        BACKUP_CONFIG_EXISTS=true
    fi
    
    # Remove incomplete installation
    rm -rf $SYSTEM_DIR 2>/dev/null || true
    rm -rf $LOG_DIR 2>/dev/null || true
    
    # Remove cron jobs
    rm -f /etc/cron.d/mikrotik-vpn 2>/dev/null || true
    
    echo "Cleanup completed"
}

# Function to restore previous configuration
restore_previous_config() {
    if [ "$BACKUP_CONFIG_EXISTS" = "true" ] && [ -f "/tmp/mikrotik-vpn-backup.env" ]; then
        log "Restoring previous configuration..."
        mkdir -p $SYSTEM_DIR/configs
        cp /tmp/mikrotik-vpn-backup.env $SYSTEM_DIR/configs/setup.env
        chmod 600 $SYSTEM_DIR/configs/setup.env
        
        # Source the configuration
        source /tmp/mikrotik-vpn-backup.env
        
        log "Previous configuration restored"
        return 0
    fi
    return 1
}

# Function to get user input with validation
get_user_input() {
    # Try to restore previous config first
    if restore_previous_config; then
        echo "Using previous configuration:"
        echo "Domain: $DOMAIN_NAME"
        echo "Email: $ADMIN_EMAIL"
        echo "SSH Port: $SSH_PORT"
        echo "VPN Network: $VPN_NETWORK"
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
        read -p "Enter your domain name (e.g., vpn.yourcompany.com): " DOMAIN_NAME
        
        # Remove leading/trailing whitespace
        DOMAIN_NAME=$(echo "$DOMAIN_NAME" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Check if domain is not empty
        if [ -z "$DOMAIN_NAME" ]; then
            echo "Domain name cannot be empty. Please try again."
            continue
        fi
        
        # More flexible domain validation
        if [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]] && \
           [[ ! $DOMAIN_NAME =~ \.\. ]] && \
           [[ ${#DOMAIN_NAME} -le 255 ]]; then
            break
        else
            echo "Invalid domain name format. Please enter a valid domain (e.g., example.com)."
        fi
    done
    
    # Email configuration
    while true; do
        read -p "Enter admin email address: " ADMIN_EMAIL
        
        # Remove leading/trailing whitespace
        ADMIN_EMAIL=$(echo "$ADMIN_EMAIL" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Check if email is not empty
        if [ -z "$ADMIN_EMAIL" ]; then
            echo "Email address cannot be empty. Please try again."
            continue
        fi
        
        # Email validation
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
    
    # Database passwords
    echo
    echo "Database Configuration:"
    
    while true; do
        read -s -p "Enter MongoDB root password: " MONGO_ROOT_PASSWORD
        echo
        if [ ${#MONGO_ROOT_PASSWORD} -ge 8 ]; then
            read -s -p "Confirm MongoDB root password: " confirm_mongo
            echo
            if [ "$MONGO_ROOT_PASSWORD" = "$confirm_mongo" ]; then
                break
            else
                echo "Passwords do not match. Please try again."
            fi
        else
            echo "Password must be at least 8 characters long."
        fi
    done
    
    while true; do
        read -s -p "Enter MongoDB app password: " MONGO_APP_PASSWORD
        echo
        if [ ${#MONGO_APP_PASSWORD} -ge 8 ]; then
            read -s -p "Confirm MongoDB app password: " confirm_app
            echo
            if [ "$MONGO_APP_PASSWORD" = "$confirm_app" ]; then
                break
            else
                echo "Passwords do not match. Please try again."
            fi
        else
            echo "Password must be at least 8 characters long."
        fi
    done
    
    while true; do
        read -s -p "Enter Redis password: " REDIS_PASSWORD
        echo
        if [ ${#REDIS_PASSWORD} -ge 8 ]; then
            read -s -p "Confirm Redis password: " confirm_redis
            echo
            if [ "$REDIS_PASSWORD" = "$confirm_redis" ]; then
                break
            else
                echo "Passwords do not match. Please try again."
            fi
        else
            echo "Password must be at least 8 characters long."
        fi
    done
    
    # Export variables
    export DOMAIN_NAME ADMIN_EMAIL SSH_PORT TIMEZONE VPN_NETWORK
    export MONGO_ROOT_PASSWORD MONGO_APP_PASSWORD REDIS_PASSWORD
    
    echo
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
    apt update && apt upgrade -y
    
    log "Setting timezone to $TIMEZONE..."
    timedatectl set-timezone $TIMEZONE
    
    log "Installing essential packages..."
    apt install -y \
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
        tree \
        jq \
        certbot \
        python3-certbot-nginx \
        mailutils \
        cron \
        logrotate \
        rsync \
        screen \
        tmux
    
    # Create system user for application
    if ! id "mikrotik-vpn" &>/dev/null; then
        log "Creating mikrotik-vpn system user..."
        useradd -r -m -s /bin/bash -d /home/mikrotik-vpn mikrotik-vpn
    fi
    
    log "Setting up system optimizations..."
    create_system_optimizations
    
    log "Phase 1 completed successfully!"
}

create_system_optimizations() {
    # System limits for performance
    cat << EOF > /etc/security/limits.d/mikrotik-vpn.conf
mikrotik-vpn soft nofile 65536
mikrotik-vpn hard nofile 65536
mikrotik-vpn soft nproc 32768
mikrotik-vpn hard nproc 32768
* soft nofile 65536
* hard nofile 65536
EOF

    # Kernel optimizations for networking and VPN
    cat << EOF > /etc/sysctl.d/99-mikrotik-vpn.conf
# Network Performance Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

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
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Memory management
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
EOF

    sysctl -p /etc/sysctl.d/99-mikrotik-vpn.conf
}

# =============================================================================
# PHASE 2: DOCKER INSTALLATION
# =============================================================================

phase2_docker_installation() {
    log "==================================================================="
    log "PHASE 2: DOCKER INSTALLATION"
    log "==================================================================="
    
    log "Adding Docker's official GPG key..."
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    log "Adding Docker repository..."
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    log "Installing Docker Engine..."
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Configure Docker daemon for production
    create_docker_config
    
    log "Adding users to docker group..."
    if [ -n "$SUDO_USER" ]; then
        usermod -aG docker $SUDO_USER
    fi
    usermod -aG docker mikrotik-vpn
    
    log "Starting and enabling Docker..."
    systemctl enable docker
    systemctl start docker
    
    log "Creating Docker network..."
    if ! docker network ls | grep -q mikrotik-vpn-net; then
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
        log "Created Docker network: mikrotik-vpn-net"
    fi
    
    log "Verifying Docker installation..."
    docker --version
    docker compose version
    
    log "Phase 2 completed successfully!"
}

create_docker_config() {
    cat << EOF > /etc/docker/daemon.json
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
  "experimental": false
}
EOF

    systemctl restart docker
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
    # Create OpenVPN directories
    mkdir -p $SYSTEM_DIR/openvpn/{server,client-configs,easy-rsa,ccd}
    
    log "Downloading and setting up Easy-RSA..."
    cd $SYSTEM_DIR/openvpn
    
    # Download Easy-RSA
    wget -q https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz
    tar xzf EasyRSA-3.1.0.tgz
    mv EasyRSA-3.1.0/* easy-rsa/
    rm -rf EasyRSA-3.1.0*
    
    # Setup Easy-RSA configuration
    cd easy-rsa
    cat << EOF > vars
set_var EASYRSA_REQ_COUNTRY    "TH"
set_var EASYRSA_REQ_PROVINCE   "Bangkok"
set_var EASYRSA_REQ_CITY       "Bangkok"
set_var EASYRSA_REQ_ORG        "MikroTik VPN System"
set_var EASYRSA_REQ_EMAIL      "$ADMIN_EMAIL"
set_var EASYRSA_REQ_OU         "VPN Management"
set_var EASYRSA_ALGO           "ec"
set_var EASYRSA_DIGEST         "sha512"
set_var EASYRSA_KEY_SIZE       2048
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
    cat << EOF > $SYSTEM_DIR/openvpn/server/server.conf
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
server $(echo $VPN_NETWORK | cut -d'/' -f1) 255.255.255.0
push "route $(echo $VPN_NETWORK | cut -d'/' -f1) 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 1.1.1.1"

# Client configuration
client-to-client
keepalive 10 120
cipher AES-256-GCM
auth SHA512
comp-lzo

# Security
user nobody
group nogroup
persist-key
persist-tun
duplicate-cn

# Logging
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3

# Performance
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"

# Connection limits
max-clients 1000

# Management interface
management localhost 7505

# Client configuration directory
client-config-dir /etc/openvpn/ccd
EOF
    
    # Create OpenVPN Docker Compose
    cat << EOF > $SYSTEM_DIR/docker-compose-openvpn.yml
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
      - $LOG_DIR:/var/log
    restart: unless-stopped
    networks:
      - mikrotik-vpn-net
    environment:
      - OPENVPN_CONFIG=/etc/openvpn/server/server.conf

networks:
  mikrotik-vpn-net:
    external: true
EOF
    
    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR/openvpn
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
    mkdir -p $SYSTEM_DIR/mongodb/{data,logs,backups}
    
    # Create MongoDB initialization script
    cat << EOF > $SYSTEM_DIR/mongodb/mongo-init.js
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
db.createCollection('payments');

// Create indexes for performance
db.organizations.createIndex({ "domain": 1 }, { unique: true });
db.sites.createIndex({ "organization_id": 1 });
db.devices.createIndex({ "serial_number": 1 }, { unique: true });
db.users.createIndex({ "username": 1 }, { unique: true });
db.vouchers.createIndex({ "code": 1 }, { unique: true });
db.sessions.createIndex({ "user_id": 1 });
db.logs.createIndex({ "timestamp": -1 });
EOF
    
    # Create MongoDB Docker Compose
    cat << EOF > $SYSTEM_DIR/docker-compose-mongodb.yml
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
    command: mongod --auth --bind_ip_all --logpath /var/log/mongodb/mongod.log
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh localhost:27017/test --quiet
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
    mkdir -p $SYSTEM_DIR/redis/{data,logs}
    
    # Create Redis configuration
    cat << EOF > $SYSTEM_DIR/redis/redis.conf
# Redis Configuration
bind 127.0.0.1 ::1
protected-mode yes
port 6379
daemonize no
supervised no
pidfile /var/run/redis_6379.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /data
requirepass $REDIS_PASSWORD
maxclients 10000
maxmemory 2gb
maxmemory-policy allkeys-lru
tcp-backlog 511
timeout 0
tcp-keepalive 300
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
EOF
    
    # Create Redis Docker Compose
    cat << EOF > $SYSTEM_DIR/docker-compose-redis.yml
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
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
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
    mkdir -p $SYSTEM_DIR/nginx/{conf.d,ssl,logs,html}
    
    # Create main Nginx configuration
    cat << EOF > $SYSTEM_DIR/nginx/nginx.conf
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

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;

    server_tokens off;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss;

    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Create site-specific configuration
    cat << EOF > $SYSTEM_DIR/nginx/conf.d/mikrotik-vpn.conf
# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME;
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        try_files \$uri =404;
    }
    
    # Redirect all other HTTP traffic to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME;

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

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

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
}
EOF

    # Create Docker Compose for Nginx
    cat << EOF > $SYSTEM_DIR/docker-compose-nginx.yml
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
}

setup_ssl_certificates() {
    log "Setting up SSL certificates..."
    
    # Create self-signed certificate for immediate use
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $SYSTEM_DIR/nginx/ssl/privkey.pem \
        -out $SYSTEM_DIR/nginx/ssl/fullchain.pem \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
        -addext "subjectAltName=DNS:$DOMAIN_NAME"
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
    # Install Node.js 20 LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    # Verify installation
    node --version
    npm --version
}

create_application_structure() {
    # Create application directory structure
    mkdir -p $SYSTEM_DIR/app/{src,config,public,views,routes,models,controllers,middleware,utils}
    
    # Create package.json
    cat << EOF > $SYSTEM_DIR/app/package.json
{
  "name": "mikrotik-vpn-management",
  "version": "2.0.0",
  "description": "MikroTik VPN-based Hotspot Management System",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "helmet": "^6.1.5",
    "cors": "^2.8.5",
    "mongoose": "^7.0.3",
    "redis": "^4.6.5",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "dotenv": "^16.0.3",
    "winston": "^3.8.2",
    "socket.io": "^4.6.1"
  },
  "engines": {
    "node": ">=20.0.0"
  }
}
EOF

    # Create main server file
    cat << 'EOF' > $SYSTEM_DIR/app/server.js
const express = require('express');
const mongoose = require('mongoose');
const redis = require('redis');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');
const { createServer } = require('http');
const { Server } = require('socket.io');

// Load environment variables
require('dotenv').config();

// Initialize Express app
const app = express();
const server = createServer(app);
const io = new Server(server);

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
    new winston.transports.File({ filename: '/var/log/mikrotik-vpn/error.log', level: 'error' }),
    new winston.transports.File({ filename: '/var/log/mikrotik-vpn/app.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Database connections
const connectMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    logger.info('Connected to MongoDB');
  } catch (error) {
    logger.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

const connectRedis = async () => {
  try {
    const client = redis.createClient({
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD
    });
    await client.connect();
    logger.info('Connected to Redis');
    return client;
  } catch (error) {
    logger.error('Redis connection error:', error);
    process.exit(1);
  }
};

// Middleware setup
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Basic routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'MikroTik VPN Management System API',
    version: '2.0.0',
    status: 'running'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!'
  });
});

// Socket.IO for real-time features
io.on('connection', (socket) => {
  logger.info('Client connected:', socket.id);
  
  socket.on('disconnect', () => {
    logger.info('Client disconnected:', socket.id);
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    mongoose.connection.close();
    process.exit(0);
  });
});

// Start server
const startServer = async () => {
  try {
    await connectMongoDB();
    await connectRedis();
    
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
EOF

    # Create environment configuration
    cat << EOF > $SYSTEM_DIR/app/.env
# Application Configuration
NODE_ENV=production
PORT=3000

# Database Configuration
MONGODB_URI=mongodb://mikrotik_app:$MONGO_APP_PASSWORD@mongodb:27017/mikrotik_vpn
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=$REDIS_PASSWORD

# Session Configuration
SESSION_SECRET=$(openssl rand -base64 32)

# JWT Configuration
JWT_SECRET=$(openssl rand -base64 64)

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=$ADMIN_EMAIL
FROM_EMAIL=$ADMIN_EMAIL

# VPN Configuration
VPN_NETWORK=$VPN_NETWORK
OPENVPN_HOST=$DOMAIN_NAME

# Logging
LOG_LEVEL=info
EOF

    # Create application Docker Compose
    cat << EOF > $SYSTEM_DIR/docker-compose-app.yml
version: '3.8'

services:
  app:
    build: 
      context: ./app
      dockerfile: Dockerfile
    container_name: mikrotik-app
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - PORT=3000
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - $SYSTEM_DIR/app:/usr/src/app
      - $LOG_DIR:/var/log/mikrotik-vpn
    networks:
      - mikrotik-vpn-net
    depends_on:
      - mongodb
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create Dockerfile
    cat << EOF > $SYSTEM_DIR/app/Dockerfile
FROM node:20-alpine

# Install system dependencies
RUN apk add --no-cache curl bash

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mikrotik -u 1001

# Create necessary directories
RUN mkdir -p logs && \
    chown -R mikrotik:nodejs /usr/src/app

# Switch to non-root user
USER mikrotik

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
EOF

    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR/app
}

# =============================================================================
# PHASE 7: MANAGEMENT SCRIPTS
# =============================================================================

phase7_management_scripts() {
    log "==================================================================="
    log "PHASE 7: MANAGEMENT SCRIPTS SETUP"
    log "==================================================================="
    
    log "Creating management scripts..."
    create_management_scripts
    
    log "Setting up system service..."
    setup_system_service
    
    log "Phase 7 completed successfully!"
}

create_management_scripts() {
    # Master control script
    cat << 'EOF' > $SYSTEM_DIR/mikrotik-vpn-manager.sh
#!/bin/bash
# MikroTik VPN System Master Management Script

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
LOG_DIR="/var/log/mikrotik-vpn"

# Functions
print_header() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}              MikroTik VPN Management System v2.1${NC}"
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

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root (use sudo)"
        exit 1
    fi
}

# System status function
show_system_status() {
    print_header
    echo -e "${BLUE}System Status Overview${NC}"
    echo "======================================"
    echo
    
    # System information
    echo -e "${PURPLE}System Information:${NC}"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p)"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory Usage: $(free -h | awk '/^Mem:/ {printf "Used: %s / Total: %s (%.1f%%)", $3, $2, $3/$2*100}')"
    echo "Disk Usage: $(df -h / | awk 'NR==2 {printf "Used: %s / Total: %s (%s)", $3, $2, $5}')"
    echo
    
    # Docker services status
    echo -e "${PURPLE}Docker Services:${NC}"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep mikrotik || echo "No MikroTik services running"
    echo
    
    # VPN status
    echo -e "${PURPLE}VPN Status:${NC}"
    if docker ps | grep -q mikrotik-openvpn; then
        echo "OpenVPN: Running"
        if docker exec mikrotik-openvpn test -f /var/log/openvpn-status.log 2>/dev/null; then
            clients=$(docker exec mikrotik-openvpn cat /var/log/openvpn-status.log 2>/dev/null | grep "CLIENT_LIST" | wc -l || echo "0")
            echo "Connected VPN Clients: $clients"
        fi
    else
        echo "OpenVPN: Not Running"
    fi
    echo
    
    # Database status
    echo -e "${PURPLE}Database Status:${NC}"
    if docker ps | grep -q mikrotik-mongodb; then
        echo "MongoDB: Running"
    else
        echo "MongoDB: Not Running"
    fi
    
    if docker ps | grep -q mikrotik-redis; then
        echo "Redis: Running"
    else
        echo "Redis: Not Running"
    fi
    echo
}

# Service management functions
start_all_services() {
    print_status "Starting all MikroTik VPN services..."
    
    cd $SYSTEM_DIR
    
    # Create Docker network if not exists
    docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 2>/dev/null || true
    
    # Start services in dependency order
    print_status "Starting databases..."
    docker compose -f docker-compose-mongodb.yml up -d
    docker compose -f docker-compose-redis.yml up -d
    
    # Wait for databases
    print_status "Waiting for databases to be ready..."
    sleep 30
    
    print_status "Starting VPN services..."
    docker compose -f docker-compose-openvpn.yml up -d
    
    print_status "Starting application..."
    docker compose -f docker-compose-app.yml up -d
    
    print_status "Starting web server..."
    docker compose -f docker-compose-nginx.yml up -d
    
    print_status "All services started!"
}

stop_all_services() {
    print_status "Stopping all MikroTik VPN services..."
    
    cd $SYSTEM_DIR
    
    # Stop services in reverse order
    docker compose -f docker-compose-nginx.yml down 2>/dev/null || true
    docker compose -f docker-compose-app.yml down 2>/dev/null || true
    docker compose -f docker-compose-openvpn.yml down 2>/dev/null || true
    docker compose -f docker-compose-redis.yml down 2>/dev/null || true
    docker compose -f docker-compose-mongodb.yml down 2>/dev/null || true
    
    print_status "All services stopped"
}

restart_all_services() {
    print_status "Restarting all services..."
    stop_all_services
    sleep 5
    start_all_services
}

# Log viewing function
view_logs() {
    local service=$1
    
    if [ -z "$service" ]; then
        echo "Available services for log viewing:"
        echo "  app          - Application logs"
        echo "  nginx        - Web server logs"
        echo "  mongodb      - Database logs"
        echo "  redis        - Cache logs"
        echo "  openvpn      - VPN server logs"
        echo "  system       - System logs"
        echo "  all          - All container logs"
        echo
        echo "Usage: $0 logs <service_name>"
        return
    fi
    
    case $service in
        "app")
            if docker ps | grep -q mikrotik-app; then
                docker logs -f mikrotik-app
            else
                print_error "Application container is not running"
            fi
            ;;
        "nginx")
            if docker ps | grep -q mikrotik-nginx; then
                docker logs -f mikrotik-nginx
            else
                print_error "Nginx container is not running"
            fi
            ;;
        "mongodb")
            if docker ps | grep -q mikrotik-mongodb; then
                docker logs -f mikrotik-mongodb
            else
                print_error "MongoDB container is not running"
            fi
            ;;
        "redis")
            if docker ps | grep -q mikrotik-redis; then
                docker logs -f mikrotik-redis
            else
                print_error "Redis container is not running"
            fi
            ;;
        "openvpn")
            if docker ps | grep -q mikrotik-openvpn; then
                docker logs -f mikrotik-openvpn
            else
                print_error "OpenVPN container is not running"
            fi
            ;;
        "system")
            tail -f $LOG_DIR/setup.log
            ;;
        "all")
            cd $SYSTEM_DIR
            docker compose -f docker-compose-*.yml logs -f
            ;;
        *)
            print_error "Unknown service: $service"
            view_logs
            ;;
    esac
}

# VPN client management
generate_vpn_client() {
    local client_name=$1
    
    if [ -z "$client_name" ]; then
        read -p "Enter client name: " client_name
    fi
    
    if [ -z "$client_name" ]; then
        print_error "Client name is required"
        return 1
    fi
    
    print_status "Creating VPN client configuration for: $client_name"
    
    # Load domain from config
    if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
        source $SYSTEM_DIR/configs/setup.env
    else
        print_error "Configuration file not found"
        return 1
    fi
    
    cd $SYSTEM_DIR/openvpn/easy-rsa
    
    # Generate client certificate
    ./easyrsa gen-req $client_name nopass
    ./easyrsa sign-req client $client_name
    
    # Create client configuration
    mkdir -p $SYSTEM_DIR/clients
    
    cat << EOC > $SYSTEM_DIR/clients/$client_name.ovpn
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
$(cat pki/ca.crt)
</ca>

<cert>
$(openssl x509 -in pki/issued/$client_name.crt)
</cert>

<key>
$(cat pki/private/$client_name.key)
</key>

<tls-auth>
$(cat ta.key)
</tls-auth>
key-direction 1
EOC

    print_status "Client configuration created: $SYSTEM_DIR/clients/$client_name.ovpn"
}

# Main menu function
show_main_menu() {
    while true; do
        print_header
        echo -e "${BLUE}Main Menu${NC}"
        echo "========================================="
        echo "1. System Status"
        echo "2. Start All Services"
        echo "3. Stop All Services"
        echo "4. Restart All Services"
        echo "5. View Logs"
        echo "6. Generate VPN Client"
        echo "7. Exit"
        echo
        read -p "Select option (1-7): " choice
        
        case $choice in
            1) show_system_status ;;
            2) start_all_services ;;
            3) stop_all_services ;;
            4) restart_all_services ;;
            5) 
                echo "Enter service name (or 'all' for all services):"
                read service
                view_logs "$service"
                ;;
            6) 
                echo "Client name:"
                read client_name
                generate_vpn_client "$client_name"
                ;;
            7) 
                print_status "Exiting MikroTik VPN Manager"
                exit 0
                ;;
            *) 
                print_error "Invalid option. Please select 1-7."
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

# Main script logic
main() {
    # Check if running as root
    check_root
    
    # Parse command line arguments
    case "${1:-menu}" in
        "status")
            show_system_status
            ;;
        "start")
            start_all_services
            ;;
        "stop")
            stop_all_services
            ;;
        "restart")
            restart_all_services
            ;;
        "logs")
            view_logs "$2"
            ;;
        "vpn")
            generate_vpn_client "$2"
            ;;
        "menu"|"")
            show_main_menu
            ;;
        "help"|"-h"|"--help")
            echo "MikroTik VPN Management System v2.1"
            echo
            echo "Usage: $0 [command] [options]"
            echo
            echo "Commands:"
            echo "  status              - Show system status"
            echo "  start               - Start all services"
            echo "  stop                - Stop all services"
            echo "  restart             - Restart all services"
            echo "  logs <service>      - View service logs"
            echo "  vpn <name>          - Generate VPN client"
            echo "  menu                - Show interactive menu (default)"
            echo "  help                - Show this help"
            ;;
        *)
            print_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
EOF

    chmod +x $SYSTEM_DIR/mikrotik-vpn-manager.sh

    # Create start/stop service scripts
    cat << 'EOF' > $SCRIPT_DIR/start-all-services.sh
#!/bin/bash
# Start all services script

SYSTEM_DIR="/opt/mikrotik-vpn"
cd $SYSTEM_DIR

echo "Starting MikroTik VPN services..."

# Create network
docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 2>/dev/null || true

# Start in dependency order
echo "Starting databases..."
docker compose -f docker-compose-mongodb.yml up -d
docker compose -f docker-compose-redis.yml up -d

echo "Waiting for databases..."
sleep 15

echo "Starting VPN services..."
docker compose -f docker-compose-openvpn.yml up -d

echo "Starting application..."
docker compose -f docker-compose-app.yml up -d

echo "Starting web server..."
docker compose -f docker-compose-nginx.yml up -d

echo "All services started!"
EOF

    chmod +x $SCRIPT_DIR/start-all-services.sh

    cat << 'EOF' > $SCRIPT_DIR/stop-all-services.sh
#!/bin/bash
# Stop all services script

SYSTEM_DIR="/opt/mikrotik-vpn"
cd $SYSTEM_DIR

echo "Stopping MikroTik VPN services..."

# Stop in reverse order
docker compose -f docker-compose-nginx.yml down 2>/dev/null || true
docker compose -f docker-compose-app.yml down 2>/dev/null || true
docker compose -f docker-compose-openvpn.yml down 2>/dev/null || true
docker compose -f docker-compose-redis.yml down 2>/dev/null || true
docker compose -f docker-compose-mongodb.yml down 2>/dev/null || true

echo "All services stopped!"
EOF

    chmod +x $SCRIPT_DIR/stop-all-services.sh

    # Create backup scripts
    cat << 'EOF' > $SCRIPT_DIR/backup-system.sh
#!/bin/bash
# Basic backup script

BACKUP_DIR="/opt/mikrotik-vpn/backups"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/mikrotik-vpn/backup.log"

# Load environment variables
if [ -f "/opt/mikrotik-vpn/configs/setup.env" ]; then
    source /opt/mikrotik-vpn/configs/setup.env
else
    echo "Configuration file not found"
    exit 1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

BACKUP_PATH="$BACKUP_DIR/daily/backup_$DATE"

log "Starting backup to $BACKUP_PATH"
mkdir -p $BACKUP_PATH

# Backup MongoDB
log "Backing up MongoDB..."
docker exec mikrotik-mongodb mongodump \
    --host localhost \
    --username admin \
    --password $MONGO_ROOT_PASSWORD \
    --authenticationDatabase admin \
    --out /tmp/mongodb-backup

docker cp mikrotik-mongodb:/tmp/mongodb-backup $BACKUP_PATH/
docker exec mikrotik-mongodb rm -rf /tmp/mongodb-backup

# Backup Redis
log "Backing up Redis..."
docker exec mikrotik-redis redis-cli --pass $REDIS_PASSWORD BGSAVE
sleep 5
docker cp mikrotik-redis:/data/dump.rdb $BACKUP_PATH/redis_dump.rdb

# Backup configurations
log "Backing up configurations..."
tar -czf $BACKUP_PATH/configs.tar.gz \
    /opt/mikrotik-vpn/configs \
    /opt/mikrotik-vpn/nginx \
    /opt/mikrotik-vpn/openvpn \
    2>/dev/null || true

# Create checksum
cd $BACKUP_PATH
find . -type f -exec sha256sum {} \; > checksums.sha256

# Compress backup
cd $BACKUP_DIR/daily
tar -czf backup_$DATE.tar.gz backup_$DATE/
rm -rf backup_$DATE/

log "Backup completed: backup_$DATE.tar.gz"
EOF

    chmod +x $SCRIPT_DIR/backup-system.sh

    # Create health check script
    cat << 'EOF' > $SCRIPT_DIR/health-check.sh
#!/bin/bash
# Health check script

LOG_FILE="/var/log/mikrotik-vpn/health-check.log"
FAILED_CHECKS=""

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

check_service() {
    local service=$1
    local container_name=$2
    
    if docker ps | grep -q $container_name; then
        log "OK: $service is running"
        return 0
    else
        log "FAIL: $service is not running"
        FAILED_CHECKS="$FAILED_CHECKS $service"
        return 1
    fi
}

check_disk_space() {
    local usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $usage -gt 80 ]; then
        log "WARN: Disk usage is high: $usage%"
        FAILED_CHECKS="$FAILED_CHECKS disk_space"
        return 1
    else
        log "OK: Disk usage is normal: $usage%"
        return 0
    fi
}

check_memory() {
    local usage=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
    if [ $usage -gt 85 ]; then
        log "WARN: Memory usage is high: $usage%"
        FAILED_CHECKS="$FAILED_CHECKS memory"
        return 1
    else
        log "OK: Memory usage is normal: $usage%"
        return 0
    fi
}

# Main health check
main() {
    log "=== Health Check Started ==="
    
    check_service "MongoDB" "mikrotik-mongodb"
    check_service "Redis" "mikrotik-redis"
    check_service "OpenVPN" "mikrotik-openvpn"
    check_service "Application" "mikrotik-app"
    check_service "Nginx" "mikrotik-nginx"
    
    check_disk_space
    check_memory
    
    if [ -z "$FAILED_CHECKS" ]; then
        log "Overall status: HEALTHY"
        echo "HEALTHY"
        exit 0
    else
        log "Overall status: UNHEALTHY - Failed checks:$FAILED_CHECKS"
        echo "UNHEALTHY"
        exit 1
    fi
}

main
EOF

    chmod +x $SCRIPT_DIR/health-check.sh
}

setup_system_service() {
    # Create systemd service
    cat << EOF > /etc/systemd/system/mikrotik-vpn.service
[Unit]
Description=MikroTik VPN Management System
Requires=docker.service
After=docker.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
WorkingDirectory=$SYSTEM_DIR
ExecStart=$SCRIPT_DIR/start-all-services.sh
ExecStop=$SCRIPT_DIR/stop-all-services.sh
ExecReload=$SYSTEM_DIR/mikrotik-vpn-manager.sh restart
TimeoutStartSec=300
TimeoutStopSec=120
Restart=no

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mikrotik-vpn.service
}

# =============================================================================
# PHASE 8: SECURITY HARDENING
# =============================================================================

phase8_security_hardening() {
    log "==================================================================="
    log "PHASE 8: SECURITY HARDENING"
    log "==================================================================="
    
    log "Configuring firewall..."
    setup_firewall
    
    log "Hardening SSH..."
    harden_ssh
    
    log "Setting up fail2ban..."
    setup_fail2ban
    
    log "Phase 8 completed successfully!"
}

setup_firewall() {
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow $SSH_PORT/tcp comment 'SSH'
    
    # Allow web traffic
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow VPN
    ufw allow 1194/udp comment 'OpenVPN'
    
    # Allow internal monitoring (from VPN network only)
    VPN_SUBNET=$(echo $VPN_NETWORK | cut -d'/' -f1 | cut -d'.' -f1-3).0/24
    ufw allow from $VPN_SUBNET to any port 3000 comment 'Internal API'
    ufw allow from $VPN_SUBNET to any port 9090 comment 'Prometheus'
    ufw allow from $VPN_SUBNET to any port 3001 comment 'Grafana'
    
    # Enable UFW
    ufw --force enable
    
    log "Firewall configured and enabled"
}

harden_ssh() {
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create hardened SSH config
    cat << EOF > /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
# SSH Hardening for MikroTik VPN System
Port $SSH_PORT
Protocol 2

# Authentication
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 10
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes

# Security
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 2

# Allowed users
AllowUsers mikrotik-vpn
EOF

    # Create SSH banner
    cat << EOF > /etc/issue.net
***************************************************************************
                        AUTHORIZED ACCESS ONLY
    
    This system is for authorized use only. All activities are logged
    and monitored. Unauthorized access will be prosecuted.
    
                   MikroTik VPN Management System
***************************************************************************
EOF

    # Add banner to SSH config
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
    
    # Add current user to allowed users if not root
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        echo "AllowUsers mikrotik-vpn $SUDO_USER" >> /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
    fi
    
    # Restart SSH
    systemctl restart sshd
    
    log "SSH hardening completed"
}

setup_fail2ban() {
    # Create fail2ban configuration
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = $ADMIN_EMAIL
sender = fail2ban@$DOMAIN_NAME
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/mikrotik-vpn/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/mikrotik-vpn/nginx/error.log
maxretry = 10

[openvpn]
enabled = true
port = 1194
protocol = udp
filter = openvpn
logpath = /var/log/mikrotik-vpn/openvpn.log
maxretry = 3
EOF

    # Create OpenVPN filter
    cat << EOF > /etc/fail2ban/filter.d/openvpn.conf
[Definition]
failregex = ^.*<HOST>:[0-9]{4,5} TLS Auth Error.*$
            ^.*<HOST>:[0-9]{4,5} VERIFY ERROR.*$
            ^.*<HOST>:[0-9]{4,5} TLS Error: TLS handshake failed$
ignoreregex =
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log "Fail2ban configured and started"
}

# =============================================================================
# PHASE 9: CONFIGURATION SAVE
# =============================================================================

phase9_save_configuration() {
    log "==================================================================="
    log "PHASE 9: SAVING CONFIGURATION"
    log "==================================================================="
    
    # Create configuration directory
    mkdir -p $SYSTEM_DIR/configs
    
    # Save installation configuration
    cat << EOF > $SYSTEM_DIR/configs/setup.env
# MikroTik VPN System Configuration
# Generated on: $(date)

# Domain and Network Configuration
DOMAIN_NAME="$DOMAIN_NAME"
ADMIN_EMAIL="$ADMIN_EMAIL"
SSH_PORT="$SSH_PORT"
TIMEZONE="$TIMEZONE"
VPN_NETWORK="$VPN_NETWORK"

# Database Passwords
MONGO_ROOT_PASSWORD="$MONGO_ROOT_PASSWORD"
MONGO_APP_PASSWORD="$MONGO_APP_PASSWORD"
REDIS_PASSWORD="$REDIS_PASSWORD"

# Installation Information
INSTALL_DATE="$(date)"
INSTALLER_VERSION="2.1"
EOF

    chmod 600 $SYSTEM_DIR/configs/setup.env
    
    # Create directory structure documentation
    cat << EOF > $SYSTEM_DIR/configs/directory-structure.txt
MikroTik VPN System Directory Structure
=====================================

/opt/mikrotik-vpn/
├── app/                        # Application files
│   ├── src/                    # Source code
│   ├── config/                 # Configuration files
│   ├── public/                 # Static files
│   └── Dockerfile              # Docker build file
├── nginx/                      # Nginx configuration
│   ├── conf.d/                 # Site configurations
│   ├── ssl/                    # SSL certificates
│   └── logs/                   # Nginx logs
├── openvpn/                    # OpenVPN configuration
│   ├── easy-rsa/               # Certificate authority
│   ├── server/                 # Server configuration
│   └── client-configs/         # Client configurations
├── mongodb/                    # MongoDB data and logs
├── redis/                      # Redis data and configuration
├── backups/                    # System backups
│   ├── daily/                  # Daily backups
│   ├── weekly/                 # Weekly backups
│   └── monthly/                # Monthly backups
├── scripts/                    # Management scripts
├── configs/                    # System configuration
├── clients/                    # Generated VPN client configs
└── docker-compose-*.yml        # Docker service definitions

/var/log/mikrotik-vpn/          # Log files
├── setup.log                   # Installation log
├── app.log                     # Application log
├── backup.log                  # Backup log
└── health-check.log            # Health check log
EOF

    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR
    
    log "Configuration saved successfully"
}

# =============================================================================
# PHASE 10: FINAL SETUP AND START
# =============================================================================

phase10_final_setup() {
    log "==================================================================="
    log "PHASE 10: FINAL SETUP AND STARTUP"
    log "==================================================================="
    
    log "Building and starting application..."
    cd $SYSTEM_DIR/app
    npm install --production
    
    log "Starting all services..."
    cd $SYSTEM_DIR
    
    # Create network
    docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 2>/dev/null || true
    
    # Start services in order
    docker compose -f docker-compose-mongodb.yml up -d
    docker compose -f docker-compose-redis.yml up -d
    
    # Wait for databases
    log "Waiting for databases to initialize..."
    sleep 30
    
    docker compose -f docker-compose-openvpn.yml up -d
    docker compose -f docker-compose-app.yml up -d
    docker compose -f docker-compose-nginx.yml up -d
    
    # Wait for services to start
    sleep 15
    
    log "Verifying service status..."
    $SCRIPT_DIR/health-check.sh
    
    # Setup cron jobs
    setup_cron_jobs
    
    log "Phase 10 completed successfully!"
}

setup_cron_jobs() {
    # Create cron job for backups
    cat << EOF > /etc/cron.d/mikrotik-vpn
# MikroTik VPN System Scheduled Tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily backup at 2:00 AM
0 2 * * * mikrotik-vpn $SCRIPT_DIR/backup-system.sh >/dev/null 2>&1

# Health check every 5 minutes
*/5 * * * * mikrotik-vpn $SCRIPT_DIR/health-check.sh >/dev/null 2>&1

# Clean old logs weekly
0 3 * * 0 mikrotik-vpn find /var/log/mikrotik-vpn -name "*.log" -mtime +30 -delete 2>/dev/null

# SSL certificate renewal (if using Let's Encrypt)
0 3 1 * * root certbot renew --quiet && docker exec mikrotik-nginx nginx -s reload 2>/dev/null
EOF

    # Set proper permissions
    chmod 644 /etc/cron.d/mikrotik-vpn
    
    # Restart cron
    systemctl restart cron
}

# =============================================================================
# MAIN INSTALLATION PROCESS
# =============================================================================

main_installation() {
    log "==================================================================="
    log "Starting MikroTik VPN Management System Installation"
    log "==================================================================="
    
    # Create initial directories
    create_initial_directories
    
    # Get configuration from user
    get_user_input
    
    # Run all installation phases
    phase1_system_preparation
    phase2_docker_installation
    phase3_vpn_server_setup
    phase4_database_setup
    phase5_webserver_setup
    phase6_application_setup
    phase7_management_scripts
    phase8_security_hardening
    phase9_save_configuration
    phase10_final_setup
    
    # Final success message
    show_installation_complete
}

show_installation_complete() {
    clear
    echo -e "${GREEN}======================================================================${NC}"
    echo -e "${GREEN}    MikroTik VPN Management System Installation Complete!${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    echo
    echo -e "${CYAN}Installation Summary:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${YELLOW}Domain:${NC}           $DOMAIN_NAME"
    echo -e "${YELLOW}Admin Email:${NC}      $ADMIN_EMAIL"
    echo -e "${YELLOW}SSH Port:${NC}         $SSH_PORT"
    echo -e "${YELLOW}VPN Network:${NC}      $VPN_NETWORK"
    echo
    echo -e "${CYAN}Access Points:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}Web Interface:${NC}    https://$DOMAIN_NAME"
    echo -e "${GREEN}SSH Access:${NC}       Port $SSH_PORT"
    echo -e "${GREEN}OpenVPN:${NC}          $DOMAIN_NAME:1194 (UDP)"
    echo
    echo -e "${CYAN}Management Commands:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}System Manager:${NC}   sudo $SYSTEM_DIR/mikrotik-vpn-manager.sh"
    echo -e "${GREEN}System Status:${NC}    sudo systemctl status mikrotik-vpn"
    echo -e "${GREEN}View Logs:${NC}        sudo journalctl -u mikrotik-vpn -f"
    echo
    echo -e "${CYAN}File Locations:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}System Directory:${NC} $SYSTEM_DIR"
    echo -e "${GREEN}Log Directory:${NC}    $LOG_DIR"
    echo -e "${GREEN}VPN Clients:${NC}      $SYSTEM_DIR/clients"
    echo -e "${GREEN}Backups:${NC}          $SYSTEM_DIR/backups"
    echo
    echo -e "${RED}⚠️  IMPORTANT SECURITY NOTES:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${YELLOW}1.${NC} Change default database passwords immediately"
    echo -e "${YELLOW}2.${NC} Configure your domain's DNS to point to this server"
    echo -e "${YELLOW}3.${NC} Replace self-signed SSL certificate with Let's Encrypt"
    echo -e "${YELLOW}4.${NC} Review and customize firewall rules"
    echo -e "${YELLOW}5.${NC} Set up SSH key authentication and disable password auth"
    echo
    echo -e "${CYAN}Next Steps:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}1.${NC} Configure your domain's DNS A record"
    echo -e "${GREEN}2.${NC} Run: sudo $SYSTEM_DIR/mikrotik-vpn-manager.sh"
    echo -e "${GREEN}3.${NC} Generate VPN client configurations"
    echo -e "${GREEN}4.${NC} Set up Let's Encrypt SSL certificate"
    echo
    echo -e "${GREEN}Installation log saved to: $LOG_DIR/setup.log${NC}"
    echo
    echo -e "${GREEN}======================================================================${NC}"
}

# =============================================================================
# SCRIPT MAIN LOGIC
# =============================================================================

print_banner() {
    clear
    echo -e "${CYAN}===================================================================${NC}"
    echo -e "${CYAN}       MikroTik VPN Management System - Installer v2.1${NC}"
    echo -e "${CYAN}       Complete VPN-based Hotspot Management Solution${NC}"
    echo -e "${CYAN}===================================================================${NC}"
    echo
}

# Main script execution
main() {
    # Check if running as root
    check_root
    
    print_banner
    
    # Create initial directories early with proper error handling
    create_initial_directories
    
    # Check if system is already installed
    if [ -d "$SYSTEM_DIR" ] && [ "$(ls -A $SYSTEM_DIR 2>/dev/null)" ]; then
        echo "Existing installation detected!"
        echo "Options:"
        echo "1. Run system manager"
        echo "2. Force complete reinstallation"
        echo "3. Exit"
        read -p "Select option (1-3): " existing_choice
        
        case $existing_choice in
            1)
                if check_installation; then
                    if [ -f "$SYSTEM_DIR/mikrotik-vpn-manager.sh" ]; then
                        exec $SYSTEM_DIR/mikrotik-vpn-manager.sh
                    else
                        echo "Manager script not found. Please reinstall."
                        exit 1
                    fi
                else
                    echo "Installation appears incomplete. Proceeding with cleanup and reinstall..."
                    BACKUP_CONFIG_EXISTS=false
                    cleanup_incomplete_installation
                    # Recreate directories after cleanup
                    create_initial_directories
                    main_installation
                fi
                ;;
            2)
                echo "⚠️  WARNING: This will completely reinstall the system!"
                read -p "Are you absolutely sure? (type 'yes' to confirm): " confirm
                if [ "$confirm" = "yes" ]; then
                    cleanup_incomplete_installation
                    # Recreate directories after cleanup
                    create_initial_directories
                    main_installation
                else
                    echo "Reinstallation cancelled."
                    exit 0
                fi
                ;;
            3)
                echo "Exiting installer."
                exit 0
                ;;
            *)
                echo "Invalid option"
                exit 1
                ;;
        esac
    else
        # Fresh installation
        main_installation
    fi
}

# Set error handling with better error message
set -e
trap 'echo "ERROR: Installation failed at line $LINENO. Please check the output above for details." >&2; exit 1' ERR

# Run main function
main "$@"
