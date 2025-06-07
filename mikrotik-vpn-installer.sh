#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script
# Version: 2.0
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

# System directories
SYSTEM_DIR="/opt/mikrotik-vpn"
LOG_DIR="/var/log/mikrotik-vpn"
BACKUP_DIR="/opt/mikrotik-vpn/backups"
SCRIPT_DIR="/opt/mikrotik-vpn/scripts"
CONFIG_DIR="/opt/mikrotik-vpn/configs"

# =============================================================================
# LOGGING AND UTILITY FUNCTIONS
# =============================================================================

# Create initial directories
create_initial_directories() {
    mkdir -p $SYSTEM_DIR
    mkdir -p $LOG_DIR
    mkdir -p $BACKUP_DIR
    mkdir -p $SCRIPT_DIR
    mkdir -p $CONFIG_DIR
    
    # Create log file
    touch $LOG_DIR/setup.log
    chmod 644 $LOG_DIR/setup.log
}

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_DIR/setup.log
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a $LOG_DIR/setup.log
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a $LOG_DIR/setup.log
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1" | tee -a $LOG_DIR/setup.log
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_error "Please run this script as root (use sudo)"
        exit 1
    fi
}

# =============================================================================
# USER INPUT AND VALIDATION
# =============================================================================

get_user_input() {
    echo
    echo "==================================================================="
    echo "MikroTik VPN Management System Configuration"
    echo "==================================================================="
    
    # Domain configuration
    while true; do
        read -p "Enter your domain name (e.g., vpn.yourcompany.com): " DOMAIN_NAME
        DOMAIN_NAME=$(echo "$DOMAIN_NAME" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//g')
        
        if [ -z "$DOMAIN_NAME" ]; then
            echo "Domain name cannot be empty. Please try again."
            continue
        fi
        
        if [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && [[ ${#DOMAIN_NAME} -le 255 ]]; then
            break
        else
            echo "Invalid domain name format. Please enter a valid domain."
        fi
    done
    
    # Email configuration
    while true; do
        read -p "Enter admin email address: " ADMIN_EMAIL
        ADMIN_EMAIL=$(echo "$ADMIN_EMAIL" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        if [ -z "$ADMIN_EMAIL" ]; then
            echo "Email address cannot be empty. Please try again."
            continue
        fi
        
        if [[ $ADMIN_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
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
    read -p "Enter VPN network (default 10.8.0.0/24): " VPN_NETWORK
    VPN_NETWORK=${VPN_NETWORK:-10.8.0.0/24}
    
    # Database passwords
    echo
    echo "Setting up database passwords..."
    
    # MongoDB root password
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
    
    # MongoDB app password
    while true; do
        read -s -p "Enter MongoDB app password: " MONGO_APP_PASSWORD
        echo
        if [ ${#MONGO_APP_PASSWORD} -ge 8 ]; then
            break
        else
            echo "Password must be at least 8 characters long."
        fi
    done
    
    # Redis password
    while true; do
        read -s -p "Enter Redis password: " REDIS_PASSWORD
        echo
        if [ ${#REDIS_PASSWORD} -ge 8 ]; then
            break
        else
            echo "Password must be at least 8 characters long."
        fi
    done
    
    # Save configuration
    save_configuration
    
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
    echo "==================================================================="
    echo
    
    read -p "Is this configuration correct? (y/n): " confirm_config
    if [[ ! $confirm_config =~ ^[Yy]$ ]]; then
        echo "Configuration cancelled. Please run the script again."
        exit 0
    fi
    
    log "Configuration completed. Starting installation..."
}

save_configuration() {
    cat << EOF > $CONFIG_DIR/setup.env
# MikroTik VPN System Configuration
export DOMAIN_NAME="$DOMAIN_NAME"
export ADMIN_EMAIL="$ADMIN_EMAIL"
export SSH_PORT="$SSH_PORT"
export TIMEZONE="$TIMEZONE"
export VPN_NETWORK="$VPN_NETWORK"
export MONGO_ROOT_PASSWORD="$MONGO_ROOT_PASSWORD"
export MONGO_APP_PASSWORD="$MONGO_APP_PASSWORD"
export REDIS_PASSWORD="$REDIS_PASSWORD"
export SYSTEM_DIR="$SYSTEM_DIR"
export LOG_DIR="$LOG_DIR"
export BACKUP_DIR="$BACKUP_DIR"
export SCRIPT_DIR="$SCRIPT_DIR"
export CONFIG_DIR="$CONFIG_DIR"
EOF
    
    chmod 600 $CONFIG_DIR/setup.env
}

# =============================================================================
# PHASE 1: SYSTEM PREPARATION
# =============================================================================

phase1_system_preparation() {
    log "==================================================================="
    log "PHASE 1: SYSTEM PREPARATION"
    log "==================================================================="
    
    # Create directory structure
    log "Creating directory structure..."
    create_directory_structure
    
    # Update system
    log "Updating system packages..."
    apt update && apt upgrade -y
    
    # Set timezone
    log "Setting timezone to $TIMEZONE..."
    timedatectl set-timezone $TIMEZONE
    
    # Install essential packages
    log "Installing essential packages..."
    install_essential_packages
    
    # Create system user
    log "Creating system user..."
    create_system_user
    
    # Apply system optimizations
    log "Applying system optimizations..."
    apply_system_optimizations
    
    log "Phase 1 completed successfully!"
}

create_directory_structure() {
    # Main directories
    mkdir -p $SYSTEM_DIR/{data,logs,backups,configs,ssl,scripts,clients}
    mkdir -p $SYSTEM_DIR/{mongodb,redis,nginx,openvpn,l2tp,monitoring,app}
    
    # Sub-directories
    mkdir -p $SYSTEM_DIR/mongodb/{data,logs,backups}
    mkdir -p $SYSTEM_DIR/redis/{data,logs}
    mkdir -p $SYSTEM_DIR/nginx/{conf.d,html,ssl}
    mkdir -p $SYSTEM_DIR/openvpn/{server,client-configs,easy-rsa,ccd}
    mkdir -p $SYSTEM_DIR/monitoring/{prometheus,grafana,alertmanager}
    mkdir -p $SYSTEM_DIR/monitoring/prometheus/rules
    mkdir -p $SYSTEM_DIR/monitoring/grafana/provisioning/{datasources,dashboards,notifiers}
    mkdir -p $SYSTEM_DIR/monitoring/grafana/dashboards
    mkdir -p $BACKUP_DIR/{daily,weekly,monthly}
    mkdir -p $LOG_DIR
    
    # Application directories
    mkdir -p $SYSTEM_DIR/app/{src,config,public,views,routes,models,controllers,middleware,utils}
    
    # Set permissions
    chown -R root:root $SYSTEM_DIR
    chmod -R 755 $SYSTEM_DIR
    chmod 700 $CONFIG_DIR
}

install_essential_packages() {
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
        tmux \
        aide \
        clamav \
        clamav-daemon \
        rkhunter \
        openssl \
        openvpn \
        easy-rsa
}

create_system_user() {
    if ! id "mikrotik-vpn" &>/dev/null; then
        useradd -r -m -s /bin/bash -d /home/mikrotik-vpn mikrotik-vpn
        log "Created mikrotik-vpn system user"
    else
        log "mikrotik-vpn user already exists"
    fi
    
    # Set ownership
    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR
    chown -R mikrotik-vpn:mikrotik-vpn $LOG_DIR
}

apply_system_optimizations() {
    # System limits
    cat << 'EOF' > /etc/security/limits.d/mikrotik-vpn.conf
mikrotik-vpn soft nofile 65536
mikrotik-vpn hard nofile 65536
mikrotik-vpn soft nproc 32768
mikrotik-vpn hard nproc 32768
* soft nofile 65536
* hard nofile 65536
EOF

    # Kernel parameters
    cat << 'EOF' > /etc/sysctl.d/99-mikrotik-vpn.conf
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
    
    # Add Docker repository
    log "Adding Docker repository..."
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    log "Installing Docker Engine..."
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Configure Docker
# log "Configuring Docker..."
# configure_docker
    
    # Add users to docker group
    log "Adding users to docker group..."
    if [ -n "$SUDO_USER" ]; then
        usermod -aG docker $SUDO_USER
    fi
    usermod -aG docker mikrotik-vpn
    
    # Start Docker
log "Starting Docker..."
systemctl enable docker
systemctl start docker
    
    # Create Docker network
    log "Creating Docker network..."
    docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 || true
    
    # Verify installation
    docker --version
    docker compose version
    
    log "Phase 2 completed successfully!"
}

configure_docker() {
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
    
    log "Setting up L2TP/IPSec server..."
    setup_l2tp_server
    
    log "Creating VPN management scripts..."
    create_vpn_management_scripts
    
    log "Phase 3 completed successfully!"
}

setup_openvpn_server() {
    cd $SYSTEM_DIR/openvpn
    
    # Download Easy-RSA
    log "Downloading Easy-RSA..."
    # ลบ directory เดิม (ถ้ามี) เพื่อป้องกัน conflict
    rm -rf easy-rsa
    mkdir -p easy-rsa
    wget -q https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz
    tar xzf EasyRSA-3.1.0.tgz
    mv EasyRSA-3.1.0/* easy-rsa/
    rm -rf EasyRSA-3.1.0*
    
    # Configure Easy-RSA
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
    
    # Generate DH parameters
    ./easyrsa gen-dh
    
    # Generate TLS auth key
    openvpn --genkey secret ta.key
    
    # Create server configuration
    create_openvpn_config
    
    # Create Docker Compose for OpenVPN
    create_openvpn_compose
    
    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR/openvpn
}

create_openvpn_config() {
    cat << EOF > $SYSTEM_DIR/openvpn/server/server.conf
# OpenVPN Server Configuration
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
server $(echo $VPN_NETWORK | cut -d'/' -f1 | cut -d'.' -f1-3).0 255.255.255.0
push "route $(echo $VPN_NETWORK | cut -d'/' -f1 | cut -d'.' -f1-3).0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

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
EOF
}

create_openvpn_compose() {
    cat << 'EOF' > $SYSTEM_DIR/docker-compose-openvpn.yml
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
      - ./openvpn:/etc/openvpn
      - /var/log/mikrotik-vpn:/var/log
    restart: unless-stopped
    networks:
      - mikrotik-vpn-net
    environment:
      - OPENVPN_CONFIG=/etc/openvpn/server/server.conf

networks:
  mikrotik-vpn-net:
    external: true
EOF
}

setup_l2tp_server() {
    # Generate random PSK
    L2TP_PSK=$(openssl rand -base64 32)
    
    cat << EOF > $SYSTEM_DIR/docker-compose-l2tp.yml
version: '3.8'

services:
  l2tp-ipsec:
    image: hwdsl2/ipsec-vpn-server:latest
    container_name: mikrotik-l2tp
    cap_add:
      - NET_ADMIN
    environment:
      - VPN_IPSEC_PSK=$L2TP_PSK
      - VPN_USER=mikrotik
      - VPN_PASSWORD=$MONGO_ROOT_PASSWORD
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

networks:
  mikrotik-vpn-net:
    external: true
EOF
    
    # Save L2TP credentials
    cat << EOF > $CONFIG_DIR/l2tp-credentials.txt
L2TP/IPSec VPN Credentials:
Server: $DOMAIN_NAME
PSK: $L2TP_PSK
Username: mikrotik
Password: $MONGO_ROOT_PASSWORD
EOF
    
    chmod 600 $CONFIG_DIR/l2tp-credentials.txt
}

create_vpn_management_scripts() {
    # VPN client generator script
    cat << 'EOF' > $SCRIPT_DIR/generate-vpn-client.sh
#!/bin/bash
# VPN Client Configuration Generator

# Load configuration
source /opt/mikrotik-vpn/configs/setup.env

CLIENT_NAME=$1
if [ -z "$CLIENT_NAME" ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

# Validate client name
if ! [[ $CLIENT_NAME =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Client name can only contain letters, numbers, hyphens and underscores"
    exit 1
fi

cd $SYSTEM_DIR/openvpn/easy-rsa

# Generate client certificate
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

# Create client directory
mkdir -p $SYSTEM_DIR/clients

# Create client configuration
cat << EOF > $SYSTEM_DIR/clients/$CLIENT_NAME.ovpn
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
$(openssl x509 -in pki/issued/$CLIENT_NAME.crt)
</cert>

<key>
$(cat pki/private/$CLIENT_NAME.key)
</key>

<tls-auth>
$(cat ta.key)
</tls-auth>
key-direction 1
EOF

echo "Client configuration created: $SYSTEM_DIR/clients/$CLIENT_NAME.ovpn"
EOF
    
    chmod +x $SCRIPT_DIR/generate-vpn-client.sh
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

// Create indexes
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
      - ./mongodb/data:/data/db
      - ./mongodb/logs:/var/log/mongodb
      - ./mongodb/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    ports:
      - "127.0.0.1:27017:27017"
    command: mongod --auth --bind_ip_all
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongo localhost:27017/test --quiet
      interval: 30s
      timeout: 10s
      retries: 5

  mongo-express:
    image: mongo-express:latest
    container_name: mikrotik-mongo-express
    restart: unless-stopped
    environment:
      - ME_CONFIG_MONGODB_ADMINUSERNAME=admin
      - ME_CONFIG_MONGODB_ADMINPASSWORD=$MONGO_ROOT_PASSWORD
      - ME_CONFIG_MONGODB_SERVER=mongodb
      - ME_CONFIG_BASICAUTH_USERNAME=admin
      - ME_CONFIG_BASICAUTH_PASSWORD=$MONGO_ROOT_PASSWORD
    ports:
      - "127.0.0.1:8081:8081"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - mongodb

networks:
  mikrotik-vpn-net:
    external: true
EOF
}

setup_redis() {
    # Load environment variables first
    if [ -f "/opt/mikrotik-vpn/configs/setup.env" ]; then
        source /opt/mikrotik-vpn/configs/setup.env
    fi

    cat << EOF > $SYSTEM_DIR/redis/redis.conf
# Redis Configuration
bind 0.0.0.0
protected-mode yes
port 6379
daemonize no
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16

# Persistence
save 900 1
save 300 10
save 60 10000
dbfilename dump.rdb
dir /data

# Security
requirepass $REDIS_PASSWORD

# Limits
maxclients 10000
maxmemory 2gb
maxmemory-policy allkeys-lru

# Performance
tcp-backlog 511
timeout 0
tcp-keepalive 300
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
      - ./redis/data:/data
      - ./redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
      - ./redis/logs:/var/log/redis
    ports:
      - "127.0.0.1:6379:6379"
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

  redis-commander:
    image: rediscommander/redis-commander:latest
    container_name: mikrotik-redis-commander
    restart: unless-stopped
    environment:
      - REDIS_HOSTS=local:redis:6379:0:$REDIS_PASSWORD
      - HTTP_USER=admin
      - HTTP_PASSWORD=$REDIS_PASSWORD
    ports:
      - "127.0.0.1:8081:8081"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - redis

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
    # Create main Nginx configuration
    cat << 'EOF' > $SYSTEM_DIR/nginx/nginx.conf
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

    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;

    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;

    # Security headers
    server_tokens off;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/atom+xml image/svg+xml;

    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;

    # Include site configurations
    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Create site configuration
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
        return 301 https://\\$server_name\\$request_uri;
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
        limit_req zone=general burst=20 nodelay;
        
        proxy_pass http://app:3000;
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
        
        proxy_pass http://app:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://app:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Static files
    location /static/ {
        alias /var/www/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Health check
    location /health {
        access_log off;
        proxy_pass http://app:3000/health;
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
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Enhanced security for admin
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;

    # Admin interface
    location / {
        limit_req zone=general burst=10 nodelay;
        
        proxy_pass http://app:3000/admin;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    # Create Docker Compose for Nginx
    cat << 'EOF' > $SYSTEM_DIR/docker-compose-nginx.yml
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
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/html:/var/www/html:ro
      - ./nginx/logs:/var/log/nginx
      - certbot_www:/var/www/certbot:ro
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3
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
    # Create self-signed certificate for immediate use
    log "Creating self-signed certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $SYSTEM_DIR/nginx/ssl/privkey.pem \
        -out $SYSTEM_DIR/nginx/ssl/fullchain.pem \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
        -addext "subjectAltName=DNS:$DOMAIN_NAME,DNS:admin.$DOMAIN_NAME"
    
    # Create Certbot Docker Compose
    cat << EOF > $SYSTEM_DIR/docker-compose-certbot.yml
version: '3.8'

services:
  certbot:
    image: certbot/certbot
    container_name: mikrotik-certbot
    volumes:
      - ./nginx/ssl:/etc/letsencrypt
      - certbot_www:/var/www/certbot
    command: certonly --webroot --webroot-path=/var/www/certbot --email $ADMIN_EMAIL --agree-tos --no-eff-email -d $DOMAIN_NAME -d admin.$DOMAIN_NAME
    networks:
      - mikrotik-vpn-net

volumes:
  certbot_www:

networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create SSL renewal script
    cat << 'EOF' > $SCRIPT_DIR/renew-ssl-certificates.sh
#!/bin/bash
# SSL Certificate renewal script

# Load configuration
source /opt/mikrotik-vpn/configs/setup.env

LOG_FILE="$LOG_DIR/ssl-renewal.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting SSL certificate renewal..."

# Renew certificates
docker compose -f $SYSTEM_DIR/docker-compose-certbot.yml run --rm certbot renew

if [ $? -eq 0 ]; then
    log "Certificate renewal successful"
    
    # Reload Nginx
    docker exec mikrotik-nginx nginx -s reload
    
    if [ $? -eq 0 ]; then
        log "Nginx reloaded successfully"
    else
        log "ERROR: Failed to reload Nginx"
        exit 1
    fi
else
    log "ERROR: Certificate renewal failed"
    exit 1
fi

log "SSL certificate renewal completed"
EOF

    chmod +x $SCRIPT_DIR/renew-ssl-certificates.sh
}

# =============================================================================
# PHASE 6: APPLICATION SETUP
# =============================================================================

phase6_application_setup() {
    log "==================================================================="
    log "PHASE 6: APPLICATION SETUP (NODE.JS)"
    log "==================================================================="
    
    log "Installing Node.js..."
    install_nodejs
    
    log "Creating application structure..."
    create_application_structure
    
    log "Phase 6 completed successfully!"
}

install_nodejs() {
    # Install Node.js 20 LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    # Install global packages
    npm install -g pm2@latest
    
    # Verify installation
    node --version
    npm --version
    pm2 --version
}

create_application_structure() {
    # Create package.json
    cat << 'EOF' > $SYSTEM_DIR/app/package.json
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
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "mongoose": "^7.5.0",
    "redis": "^4.6.8",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1",
    "winston": "^3.10.0",
    "socket.io": "^4.7.2",
    "axios": "^1.5.0",
    "joi": "^17.10.1",
    "moment": "^2.29.4",
    "nodemailer": "^6.9.4"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
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
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');
const { createServer } = require('http');
const { Server } = require('socket.io');
const path = require('path');

// Load environment variables
require('dotenv').config();

// Initialize Express app
const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST']
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
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: '/var/log/mikrotik-vpn/app.log' 
        }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// Database connections
const connectMongoDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        logger.info('Connected to MongoDB');
    } catch (error) {
        logger.error('MongoDB connection error:', error);
        process.exit(1);
    }
};

const connectRedis = async () => {
    try {
        const client = redis.createClient({
            url: `redis://:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`
        });
        
        client.on('error', (err) => {
            logger.error('Redis Client Error', err);
        });
        
        await client.connect();
        logger.info('Connected to Redis');
        return client;
    } catch (error) {
        logger.error('Redis connection error:', error);
        process.exit(1);
    }
};

// Global Redis client
let redisClient;

// Middleware setup
app.use(helmet());
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Static files
app.use('/static', express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        redis: redisClient && redisClient.isOpen ? 'connected' : 'disconnected'
    });
});

// Basic routes
app.get('/', (req, res) => {
    res.json({ 
        message: 'MikroTik VPN Management System API',
        version: '2.0.0'
    });
});

// API routes placeholder
app.use('/api/auth', require('./routes/auth'));
app.use('/api/devices', require('./routes/devices'));
app.use('/api/users', require('./routes/users'));
app.use('/api/vouchers', require('./routes/vouchers'));
app.use('/api/monitoring', require('./routes/monitoring'));

// Admin routes
app.use('/admin', require('./routes/admin'));

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: 'The requested resource was not found'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error(err.stack);
    
    const status = err.status || 500;
    const message = err.message || 'Internal Server Error';
    
    res.status(status).json({
        error: status === 500 ? 'Internal Server Error' : err.name,
        message: process.env.NODE_ENV === 'development' ? message : 'Something went wrong!',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// Socket.IO for real-time features
io.on('connection', (socket) => {
    logger.info('Client connected:', socket.id);
    
    socket.on('join-room', (room) => {
        socket.join(room);
        logger.info(`Socket ${socket.id} joined room ${room}`);
    });
    
    socket.on('leave-room', (room) => {
        socket.leave(room);
        logger.info(`Socket ${socket.id} left room ${room}`);
    });
    
    socket.on('disconnect', () => {
        logger.info('Client disconnected:', socket.id);
    });
});

// Graceful shutdown
const gracefulShutdown = async () => {
    logger.info('Received shutdown signal');
    
    server.close(() => {
        logger.info('HTTP server closed');
    });
    
    try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
        
        if (redisClient) {
            await redisClient.quit();
            logger.info('Redis connection closed');
        }
        
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown:', error);
        process.exit(1);
    }
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
const startServer = async () => {
    try {
        await connectMongoDB();
        redisClient = await connectRedis();
        
        // Make Redis client available globally
        app.locals.redis = redisClient;
        
        const PORT = process.env.PORT || 3000;
        server.listen(PORT, '0.0.0.0', () => {
            logger.info(`Server running on port ${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV}`);
        });
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Export for testing
module.exports = { app, io };

// Start server if not in test mode
if (process.env.NODE_ENV !== 'test') {
    startServer();
}
EOF

    # Create environment configuration
    cat << EOF > $SYSTEM_DIR/app/.env
# Application Configuration
NODE_ENV=production
PORT=3000
CORS_ORIGIN=https://$DOMAIN_NAME

# Database Configuration
MONGODB_URI=mongodb://mikrotik_app:$MONGO_APP_PASSWORD@mongodb:27017/mikrotik_vpn
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=$REDIS_PASSWORD

# Session Configuration
SESSION_SECRET=$(openssl rand -base64 32)

# JWT Configuration
JWT_SECRET=$(openssl rand -base64 64)
JWT_EXPIRES_IN=24h

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=$ADMIN_EMAIL
# TODO: Replace with real SMTP App Password
SMTP_PASS=your-app-password
FROM_EMAIL=$ADMIN_EMAIL

# VPN Configuration
VPN_NETWORK=$VPN_NETWORK
OPENVPN_HOST=$DOMAIN_NAME
OPENVPN_PORT=1194

# API Keys
API_KEY=$(openssl rand -base64 32)

# Logging
LOG_LEVEL=info
EOF

    # Create Dockerfile for application
    cat << 'EOF' > $SYSTEM_DIR/app/Dockerfile
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

    # Create Docker Compose for application
    cat << 'EOF' > $SYSTEM_DIR/docker-compose-app.yml
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
      - ./app:/usr/src/app
      - /usr/src/app/node_modules
      - ./logs:/var/log/mikrotik-vpn
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

networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create basic route files structure
    mkdir -p $SYSTEM_DIR/app/routes
    
    # Create placeholder route files
    for route in auth devices users vouchers monitoring admin; do
        cat << 'EOF' > $SYSTEM_DIR/app/routes/$route.js
const express = require('express');
const router = express.Router();

// Placeholder route
router.get('/', (req, res) => {
    res.json({ message: `${route} route` });
});

module.exports = router;
EOF
    done
    
    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR/app
}

# =============================================================================
# PHASE 7: MONITORING SETUP
# =============================================================================

phase7_monitoring_setup() {
    log "==================================================================="
    log "PHASE 7: MONITORING & ANALYTICS SETUP"
    log "==================================================================="
    
    log "Setting up Prometheus..."
    setup_prometheus
    
    log "Setting up Grafana..."
    setup_grafana
    
    log "Setting up Alertmanager..."
    setup_alertmanager
    
    log "Phase 7 completed successfully!"
}

setup_prometheus() {
    # Prometheus configuration
    cat << 'EOF' > $SYSTEM_DIR/monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'mikrotik-vpn-monitor'

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

  # Application metrics
  - job_name: 'mikrotik-app'
    static_configs:
      - targets: ['app:3000']
    metrics_path: '/metrics'
EOF

    # Create alert rules
    cat << 'EOF' > $SYSTEM_DIR/monitoring/prometheus/rules/alerts.yml
groups:
  - name: system_alerts
    interval: 30s
    rules:
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% (current value: {{ \$value }}%)"

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 85% (current value: {{ \$value }}%)"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 20
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space"
          description: "Disk space is below 20% (current value: {{ \$value }}%)"

      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
          description: "{{ \$labels.job }} on {{ \$labels.instance }} is down"

  - name: vpn_alerts
    interval: 30s
    rules:
      - alert: VPNConnectionsHigh
        expr: openvpn_server_connected_clients > 900
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High VPN connections"
          description: "VPN connections approaching limit (current: {{ \$value }})"

      - alert: VPNServiceDown
        expr: up{job="openvpn"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "VPN service down"
          description: "OpenVPN service is not responding"

  - name: database_alerts
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

      - alert: MongoDBHighConnections
        expr: mongodb_connections_current > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "MongoDB high connections"
          description: "MongoDB has {{ \$value }} active connections"
EOF
}

setup_grafana() {
    # Grafana datasource configuration
    cat << 'EOF' > $SYSTEM_DIR/monitoring/grafana/provisioning/datasources/prometheus.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

    # Dashboard provisioning
    cat << 'EOF' > $SYSTEM_DIR/monitoring/grafana/provisioning/dashboards/dashboard.yml
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

    # Create main dashboard
    cat << 'EOF' > $SYSTEM_DIR/monitoring/grafana/dashboards/mikrotik-vpn-overview.json
{
  "dashboard": {
    "id": null,
    "uid": "mikrotik-vpn-overview",
    "title": "MikroTik VPN System Overview",
    "tags": ["mikrotik", "vpn", "overview"],
    "timezone": "browser",
    "schemaVersion": 30,
    "version": 0,
    "refresh": "10s",
    "panels": [
      {
        "datasource": "Prometheus",
        "fieldConfig": {
          "defaults": {
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
          }
        },
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 0,
          "y": 0
        },
        "id": 1,
        "options": {
          "orientation": "auto",
          "reduceOptions": {
            "calcs": ["lastNotNull"],
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
          }
        },
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 12,
          "y": 0
        },
        "id": 2,
        "options": {
          "orientation": "auto",
          "reduceOptions": {
            "calcs": ["lastNotNull"],
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
      }
    ]
  }
}
EOF
}

setup_alertmanager() {
    # Create Alertmanager configuration
    cat << EOF > $SYSTEM_DIR/monitoring/alertmanager.yml
global:
  resolve_timeout: 5m
  smtp_from: '$ADMIN_EMAIL'
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_auth_username: '$ADMIN_EMAIL'
  smtp_auth_password: 'your-app-password'

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

receivers:
  - name: 'default'
    email_configs:
      - to: '$ADMIN_EMAIL'
        headers:
          Subject: '[MikroTik VPN Alert] {{ .GroupLabels.alertname }}'

  - name: 'critical'
    email_configs:
      - to: '$ADMIN_EMAIL'
        headers:
          Subject: '[CRITICAL] MikroTik VPN Alert: {{ .GroupLabels.alertname }}'
    webhook_configs:
      - url: 'http://app:3000/api/webhooks/alertmanager'
        send_resolved: true

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
EOF

    # Create monitoring Docker Compose
    cat << EOF > $SYSTEM_DIR/docker-compose-monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: mikrotik-prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
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
      - GF_SECURITY_ADMIN_PASSWORD=$MONGO_ROOT_PASSWORD
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
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

  node-exporter:
    image: prom/node-exporter:latest
    container_name: mikrotik-node-exporter
    restart: unless-stopped
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
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
    devices:
      - /dev/kmsg
    ports:
      - "127.0.0.1:8080:8080"
    networks:
      - mikrotik-vpn-net
    privileged: true

  alertmanager:
    image: prom/alertmanager:latest
    container_name: mikrotik-alertmanager
    restart: unless-stopped
    volumes:
      - ./monitoring/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - alertmanager_data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    ports:
      - "127.0.0.1:9093:9093"
    networks:
      - mikrotik-vpn-net

  mongodb-exporter:
    image: percona/mongodb_exporter:0.35
    container_name: mikrotik-mongodb-exporter
    restart: unless-stopped
    environment:
      - MONGODB_URI=mongodb://admin:$MONGO_ROOT_PASSWORD@mongodb:27017
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
      - REDIS_PASSWORD=$REDIS_PASSWORD
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

volumes:
  prometheus_data:
  grafana_data:
  alertmanager_data:

networks:
  mikrotik-vpn-net:
    external: true
EOF

    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR/monitoring
}

# =============================================================================
# PHASE 8: SECURITY HARDENING
# =============================================================================

phase8_security_hardening() {
    log "==================================================================="
    log "PHASE 8: SECURITY HARDENING"
    log "==================================================================="
    
    log "Configuring firewall (UFW)..."
    setup_firewall
    
    log "Setting up Fail2ban..."
    setup_fail2ban
    
    log "Hardening SSH..."
    harden_ssh
    
    log "Setting up intrusion detection..."
    setup_intrusion_detection
    
    log "Phase 8 completed successfully!"
}

setup_firewall() {
    # Reset UFW to defaults
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow $SSH_PORT/tcp comment 'SSH'
    
    # Allow web traffic
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow VPN traffic
    ufw allow 1194/udp comment 'OpenVPN'
    ufw allow 500/udp comment 'IPSec'
    ufw allow 4500/udp comment 'IPSec NAT-T'
    ufw allow 1701/udp comment 'L2TP'
    
    # Allow monitoring (from VPN network only)
    VPN_SUBNET=$(echo $VPN_NETWORK | cut -d'/' -f1 | cut -d'.' -f1-3).0/24
    ufw allow from $VPN_SUBNET to any port 9090 comment 'Prometheus'
    ufw allow from $VPN_SUBNET to any port 3001 comment 'Grafana'
    
    # Allow Docker bridge network
    ufw allow from 172.20.0.0/16 comment 'Docker network'
    
    # Enable UFW
    ufw --force enable
    
    # Show status
    ufw status verbose
}

setup_fail2ban() {
    # Create custom jail configuration
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = $ADMIN_EMAIL
sender = fail2ban@$DOMAIN_NAME
action = %(action_mwl)s
ignoreip = 127.0.0.1/8 ::1 $VPN_SUBNET

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
logpath = $LOG_DIR/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = $LOG_DIR/nginx/error.log
maxretry = 10
findtime = 60

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = $LOG_DIR/nginx/access.log
maxretry = 2

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = $LOG_DIR/nginx/access.log
maxretry = 6

[openvpn]
enabled = true
port = 1194
protocol = udp
filter = openvpn
logpath = $LOG_DIR/openvpn.log
maxretry = 3

[mongodb-auth]
enabled = true
filter = mongodb-auth
port = 27017
logpath = $SYSTEM_DIR/mongodb/logs/mongod.log
maxretry = 3
EOF

    # Create OpenVPN filter
    cat << 'EOF' > /etc/fail2ban/filter.d/openvpn.conf
[Definition]
failregex = ^.*<HOST>:[0-9]{4,5} TLS Auth Error.*$
            ^.*<HOST>:[0-9]{4,5} VERIFY ERROR.*$
            ^.*<HOST>:[0-9]{4,5} TLS Error: TLS handshake failed$
            ^.*<HOST>:[0-9]{4,5} Connection reset, restarting.*$
ignoreregex =
EOF

    # Create MongoDB filter
    cat << 'EOF' > /etc/fail2ban/filter.d/mongodb-auth.conf
[Definition]
failregex = ^.*authentication failed.*from client <HOST>.*$
            ^.*Failed to authenticate.*from client <HOST>.*$
ignoreregex =
EOF

    # Restart and enable Fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    # Check status
    fail2ban-client status
}

harden_ssh() {
    # Backup original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
    
    # Create hardened SSH configuration
    ssh-keygen -A

    cat << EOF > /etc/ssh/sshd_config.d/99-mikrotik-vpn-hardening.conf
# SSH Hardening for MikroTik VPN System
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
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2

# Password authentication
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Disable problematic methods
HostbasedAuthentication no
IgnoreUserKnownHosts yes
IgnoreRhosts yes
UsePAM yes

# Security features
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no

# User restrictions
AllowUsers mikrotik-vpn \${SUDO_USER:-root}

# Logging
SyslogFacility AUTH
LogLevel INFO

# Modern cryptography
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# Banner
Banner /etc/issue.net
EOF

    # Create login banner
    cat << 'EOF' > /etc/issue.net
******************************************************************************
                        AUTHORIZED ACCESS ONLY

This system is for authorized use only. All activities are logged and
monitored. Unauthorized access attempts will be investigated and may
result in prosecution. If you are not authorized to access this system,
disconnect immediately.

                    MikroTik VPN Management System
******************************************************************************
EOF

    # Test SSH configuration
    sshd -t
    
    if [ $? -eq 0 ]; then
        systemctl restart sshd
        log "SSH hardening completed successfully"
    else
        log_error "SSH configuration test failed"
        exit 1
    fi
}

setup_intrusion_detection() {
    # Setup AIDE
    log "Setting up AIDE..."
    
    # Initialize AIDE database
    aideinit
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    # Create AIDE configuration
    cat << 'EOF' > /etc/aide/aide.conf.d/99-mikrotik-vpn
# MikroTik VPN System AIDE Rules
/opt/mikrotik-vpn/configs$ VarDir
/opt/mikrotik-vpn/scripts$ BinDir
/opt/mikrotik-vpn/ssl$ VarDir
/opt/mikrotik-vpn/*.yml$ ConfFiles
/var/log/mikrotik-vpn$ Logs
EOF
    
    # Setup ClamAV
    log "Setting up ClamAV..."
    freshclam
    systemctl enable clamav-freshclam
    systemctl start clamav-freshclam
    
    # Create virus scan script
    cat << 'EOF' > $SCRIPT_DIR/virus-scan.sh
#!/bin/bash
# Virus scan script

LOG_FILE="/var/log/mikrotik-vpn/virus-scan.log"
SCAN_DIRS="/opt/mikrotik-vpn /home /tmp /var/tmp"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting virus scan..."

# Update virus definitions
freshclam >> $LOG_FILE 2>&1

# Scan directories
for dir in $SCAN_DIRS; do
    if [ -d "$dir" ]; then
        log "Scanning $dir..."
        clamscan -r -i --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" "$dir" >> $LOG_FILE 2>&1
    fi
done

log "Virus scan completed"
EOF
    
    chmod +x $SCRIPT_DIR/virus-scan.sh
    
    # Setup rkhunter
    log "Setting up rkhunter..."
    rkhunter --update
    rkhunter --propupd
    
    # Create security audit script
    cat << 'EOF' > $SCRIPT_DIR/security-audit.sh
#!/bin/bash
# Security audit script

LOG_FILE="/var/log/mikrotik-vpn/security-audit.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting security audit..."

# Check for suspicious users
log "Checking for suspicious users..."
awk -F: '($3 == 0) && ($1 != "root")' /etc/passwd >> $LOG_FILE

# Check for files with SUID/SGID bits
log "Checking SUID/SGID files..."
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null >> $LOG_FILE

# Check for world-writable files
log "Checking world-writable files..."
find / -type f -perm -002 2>/dev/null | grep -v "^/proc" | grep -v "^/sys" >> $LOG_FILE

# Check listening ports
log "Checking listening ports..."
netstat -tulpn >> $LOG_FILE 2>&1

# Run rkhunter
log "Running rkhunter..."
rkhunter --check --skip-keypress >> $LOG_FILE 2>&1

# Run AIDE check
log "Running AIDE check..."
aide --check >> $LOG_FILE 2>&1

log "Security audit completed"
EOF
    
    chmod +x $SCRIPT_DIR/security-audit.sh
}

# =============================================================================
# PHASE 9: BACKUP SYSTEM SETUP
# =============================================================================

phase9_backup_setup() {
    log "==================================================================="
    log "PHASE 9: BACKUP SYSTEM SETUP"
    log "==================================================================="
    
    log "Creating backup scripts..."
    create_backup_system
    
    log "Setting up automated backups..."
    setup_backup_automation
    
    log "Creating disaster recovery procedures..."
    create_disaster_recovery
    
    log "Phase 9 completed successfully!"
}

create_backup_system() {
    # Main backup script
    cat << 'EOF' > $SCRIPT_DIR/backup-system.sh
#!/bin/bash
# MikroTik VPN System Comprehensive Backup Script

# Configuration
BACKUP_DIR="/opt/mikrotik-vpn/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAILY=7
RETENTION_WEEKLY=4
RETENTION_MONTHLY=12
LOG_FILE="/var/log/mikrotik-vpn/backup.log"

# Load environment variables
source /opt/mikrotik-vpn/configs/setup.env

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# Error handling
set -e
trap 'log "ERROR: Backup failed at line $LINENO"' ERR

# Determine backup type
BACKUP_TYPE="daily"
if [ $(date +%d) -eq 1 ]; then
    BACKUP_TYPE="monthly"
elif [ $(date +%u) -eq 7 ]; then
    BACKUP_TYPE="weekly"
fi

BACKUP_PATH="$BACKUP_DIR/$BACKUP_TYPE/backup_$DATE"

log "Starting $BACKUP_TYPE backup to $BACKUP_PATH"

# Create backup directory
mkdir -p $BACKUP_PATH

# 1. Stop non-critical services for consistency
log "Preparing services for backup..."
docker exec mikrotik-app pm2 stop all 2>/dev/null || true

# 2. Database Backups
log "Backing up MongoDB..."
docker exec mikrotik-mongodb mongodump \
    --host localhost \
    --username admin \
    --password $MONGO_ROOT_PASSWORD \
    --authenticationDatabase admin \
    --gzip \
    --out /tmp/mongodb-backup

docker cp mikrotik-mongodb:/tmp/mongodb-backup $BACKUP_PATH/
docker exec mikrotik-mongodb rm -rf /tmp/mongodb-backup

log "Backing up Redis..."
docker exec mikrotik-redis redis-cli --pass $REDIS_PASSWORD BGSAVE
sleep 5
docker cp mikrotik-redis:/data/dump.rdb $BACKUP_PATH/redis_dump.rdb
docker cp mikrotik-redis:/data/appendonly.aof $BACKUP_PATH/redis_appendonly.aof 2>/dev/null || true

# 3. Configuration Files
log "Backing up configuration files..."
tar -czf $BACKUP_PATH/configs.tar.gz \
    /opt/mikrotik-vpn/configs \
    /opt/mikrotik-vpn/nginx \
    /opt/mikrotik-vpn/openvpn \
    /opt/mikrotik-vpn/l2tp \
    /opt/mikrotik-vpn/monitoring \
    /opt/mikrotik-vpn/app/.env \
    /opt/mikrotik-vpn/*.yml \
    /opt/mikrotik-vpn/scripts \
    /etc/ssh/sshd_config.d/99-mikrotik-vpn-hardening.conf \
    /etc/fail2ban/jail.local \
    /etc/ufw/user.rules \
    2>/dev/null || true

# 4. SSL Certificates
log "Backing up SSL certificates..."
tar -czf $BACKUP_PATH/ssl.tar.gz \
    /opt/mikrotik-vpn/nginx/ssl \
    2>/dev/null || true

# 5. Docker volumes
log "Backing up Docker volumes..."
docker run --rm -v prometheus_data:/data -v $BACKUP_PATH:/backup alpine \
    tar -czf /backup/prometheus_data.tar.gz -C /data . 2>/dev/null || true
docker run --rm -v grafana_data:/data -v $BACKUP_PATH:/backup alpine \
    tar -czf /backup/grafana_data.tar.gz -C /data . 2>/dev/null || true

# 6. VPN client configurations
log "Backing up VPN client configurations..."
if [ -d "/opt/mikrotik-vpn/clients" ]; then
    tar -czf $BACKUP_PATH/vpn_clients.tar.gz /opt/mikrotik-vpn/clients
fi

# 7. Application logs
log "Backing up application logs..."
tar -czf $BACKUP_PATH/logs.tar.gz \
    /var/log/mikrotik-vpn \
    --exclude='*.gz' \
    --exclude='*.old' \
    2>/dev/null || true

# 8. System information
log "Collecting system information..."
cat << SYSINFO > $BACKUP_PATH/system_info.txt
Backup Date: $(date)
Hostname: $(hostname)
System: $(lsb_release -d | cut -f2)
Kernel: $(uname -r)
Docker Version: $(docker --version)
Disk Usage: $(df -h /)
Memory: $(free -h)

Docker Containers:
$(docker ps -a)

Docker Images:
$(docker images)

Network Configuration:
$(ip addr show)
$(ip route show)
SYSINFO

# 9. Create backup manifest
log "Creating backup manifest..."
cat << MANIFEST > $BACKUP_PATH/manifest.json
{
  "backup_date": "$(date -Iseconds)",
  "backup_type": "$BACKUP_TYPE",
  "system_version": "2.0",
  "hostname": "$(hostname)",
  "domain": "$DOMAIN_NAME",
  "components": [
    "mongodb",
    "redis", 
    "openvpn",
    "l2tp",
    "nginx",
    "app",
    "monitoring"
  ]
}
MANIFEST

# 10. Restart services
log "Restarting services..."
docker exec mikrotik-app pm2 start all 2>/dev/null || true

# 11. Create checksums
log "Creating checksums..."
cd $BACKUP_PATH
find . -type f -exec sha256sum {} \; > checksums.sha256

# 12. Compress entire backup
log "Compressing backup..."
cd $BACKUP_DIR/$BACKUP_TYPE
tar -czf backup_$DATE.tar.gz backup_$DATE/
rm -rf backup_$DATE/

# 13. Encrypt backup (optional)
if [ -n "$BACKUP_ENCRYPTION_KEY" ]; then
    log "Encrypting backup..."
    openssl enc -aes-256-cbc -salt -in backup_$DATE.tar.gz -out backup_$DATE.tar.gz.enc -pass pass:$BACKUP_ENCRYPTION_KEY
    rm backup_$DATE.tar.gz
    mv backup_$DATE.tar.gz.enc backup_$DATE.tar.gz
fi

# 14. Cleanup old backups
log "Cleaning up old backups..."
find $BACKUP_DIR/daily -name "*.tar.gz" -mtime +$RETENTION_DAILY -delete 2>/dev/null || true
find $BACKUP_DIR/weekly -name "*.tar.gz" -mtime +$((RETENTION_WEEKLY * 7)) -delete 2>/dev/null || true
find $BACKUP_DIR/monthly -name "*.tar.gz" -mtime +$((RETENTION_MONTHLY * 30)) -delete 2>/dev/null || true

# 15. Verify backup integrity
log "Verifying backup integrity..."
if tar -tzf $BACKUP_DIR/$BACKUP_TYPE/backup_$DATE.tar.gz >/dev/null 2>&1; then
    log "Backup verification successful"
else
    log "ERROR: Backup verification failed"
    exit 1
fi

# 16. Calculate backup size
BACKUP_SIZE=$(du -h $BACKUP_DIR/$BACKUP_TYPE/backup_$DATE.tar.gz | cut -f1)

# 17. Send notification
log "Sending backup notification..."
if command -v mail >/dev/null 2>&1; then
cat << MAIL | mail -s "[MikroTik VPN] Backup Completed - $BACKUP_TYPE" "$ADMIN_EMAIL"
Backup completed successfully!

Type: $BACKUP_TYPE
Date: $DATE
Size: $BACKUP_SIZE
Location: $BACKUP_DIR/$BACKUP_TYPE/backup_$DATE.tar.gz

System Status:
$(docker ps --format "table {{.Names}}\t{{.Status}}" | grep mikrotik)

Disk Usage:
$(df -h $BACKUP_DIR)
MAIL
fi

log "=== Backup Summary ==="
log "Type: $BACKUP_TYPE"
log "Date: $DATE"
log "Size: $BACKUP_SIZE"
log "Location: $BACKUP_DIR/$BACKUP_TYPE/backup_$DATE.tar.gz"
log "Backup completed successfully!"
EOF

    chmod +x $SCRIPT_DIR/backup-system.sh

    # Restore script
    cat << 'EOF' > $SCRIPT_DIR/restore-system.sh
#!/bin/bash
# MikroTik VPN System Restore Script

BACKUP_DIR="/opt/mikrotik-vpn/backups"
LOG_FILE="/var/log/mikrotik-vpn/restore.log"
SYSTEM_DIR="/opt/mikrotik-vpn"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# Function to list available backups
list_backups() {
    echo "Available backups:"
    echo "=================="
    
    for type in daily weekly monthly; do
        echo -e "\n$type backups:"
        if [ -d "$BACKUP_DIR/$type" ]; then
            ls -1 $BACKUP_DIR/$type/*.tar.gz 2>/dev/null | sort -r | head -10 || echo "  No backups found"
        else
            echo "  No backups found"
        fi
    done
}

# Function to validate backup
validate_backup() {
    local backup_file=$1
    local temp_dir="/tmp/restore_validate_$(date +%s)"
    
    log "Validating backup file..."
    
    # Check if file exists
    if [ ! -f "$backup_file" ]; then
        log "ERROR: Backup file not found: $backup_file"
        return 1
    fi
    
    # Try to list contents
    if ! tar -tzf "$backup_file" >/dev/null 2>&1; then
        log "ERROR: Invalid backup file format"
        return 1
    fi
    
    # Extract and check manifest
    mkdir -p $temp_dir
    if tar -xzf "$backup_file" -C $temp_dir --wildcards "*/manifest.json" 2>/dev/null; then
        local manifest=$(find $temp_dir -name "manifest.json" -type f | head -1)
        if [ -f "$manifest" ]; then
            log "Backup manifest found:"
            cat "$manifest" | tee -a $LOG_FILE
        fi
    fi
    
    rm -rf $temp_dir
    return 0
}

# Function to restore from backup
restore_backup() {
    local backup_file=$1
    local temp_dir="/tmp/restore_$(date +%s)"
    
    if [ ! -f "$backup_file" ]; then
        log "ERROR: Backup file not found: $backup_file"
        exit 1
    fi
    
    log "Starting restore from: $backup_file"
    
    # Validate backup first
    if ! validate_backup "$backup_file"; then
        log "ERROR: Backup validation failed"
        exit 1
    fi
    
    # Create confirmation prompt
    echo
    echo "WARNING: This will overwrite the current system configuration!"
    echo "Current containers will be stopped and data will be replaced."
    echo
    read -p "Are you sure you want to continue? Type 'RESTORE' to confirm: " confirm
    
    if [ "$confirm" != "RESTORE" ]; then
        log "Restore cancelled by user"
        exit 0
    fi
    
    # Create restore point
    log "Creating restore point..."
    $SYSTEM_DIR/scripts/backup-system.sh || log "WARNING: Failed to create restore point"
    
    # Extract backup
    log "Extracting backup..."
    mkdir -p $temp_dir
    tar -xzf $backup_file -C $temp_dir
    
    # Find extracted directory
    backup_dir=$(find $temp_dir -maxdepth 1 -type d -name "backup_*" | head -1)
    
    if [ -z "$backup_dir" ]; then
        log "ERROR: Could not find backup directory in archive"
        rm -rf $temp_dir
        exit 1
    fi
    
    # Load environment from backup
    if [ -f "$backup_dir/configs.tar.gz" ]; then
        log "Extracting configuration..."
        tar -xzf $backup_dir/configs.tar.gz -C / 2>/dev/null || true
    fi
    
    # Load environment variables
    if [ -f "/opt/mikrotik-vpn/configs/setup.env" ]; then
        log "Loading environment from backup..."
        source /opt/mikrotik-vpn/configs/setup.env
    fi
    
    # Verify checksums
    log "Verifying backup integrity..."
    cd $backup_dir
    if [ -f checksums.sha256 ]; then
        if sha256sum -c checksums.sha256 --quiet 2>/dev/null; then
            log "Backup integrity verified"
        else
            log "WARNING: Some files failed integrity check"
        fi
    else
        log "WARNING: No checksums found, skipping integrity check"
    fi
    
    # Stop all services
    log "Stopping all services..."
    cd $SYSTEM_DIR
    $SCRIPT_DIR/stop-all-services.sh || true
    
    # Give services time to stop
    sleep 10
    
    # Restore MongoDB
    log "Restoring MongoDB..."
    docker compose -f docker-compose-mongodb.yml up -d
    
    # Wait for MongoDB to be ready
    for i in {1..30}; do
        if docker exec mikrotik-mongodb mongosh --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    if [ -d "$backup_dir/mongodb-backup" ]; then
        docker cp $backup_dir/mongodb-backup mikrotik-mongodb:/tmp/
        docker exec mikrotik-mongodb mongorestore \
            --host localhost \
            --username admin \
            --password $MONGO_ROOT_PASSWORD \
            --authenticationDatabase admin \
            --drop \
            --gzip \
            /tmp/mongodb-backup 2>/dev/null || log "WARNING: MongoDB restore had issues"
        docker exec mikrotik-mongodb rm -rf /tmp/mongodb-backup
    fi
    
    # Restore Redis
    log "Restoring Redis..."
    docker compose -f docker-compose-redis.yml down
    if [ -f "$backup_dir/redis_dump.rdb" ]; then
        docker run --rm -v mikrotik-redis-data:/data alpine \
            sh -c "rm -f /data/dump.rdb /data/appendonly.aof"
        docker cp $backup_dir/redis_dump.rdb mikrotik-redis:/data/dump.rdb 2>/dev/null || true
        docker cp $backup_dir/redis_appendonly.aof mikrotik-redis:/data/appendonly.aof 2>/dev/null || true
    fi
    docker compose -f docker-compose-redis.yml up -d
    
    # Restore SSL certificates
    log "Restoring SSL certificates..."
    if [ -f "$backup_dir/ssl.tar.gz" ]; then
        cd /
        tar -xzf $backup_dir/ssl.tar.gz 2>/dev/null || true
    fi
    
    # Restore Docker volumes
    log "Restoring Docker volumes..."
    if [ -f "$backup_dir/prometheus_data.tar.gz" ]; then
        docker run --rm -v prometheus_data:/data -v $backup_dir:/backup alpine \
            tar -xzf /backup/prometheus_data.tar.gz -C /data 2>/dev/null || true
    fi
    if [ -f "$backup_dir/grafana_data.tar.gz" ]; then
        docker run --rm -v grafana_data:/data -v $backup_dir:/backup alpine \
            tar -xzf /backup/grafana_data.tar.gz -C /data 2>/dev/null || true
    fi
    
    # Restore VPN clients
    log "Restoring VPN client configurations..."
    if [ -f "$backup_dir/vpn_clients.tar.gz" ]; then
        cd /
        tar -xzf $backup_dir/vpn_clients.tar.gz 2>/dev/null || true
    fi
    
    # Fix permissions
    log "Fixing permissions..."
    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR
    chmod 600 $SYSTEM_DIR/configs/setup.env 2>/dev/null || true
    chmod 600 $SYSTEM_DIR/configs/l2tp-credentials.txt 2>/dev/null || true
    chmod -R 755 $SCRIPT_DIR
    
    # Start all services
    log "Starting all services..."
    cd $SYSTEM_DIR
    $SCRIPT_DIR/start-all-services.sh
    
    # Wait for services to stabilize
    log "Waiting for services to stabilize..."
    sleep 30
    
    # Verify services
    log "Verifying services..."
    docker ps --format "table {{.Names}}\t{{.Status}}" | grep mikrotik | tee -a $LOG_FILE
    
    # Cleanup
    rm -rf $temp_dir
    
    log "Restore completed successfully!"
    log "Please verify all services are working correctly"
    
    # Run health check
    $SCRIPT_DIR/health-check.sh || log "WARNING: Some health checks failed"
}

# Main menu
main() {
    case "${1:-menu}" in
        "list")
            list_backups
            ;;
        "restore")
            if [ -z "$2" ]; then
                echo "Usage: $0 restore <backup_file>"
                echo
                list_backups
                exit 1
            fi
            restore_backup "$2"
            ;;
        "validate")
            if [ -z "$2" ]; then
                echo "Usage: $0 validate <backup_file>"
                exit 1
            fi
            if validate_backup "$2"; then
                echo "Backup validation passed"
            else
                echo "Backup validation failed"
                exit 1
            fi
            ;;
        "menu"|*)
            echo "MikroTik VPN System Restore Utility"
            echo "===================================="
            echo
            echo "Usage: $0 [command] [options]"
            echo
            echo "Commands:"
            echo "  list              - List available backups"
            echo "  restore <file>    - Restore from backup file"
            echo "  validate <file>   - Validate backup file"
            echo
            echo "Examples:"
            echo "  $0 list"
            echo "  $0 restore /opt/mikrotik-vpn/backups/daily/backup_20240101_120000.tar.gz"
            echo "  $0 validate /opt/mikrotik-vpn/backups/daily/backup_20240101_120000.tar.gz"
            ;;
    esac
}

main "$@"
EOF

    chmod +x $SCRIPT_DIR/restore-system.sh
}

setup_backup_automation() {
    # Create cron jobs for automated backups
    cat << EOF > /etc/cron.d/mikrotik-vpn-backup
# MikroTik VPN System Backup Schedule
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=$ADMIN_EMAIL

# Daily backup at 2:00 AM
0 2 * * * mikrotik-vpn /opt/mikrotik-vpn/scripts/backup-system.sh >> /var/log/mikrotik-vpn/backup-cron.log 2>&1

# Weekly cleanup at 3:00 AM on Sundays
0 3 * * 0 mikrotik-vpn /opt/mikrotik-vpn/scripts/cleanup-old-backups.sh >> /var/log/mikrotik-vpn/backup-cleanup.log 2>&1

# Monthly backup verification at 4:00 AM on the 1st
0 4 1 * * mikrotik-vpn /opt/mikrotik-vpn/scripts/verify-backups.sh >> /var/log/mikrotik-vpn/backup-verify.log 2>&1
EOF

    # Create cleanup script
    cat << 'EOF' > $SCRIPT_DIR/cleanup-old-backups.sh
#!/bin/bash
# Old backup cleanup script

BACKUP_DIR="/opt/mikrotik-vpn/backups"
LOG_FILE="/var/log/mikrotik-vpn/backup-cleanup.log"

# Retention periods (in days)
DAILY_RETENTION=7
WEEKLY_RETENTION=28
MONTHLY_RETENTION=365

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting backup cleanup..."

# Function to cleanup old backups
cleanup_old_backups() {
    local backup_type=$1
    local retention_days=$2
    local backup_path="$BACKUP_DIR/$backup_type"
    
    if [ -d "$backup_path" ]; then
        log "Cleaning up $backup_type backups older than $retention_days days..."
        
        # Find and remove old backups
        old_backups=$(find "$backup_path" -name "*.tar.gz" -type f -mtime +$retention_days 2>/dev/null)
        
        if [ -n "$old_backups" ]; then
            echo "$old_backups" | while read -r backup; do
                log "Removing old backup: $backup"
                rm -f "$backup"
            done
            
            count=$(echo "$old_backups" | wc -l)
            log "Removed $count old $backup_type backups"
        else
            log "No old $backup_type backups found for cleanup"
        fi
    else
        log "Backup directory $backup_path does not exist"
    fi
}

# Calculate total backup size before cleanup
BEFORE_SIZE=$(du -sh $BACKUP_DIR 2>/dev/null | cut -f1)
log "Backup directory size before cleanup: $BEFORE_SIZE"

# Cleanup each backup type
cleanup_old_backups "daily" $DAILY_RETENTION
cleanup_old_backups "weekly" $WEEKLY_RETENTION
cleanup_old_backups "monthly" $MONTHLY_RETENTION

# Cleanup orphaned files
log "Cleaning up orphaned files..."
find $BACKUP_DIR -type f -name "*.tmp" -delete 2>/dev/null || true
find $BACKUP_DIR -type f -name "*.partial" -delete 2>/dev/null || true
find $BACKUP_DIR -empty -type d -delete 2>/dev/null || true

# Cleanup log files older than 90 days
log "Cleaning up old log files..."
find /var/log/mikrotik-vpn -name "*.log" -type f -mtime +90 -exec gzip {} \; 2>/dev/null || true
find /var/log/mikrotik-vpn -name "*.gz" -type f -mtime +180 -delete 2>/dev/null || true

# Calculate total backup size after cleanup
AFTER_SIZE=$(du -sh $BACKUP_DIR 2>/dev/null | cut -f1)
log "Backup directory size after cleanup: $AFTER_SIZE"

# Report current backup inventory
log "Current backup inventory:"
for type in daily weekly monthly; do
    if [ -d "$BACKUP_DIR/$type" ]; then
        count=$(ls -1 $BACKUP_DIR/$type/*.tar.gz 2>/dev/null | wc -l)
        size=$(du -sh $BACKUP_DIR/$type 2>/dev/null | cut -f1)
        log "  $type: $count backups, $size total"
    fi
done

# Check available disk space
DISK_USAGE=$(df -h $BACKUP_DIR | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    log "WARNING: Disk usage is high: $DISK_USAGE%"
    # Send alert
    echo "Disk usage on backup partition is $DISK_USAGE%" | mail -s "[MikroTik VPN] High Disk Usage Alert" $ADMIN_EMAIL
fi

log "Backup cleanup completed"
EOF

    chmod +x $SCRIPT_DIR/cleanup-old-backups.sh

    # Create backup verification script
    cat << 'EOF' > $SCRIPT_DIR/verify-backups.sh
#!/bin/bash
# Backup verification script

BACKUP_DIR="/opt/mikrotik-vpn/backups"
LOG_FILE="/var/log/mikrotik-vpn/backup-verify.log"
FAILED_BACKUPS=""

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

verify_backup() {
    local backup_file=$1
    local backup_name=$(basename $backup_file)
    
    log "Verifying $backup_name..."
    
    # Check file exists and is readable
    if [ ! -r "$backup_file" ]; then
        log "ERROR: Cannot read backup file"
        FAILED_BACKUPS="${FAILED_BACKUPS:-}${FAILED_BACKUPS:+\n}${backup_file}"
        return 1
    fi
    
    # Check file size
    size=$(stat -c%s "$backup_file" 2>/dev/null)
    if [ "$size" -lt 1024 ]; then
        log "ERROR: Backup file too small (${size} bytes)"
        FAILED_BACKUPS="${FAILED_BACKUPS:-}${FAILED_BACKUPS:+\n}${backup_file}"
        return 1
    fi
    
    # Verify tar integrity
    if ! tar -tzf "$backup_file" >/dev/null 2>&1; then
        log "ERROR: Backup file is corrupted"
        FAILED_BACKUPS="${FAILED_BACKUPS:-}${FAILED_BACKUPS:+\n}${backup_file}"
        return 1
    fi
    
    # Extract and verify manifest
    manifest=$(tar -xzf "$backup_file" --to-stdout --wildcards "*/manifest.json" 2>/dev/null)
    if [ -z "$manifest" ]; then
        log "WARNING: No manifest found in backup"
    fi
    
    log "✓ Backup verified successfully"
    return 0
}

log "Starting backup verification..."

# Verify all backups
for type in daily weekly monthly; do
    if [ -d "$BACKUP_DIR/$type" ]; then
        log "Verifying $type backups..."
        for backup in $BACKUP_DIR/$type/*.tar.gz; do
            if [ -f "$backup" ]; then
                verify_backup "$backup"
            fi
        done
    fi
done

# Report results
if [ -n "$FAILED_BACKUPS" ]; then
    log "ERROR: The following backups failed verification:$FAILED_BACKUPS"
    echo -e "The following backups failed verification:$FAILED_BACKUPS" | \
        mail -s "[MikroTik VPN] Backup Verification Failed" $ADMIN_EMAIL
else
    log "All backups verified successfully"
fi

log "Backup verification completed"
EOF

    chmod +x $SCRIPT_DIR/verify-backups.sh

    # Create logrotate configuration
    cat << EOF > /etc/logrotate.d/mikrotik-vpn
/var/log/mikrotik-vpn/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 mikrotik-vpn mikrotik-vpn
    sharedscripts
    postrotate
        # Reload services if needed
        docker exec mikrotik-nginx nginx -s reload >/dev/null 2>&1 || true
        docker exec mikrotik-app pm2 flush >/dev/null 2>&1 || true
    endscript
}
EOF
}

create_disaster_recovery() {
    # Create disaster recovery documentation
    cat << EOF > $SYSTEM_DIR/DISASTER_RECOVERY.md
# MikroTik VPN System Disaster Recovery Guide

## Overview
This guide provides procedures for recovering the MikroTik VPN Management System in various disaster scenarios.

## Backup Locations
- Local: /opt/mikrotik-vpn/backups/
- Remote: Configure in backup-system.sh

## Recovery Scenarios

### 1. Complete System Failure
1. Install fresh Ubuntu 22.04 LTS
2. Download installation script
3. Run: sudo ./install-mikrotik-vpn.sh
4. Restore from backup: sudo /opt/mikrotik-vpn/scripts/restore-system.sh restore <backup_file>

### 2. Database Corruption
1. Stop affected database: docker compose -f docker-compose-mongodb.yml down
2. Restore database from backup
3. Start database: docker compose -f docker-compose-mongodb.yml up -d

### 3. Service Failure
1. Check service status: docker ps -a
2. View logs: docker logs <container_name>
3. Restart service: docker compose -f docker-compose-<service>.yml restart

### 4. Network Issues
1. Check firewall: sudo ufw status
2. Verify Docker network: docker network ls
3. Recreate network if needed: docker network create mikrotik-vpn-net --subnet=172.20.0.0/16

## Important Files
- Configuration: /opt/mikrotik-vpn/configs/setup.env
- SSL Certificates: /opt/mikrotik-vpn/nginx/ssl/
- VPN Configs: /opt/mikrotik-vpn/openvpn/
- Database Data: /opt/mikrotik-vpn/mongodb/data/

## Emergency Contacts
- Admin Email: $ADMIN_EMAIL
- Domain: $DOMAIN_NAME

## Recovery Checklist
[ ] Verify system requirements
[ ] Check network connectivity
[ ] Restore from latest backup
[ ] Verify all services running
[ ] Test VPN connections
[ ] Verify web access
[ ] Check monitoring dashboards
[ ] Test user authentication
[ ] Verify backup automation

Generated on: $(date)
EOF

    # Create emergency recovery script
    cat << 'EOF' > $SCRIPT_DIR/emergency-recovery.sh
#!/bin/bash
# Emergency recovery script for critical failures

SYSTEM_DIR="/opt/mikrotik-vpn"
LOG_FILE="/var/log/mikrotik-vpn/emergency-recovery.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting emergency recovery..."

# 1. Stop all services
log "Stopping all services..."
cd $SYSTEM_DIR
for compose_file in docker-compose-*.yml; do
    if [ -f "$compose_file" ]; then
        docker compose -f "$compose_file" down 2>/dev/null || true
    fi
done

# 2. Clean up Docker
log "Cleaning up Docker..."
docker system prune -f
docker volume prune -f

# 3. Recreate network
log "Recreating Docker network..."
docker network rm mikrotik-vpn-net 2>/dev/null || true
docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16

# 4. Start core services only
log "Starting core services..."
docker compose -f docker-compose-mongodb.yml up -d
sleep 10
docker compose -f docker-compose-redis.yml up -d
sleep 5

# 5. Verify core services
if docker ps | grep -q mikrotik-mongodb && docker ps | grep -q mikrotik-redis; then
    log "Core services started successfully"
else
    log "ERROR: Core services failed to start"
    exit 1
fi

# 6. Start remaining services
log "Starting remaining services..."
docker compose -f docker-compose-openvpn.yml up -d
docker compose -f docker-compose-app.yml up -d
docker compose -f docker-compose-nginx.yml up -d
docker compose -f docker-compose-monitoring.yml up -d

# 7. Health check
sleep 30
$SYSTEM_DIR/scripts/health-check.sh

log "Emergency recovery completed"
EOF

    chmod +x $SCRIPT_DIR/emergency-recovery.sh
}

# =============================================================================
# PHASE 10: MANAGEMENT SCRIPTS AND FINAL SETUP
# =============================================================================

phase10_management_scripts() {
    log "==================================================================="
    log "PHASE 10: MANAGEMENT SCRIPTS AND FINAL SETUP"
    log "==================================================================="
    
    log "Creating management scripts..."
    create_management_scripts
    
    log "Setting up system service..."
    setup_system_service
    
    log "Creating maintenance scripts..."
    create_maintenance_scripts
    
    log "Creating final configuration..."
    create_final_configuration
    
    log "Phase 10 completed successfully!"
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
SCRIPT_DIR="/opt/mikrotik-vpn/scripts"

# Load environment
if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
    source $SYSTEM_DIR/configs/setup.env
fi

# Functions
print_header() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}              MikroTik VPN Management System v2.0${NC}"
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
    
    if docker ps | grep -q mikrotik-l2tp; then
        echo "L2TP/IPSec: Running"
    else
        echo "L2TP/IPSec: Not Running"
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
    
    # Web services status
    echo -e "${PURPLE}Web Services:${NC}"
    if docker ps | grep -q mikrotik-nginx; then
        echo "Nginx: Running"
        echo "Web Interface: https://$DOMAIN_NAME"
        echo "Admin Panel: https://admin.$DOMAIN_NAME"
    else
        echo "Nginx: Not Running"
    fi
    
    if docker ps | grep -q mikrotik-app; then
        echo "Application: Running"
    else
        echo "Application: Not Running"
    fi
    echo
}

# Service management functions
start_all_services() {
    print_status "Starting all MikroTik VPN services..."
    $SCRIPT_DIR/start-all-services.sh
}

stop_all_services() {
    print_status "Stopping all MikroTik VPN services..."
    $SCRIPT_DIR/stop-all-services.sh
}

restart_all_services() {
    print_status "Restarting all services..."
    stop_all_services
    sleep 5
    start_all_services
}

# VPN client management
manage_vpn_clients() {
    local action=$1
    local client_name=$2
    
    case $action in
        "create")
            if [ -z "$client_name" ]; then
                read -p "Enter client name: " client_name
            fi
            
            print_status "Creating VPN client configuration for: $client_name"
            $SCRIPT_DIR/generate-vpn-client.sh "$client_name"
            ;;
        
        "list")
            print_status "Available VPN client configurations:"
            echo
            if [ -d "$SYSTEM_DIR/clients" ]; then
                for client in $SYSTEM_DIR/clients/*.ovpn; do
                    if [ -f "$client" ]; then
                        basename "$client" .ovpn
                    fi
                done | sort
            else
                echo "No client configurations found"
            fi
            ;;
        
        *)
            echo "VPN Client Management:"
            echo "  create <name>  - Create new VPN client"
            echo "  list           - List existing clients"
            ;;
    esac
}

# Backup management
manage_backups() {
    local action=$1
    
    case $action in
        "create")
            print_status "Creating backup..."
            $SCRIPT_DIR/backup-system.sh
            ;;
        
        "list")
            print_status "Available backups:"
            $SCRIPT_DIR/restore-system.sh list
            ;;
        
        "restore")
            local backup_file=$2
            if [ -z "$backup_file" ]; then
                $SCRIPT_DIR/restore-system.sh list
                echo
                read -p "Enter backup file path: " backup_file
            fi
            $SCRIPT_DIR/restore-system.sh restore "$backup_file"
            ;;
        
        *)
            echo "Backup Management:"
            echo "  create         - Create backup now"
            echo "  list           - List available backups"
            echo "  restore [file] - Restore from backup"
            ;;
    esac
}

# Logs management
view_logs() {
    local service=$1
    
    case $service in
        "all")
            print_status "Viewing all logs..."
            cd $SYSTEM_DIR
            docker compose -f docker-compose-*.yml logs -f
            ;;
        
        "app")
            docker logs -f mikrotik-app
            ;;
        
        "nginx")
            docker logs -f mikrotik-nginx
            ;;
        
        "mongodb")
            docker logs -f mikrotik-mongodb
            ;;
        
        "redis")
            docker logs -f mikrotik-redis
            ;;
        
        "openvpn")
            docker logs -f mikrotik-openvpn
            ;;
        
        *)
            echo "Available log sources:"
            echo "  all        - All services"
            echo "  app        - Application"
            echo "  nginx      - Web server"
            echo "  mongodb    - MongoDB database"
            echo "  redis      - Redis cache"
            echo "  openvpn    - OpenVPN server"
            ;;
    esac
}

# Main script logic
main() {
    check_root
    
    case "${1:-help}" in
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
        
        "vpn")
            manage_vpn_clients "$2" "$3"
            ;;
        
        "backup")
            manage_backups "$2" "$3"
            ;;
        
        "logs")
            view_logs "$2"
            ;;
        
        "health")
            $SCRIPT_DIR/health-check.sh
            ;;
        
        "update")
            print_status "Checking for updates..."
            cd $SYSTEM_DIR
            docker compose -f docker-compose-*.yml pull
            restart_all_services
            print_status "System updated"
            ;;
        
        "help"|"-h"|"--help")
            print_header
            echo "Usage: $0 [command] [options]"
            echo
            echo "System Commands:"
            echo "  status              - Show system status"
            echo "  start               - Start all services"
            echo "  stop                - Stop all services"
            echo "  restart             - Restart all services"
            echo "  health              - Run health check"
            echo "  update              - Update system containers"
            echo
            echo "VPN Management:"
            echo "  vpn create <name>   - Create new VPN client"
            echo "  vpn list            - List VPN clients"
            echo
            echo "Backup Management:"
            echo "  backup create       - Create backup now"
            echo "  backup list         - List backups"
            echo "  backup restore      - Restore from backup"
            echo
            echo "Monitoring:"
            echo "  logs <service>      - View service logs"
            echo "  health              - System health check"
            echo
            echo "Examples:"
            echo "  $0 status"
            echo "  $0 vpn create john-doe"
            echo "  $0 backup create"
            echo "  $0 logs nginx"
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
    
    # Create symbolic link for easy access
    ln -sf $SYSTEM_DIR/mikrotik-vpn-manager.sh /usr/local/bin/mikrotik-vpn

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
docker compose -f docker-compose-l2tp.yml up -d

echo "Starting application..."
docker compose -f docker-compose-app.yml up -d

echo "Starting web server..."
docker compose -f docker-compose-nginx.yml up -d

echo "Starting monitoring..."
docker compose -f docker-compose-monitoring.yml up -d

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
docker compose -f docker-compose-monitoring.yml down 2>/dev/null || true
docker compose -f docker-compose-nginx.yml down 2>/dev/null || true
docker compose -f docker-compose-app.yml down 2>/dev/null || true
docker compose -f docker-compose-l2tp.yml down 2>/dev/null || true
docker compose -f docker-compose-openvpn.yml down 2>/dev/null || true
docker compose -f docker-compose-redis.yml down 2>/dev/null || true
docker compose -f docker-compose-mongodb.yml down 2>/dev/null || true

echo "All services stopped!"
EOF

    chmod +x $SCRIPT_DIR/stop-all-services.sh
}

setup_system_service() {
    # Create systemd service
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
ExecStart=/opt/mikrotik-vpn/scripts/start-all-services.sh
ExecStop=/opt/mikrotik-vpn/scripts/stop-all-services.sh
TimeoutStartSec=300
TimeoutStopSec=120
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Enable service
    systemctl daemon-reload
    systemctl enable mikrotik-vpn.service
    
    log "SystemD service created and enabled"
}

create_maintenance_scripts() {
    # Health check script
    cat << 'EOF' > $SCRIPT_DIR/health-check.sh
#!/bin/bash
# Comprehensive health check script

LOG_FILE="/var/log/mikrotik-vpn/health-check.log"
FAILED_CHECKS=""
WARNING_CHECKS=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

print_ok() {
    echo -e "${GREEN}✓${NC} $1"
    log "✓ $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    log "⚠ $1"
    WARNING_CHECKS="${WARNING_CHECKS:-}${WARNING_CHECKS:+\n}- $1"
}

print_fail() {
    echo -e "${RED}✗${NC} $1"
    log "✗ $1"
    FAILED_CHECKS="$FAILED_CHECKS\n- $1"
}

check_service() {
    local service=$1
    local container_name="mikrotik-$service"
    
    if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        if docker ps --format "{{.Names}} {{.Status}}" | grep "^${container_name}" | grep -q "Up"; then
            # Additional health check
            case $service in
                "mongodb")
                    if docker exec $container_name mongosh --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
                        print_ok "$service is running and responding"
                    else
                        print_fail "$service is running but not responding"
                    fi
                    ;;
                "redis")
                    if docker exec $container_name redis-cli ping >/dev/null 2>&1; then
                        print_ok "$service is running and responding"
                    else
                        print_fail "$service is running but not responding"
                    fi
                    ;;
                "nginx")
                    if curl -s -o /dev/null -w "%{http_code}" http://localhost >/dev/null 2>&1; then
                        print_ok "$service is running and responding"
                    else
                        print_warning "$service is running but not responding on port 80"
                    fi
                    ;;
                *)
                    print_ok "$service is running"
                    ;;
            esac
        else
            print_fail "$service container exists but not healthy"
        fi
    else
        print_fail "$service container not found"
    fi
}

check_disk_space() {
    local usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$usage" -lt 70 ]; then
        print_ok "Disk usage is acceptable ($usage%)"
    elif [ "$usage" -lt 85 ]; then
        print_warning "Disk usage is getting high ($usage%)"
    else
        print_fail "Disk usage is critical ($usage%)"
    fi
}

check_memory() {
    local usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    
    if [ "$usage" -lt 70 ]; then
        print_ok "Memory usage is acceptable ($usage%)"
    elif [ "$usage" -lt 85 ]; then
        print_warning "Memory usage is high ($usage%)"
    else
        print_fail "Memory usage is critical ($usage%)"
    fi
}

check_network() {
    # Check Docker network
    if docker network ls | grep -q mikrotik-vpn-net; then
        print_ok "Docker network exists"
    else
        print_fail "Docker network missing"
    fi
    
    # Check internet connectivity
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        print_ok "Internet connectivity OK"
    else
        print_warning "No internet connectivity"
    fi
}

check_certificates() {
    local cert_file="/opt/mikrotik-vpn/nginx/ssl/fullchain.pem"
    
    if [ -f "$cert_file" ]; then
        # Check certificate expiry
        local expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s)
        local current_epoch=$(date +%s)
        local days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
        
        if [ $days_left -gt 30 ]; then
            print_ok "SSL certificate valid for $days_left days"
        elif [ $days_left -gt 7 ]; then
            print_warning "SSL certificate expires in $days_left days"
        else
            print_fail "SSL certificate expires in $days_left days!"
        fi
    else
        print_warning "SSL certificate file not found"
    fi
}

check_backups() {
    local backup_dir="/opt/mikrotik-vpn/backups"
    local latest_backup=$(find $backup_dir -name "*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    
    if [ -n "$latest_backup" ]; then
        local backup_age=$(( ($(date +%s) - $(stat -c %Y "$latest_backup")) / 86400 ))
        
        if [ $backup_age -lt 2 ]; then
            print_ok "Latest backup is $backup_age days old"
        elif [ $backup_age -lt 7 ]; then
            print_warning "Latest backup is $backup_age days old"
        else
            print_fail "Latest backup is $backup_age days old!"
        fi
    else
        print_fail "No backups found"
    fi
}

# Main health check execution
main() {
    echo "=== MikroTik VPN System Health Check ==="
    echo "Timestamp: $(date)"
    echo "Hostname: $(hostname)"
    echo
    
    # Check all critical services
    echo "Checking Docker services..."
    check_service "mongodb"
    check_service "redis"
    check_service "app"
    check_service "nginx"
    check_service "openvpn"
    check_service "prometheus"
    check_service "grafana"
    echo
    
    # Check system resources
    echo "Checking system resources..."
    check_disk_space
    check_memory
    echo
    
    # Check network
    echo "Checking network..."
    check_network
    echo
    
    # Check certificates
    echo "Checking certificates..."
    check_certificates
    echo
    
    # Check backups
    echo "Checking backups..."
    check_backups
    echo
    
    # Summary
    echo "=== Health Check Summary ==="
    if [ -n "$FAILED_CHECKS" ]; then
        echo -e "${RED}Failed checks:${NC}$FAILED_CHECKS"
        echo
    fi
    
    if [ -n "$WARNING_CHECKS" ]; then
        echo -e "${YELLOW}Warnings:${NC}$WARNING_CHECKS"
        echo
    fi
    
    if [ -z "$FAILED_CHECKS" ] && [ -z "$WARNING_CHECKS" ]; then
        echo -e "${GREEN}All health checks passed!${NC}"
        exit 0
    elif [ -z "$FAILED_CHECKS" ]; then
        echo -e "${YELLOW}Health check completed with warnings${NC}"
        exit 0
    else
        echo -e "${RED}Health check failed!${NC}"
        exit 1
    fi
}

main "$@"
EOF

    chmod +x $SCRIPT_DIR/health-check.sh

    # System optimization script
    cat << 'EOF' > $SCRIPT_DIR/optimize-system.sh
#!/bin/bash
# System optimization script

LOG_FILE="/var/log/mikrotik-vpn/optimization.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting system optimization..."

# 1. Docker cleanup
log "Cleaning up Docker..."

# Remove stopped containers
docker container prune -f

# Remove unused images
docker image prune -a -f

# Remove unused volumes (careful with this)
docker volume ls -qf dangling=true | xargs -r docker volume rm

# Remove unused networks
docker network prune -f

# Clean build cache
docker builder prune -f

# 2. Log rotation
log "Rotating logs..."

# Compress old logs
find /var/log -name "*.log" -size +100M -exec gzip {} \; 2>/dev/null || true

# Truncate large active logs
find /opt/mikrotik-vpn/logs -name "*.log" -size +50M -exec truncate -s 10M {} \; 2>/dev/null || true

# Remove old compressed logs
find /var/log -name "*.gz" -mtime +30 -delete 2>/dev/null || true

# 3. MongoDB optimization
log "Optimizing MongoDB..."
docker exec mikrotik-mongodb mongosh mikrotik_vpn --eval "db.adminCommand({compact: 'devices'})" 2>/dev/null || true

# 4. Redis optimization
log "Optimizing Redis..."
docker exec mikrotik-redis redis-cli --pass $REDIS_PASSWORD BGREWRITEAOF 2>/dev/null || true

# 5. System cache cleanup
log "Cleaning system cache..."
sync
echo 3 > /proc/sys/vm/drop_caches

# 6. Package cache cleanup
log "Cleaning package cache..."
apt-get autoremove -y
apt-get autoclean
apt-get clean

# Report disk usage
log "Current disk usage:"
df -h | tee -a $LOG_FILE

log "System optimization completed"
EOF

    chmod +x $SCRIPT_DIR/optimize-system.sh
}

create_final_configuration() {
    # Create installation completion script
    cat << 'EOF' > $SCRIPT_DIR/complete-installation.sh
#!/bin/bash
# Installation completion script

echo "==================================================================="
echo "MikroTik VPN Management System Installation Complete!"
echo "==================================================================="
echo
echo "Access Information:"
echo "  Web Interface: https://$DOMAIN_NAME"
echo "  Admin Panel: https://admin.$DOMAIN_NAME"
echo "  Grafana: https://$DOMAIN_NAME:3001 (admin / $MONGO_ROOT_PASSWORD)"
echo
echo "SSH Access:"
echo "  Port: $SSH_PORT"
echo "  User: mikrotik-vpn or $SUDO_USER"
echo
echo "Database Access:"
echo "  MongoDB: localhost:27017 (admin / $MONGO_ROOT_PASSWORD)"
echo "  Redis: localhost:6379 (password: $REDIS_PASSWORD)"
echo
echo "VPN Access:"
echo "  OpenVPN: $DOMAIN_NAME:1194"
echo "  L2TP/IPSec: $DOMAIN_NAME (check /opt/mikrotik-vpn/configs/l2tp-credentials.txt)"
echo
echo "Management Commands:"
echo "  mikrotik-vpn status    - Check system status"
echo "  mikrotik-vpn start     - Start all services"
echo "  mikrotik-vpn stop      - Stop all services"
echo "  mikrotik-vpn restart   - Restart all services"
echo "  mikrotik-vpn health    - Run health check"
echo "  mikrotik-vpn help      - Show all commands"
echo
echo "Important Files:"
echo "  Configuration: /opt/mikrotik-vpn/configs/setup.env"
echo "  Logs: /var/log/mikrotik-vpn/"
echo "  Backups: /opt/mikrotik-vpn/backups/"
echo "  Scripts: /opt/mikrotik-vpn/scripts/"
echo
echo "Next Steps:"
echo "1. Run 'mikrotik-vpn health' to verify installation"
echo "2. Generate Let's Encrypt SSL certificate:"
echo "   docker compose -f /opt/mikrotik-vpn/docker-compose-certbot.yml run --rm certbot"
echo "3. Create your first VPN client:"
echo "   mikrotik-vpn vpn create <client-name>"
echo "4. Set up email configuration for alerts"
echo "5. Configure your MikroTik devices to connect via VPN"
echo
echo "Documentation: /opt/mikrotik-vpn/DISASTER_RECOVERY.md"
echo
echo "IMPORTANT: Change all default passwords immediately!"
echo "==================================================================="
EOF

    chmod +x $SCRIPT_DIR/complete-installation.sh
}

# =============================================================================
# MAIN INSTALLATION FUNCTION
# =============================================================================

main() {
    clear
    echo "==================================================================="
    echo "MikroTik VPN Management System Installer v2.0"
    echo "==================================================================="
    echo
    
    # Create initial directories
    create_initial_directories
    
    # Check root privileges
    check_root
    
    # Get user input
    get_user_input
    
    # Run installation phases
    phase1_system_preparation
    phase2_docker_installation
    phase3_vpn_server_setup
    phase4_database_setup
    phase5_webserver_setup
    phase6_application_setup
    phase7_monitoring_setup
    phase8_security_hardening
    phase9_backup_setup
    phase10_management_scripts
    
    # Start all services
    log "Starting all services..."
    cd $SYSTEM_DIR
    $SCRIPT_DIR/start-all-services.sh
    
    # Run initial health check
    sleep 30
    log "Running health check..."
    $SCRIPT_DIR/health-check.sh
    
    # Display completion message
    $SCRIPT_DIR/complete-installation.sh
    
    log "Installation completed successfully!"
}

main "$@"
exit 0
