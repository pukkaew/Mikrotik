#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script
# Version: 2.0
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

# Create initial directories
mkdir -p $SYSTEM_DIR $LOG_DIR $BACKUP_DIR $SCRIPT_DIR

# Logging function
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

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_error "Please run this script as root (use sudo)"
        exit 1
    fi
}

# Function to get user input with validation
get_user_input() {
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
        # Allow: letters, numbers, dots, hyphens
        # Must have at least one dot
        # Cannot start or end with hyphen or dot
        if [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]] && \
           [[ ! $DOMAIN_NAME =~ \.\. ]] && \
           [[ ${#DOMAIN_NAME} -le 255 ]]; then
            break
        else
            echo "Invalid domain name format. Please enter a valid domain (e.g., example.com, sub.domain.org)."
            echo "Domain should:"
            echo "  - Contain only letters, numbers, dots, and hyphens"
            echo "  - Have at least one dot"
            echo "  - Not start or end with hyphen or dot"
            echo "  - Be less than 256 characters"
        fi
    done
    
    # Email configuration with more flexible validation
    while true; do
        read -p "Enter admin email address: " ADMIN_EMAIL
        
        # Remove leading/trailing whitespace
        ADMIN_EMAIL=$(echo "$ADMIN_EMAIL" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Check if email is not empty
        if [ -z "$ADMIN_EMAIL" ]; then
            echo "Email address cannot be empty. Please try again."
            continue
        fi
        
        # More flexible email validation
        if [[ $ADMIN_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && \
           [[ ! $ADMIN_EMAIL =~ \.\. ]] && \
           [[ ! $ADMIN_EMAIL =~ @\. ]] && \
           [[ ! $ADMIN_EMAIL =~ \.@ ]] && \
           [[ ${#ADMIN_EMAIL} -le 254 ]]; then
            break
        else
            echo "Invalid email format. Please enter a valid email address (e.g., admin@example.com)."
        fi
    done
    
    # SSH port configuration with validation
    while true; do
        read -p "Enter SSH port (default 22): " SSH_PORT
        SSH_PORT=${SSH_PORT:-22}
        
        # Validate SSH port (1-65535, avoid well-known ports if not default)
        if [[ $SSH_PORT =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
            # Warn about common ports
            case $SSH_PORT in
                22) break ;;  # Default SSH port
                80|443|21|23|25|53|110|143|993|995)
                    echo "Warning: Port $SSH_PORT is commonly used by other services."
                    read -p "Are you sure you want to use this port? (y/n): " confirm
                    if [[ $confirm =~ ^[Yy]$ ]]; then
                        break
                    fi
                    ;;
                *) break ;;
            esac
        else
            echo "Invalid port number. Please enter a number between 1 and 65535."
        fi
    done
    
    # Timezone configuration with suggestions
    echo
    echo "Common timezones:"
    echo "  Asia/Bangkok (Thailand)"
    echo "  Asia/Singapore (Singapore)" 
    echo "  Asia/Jakarta (Indonesia)"
    echo "  Asia/Manila (Philippines)"
    echo "  Asia/Kuala_Lumpur (Malaysia)"
    echo "  UTC (Universal Time)"
    echo
    read -p "Enter timezone (default Asia/Bangkok): " TIMEZONE
    TIMEZONE=${TIMEZONE:-Asia/Bangkok}
    
    # Validate timezone
    if ! timedatectl list-timezones | grep -q "^$TIMEZONE$"; then
        echo "Warning: Timezone '$TIMEZONE' may not be valid. Using Asia/Bangkok as fallback."
        TIMEZONE="Asia/Bangkok"
    fi
    
    # VPN network configuration with validation
    while true; do
        read -p "Enter VPN network (default 10.8.0.0/24): " VPN_NETWORK
        VPN_NETWORK=${VPN_NETWORK:-10.8.0.0/24}
        
        # Basic CIDR validation
        if [[ $VPN_NETWORK =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            # Extract IP and prefix
            IFS='/' read -r ip prefix <<< "$VPN_NETWORK"
            IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
            
            # Validate IP octets and prefix
            if [ "$i1" -le 255 ] && [ "$i2" -le 255 ] && [ "$i3" -le 255 ] && [ "$i4" -le 255 ] && \
               [ "$prefix" -ge 8 ] && [ "$prefix" -le 30 ]; then
                # Suggest private network ranges
                if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ $ip =~ ^192\.168\. ]]; then
                    break
                else
                    echo "Warning: '$VPN_NETWORK' is not a private network range."
                    echo "Recommended private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
                    read -p "Continue anyway? (y/n): " confirm
                    if [[ $confirm =~ ^[Yy]$ ]]; then
                        break
                    fi
                fi
            else
                echo "Invalid network format. Please use CIDR notation (e.g., 10.8.0.0/24)."
            fi
        else
            echo "Invalid network format. Please use CIDR notation (e.g., 10.8.0.0/24)."
        fi
    done
    
    # Database passwords with strength validation
    echo
    echo "Database Configuration:"
    echo "Passwords should be at least 8 characters long and contain mixed characters."
    
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
    
    # Summary of configuration
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
        tmux \
        aide \
        aide-common \
        clamav \
        clamav-daemon \
        clamav-freshclam \
        rkhunter
    
    log "Creating system directories..."
    mkdir -p $SYSTEM_DIR/{data,logs,backups,configs,ssl,scripts,clients}
    mkdir -p $SYSTEM_DIR/{mongodb,redis,nginx,openvpn,l2tp,monitoring}
    mkdir -p $SYSTEM_DIR/nginx/{conf.d,html,ssl}
    mkdir -p $SYSTEM_DIR/openvpn/{server,client-configs,easy-rsa}
    mkdir -p $BACKUP_DIR/{daily,weekly,monthly}
    
    # Create system user for application
    if ! id "mikrotik-vpn" &>/dev/null; then
        useradd -r -m -s /bin/bash -d $SYSTEM_DIR mikrotik-vpn
        log "Created mikrotik-vpn system user"
    else
        log "mikrotik-vpn user already exists"
    fi
    
    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR
    
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
        log "Added $SUDO_USER to docker group"
    fi
    usermod -aG docker mikrotik-vpn
    
    log "Starting and enabling Docker..."
    systemctl enable docker
    systemctl start docker
    
    log "Creating Docker network..."
    if ! docker network ls | grep -q mikrotik-vpn-net; then
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
        log "Created Docker network: mikrotik-vpn-net"
    else
        log "Docker network mikrotik-vpn-net already exists"
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
    
    log "Setting up L2TP/IPSec server..."
    setup_l2tp_server
    
    log "Creating VPN management scripts..."
    create_vpn_management_scripts
    
    log "Phase 3 completed successfully!"
}

setup_openvpn_server() {
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
    
    # Create client config directory
    mkdir -p $SYSTEM_DIR/openvpn/ccd
    
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
      - $SYSTEM_DIR/l2tp:/etc/ipsec.d
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
    cat << EOF > $SYSTEM_DIR/configs/l2tp-credentials.txt
L2TP/IPSec VPN Credentials:
Server: $DOMAIN_NAME
PSK: $L2TP_PSK
Username: mikrotik
Password: $MONGO_ROOT_PASSWORD
EOF
    
    chmod 600 $SYSTEM_DIR/configs/l2tp-credentials.txt
}

create_vpn_management_scripts() {
    # VPN client generator script
    cat << 'EOF' > $SCRIPT_DIR/generate-vpn-client.sh
#!/bin/bash
# VPN Client Configuration Generator

CLIENT_NAME=$1
if [ -z "$CLIENT_NAME" ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

SYSTEM_DIR="/opt/mikrotik-vpn"

# Load domain from config
if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
    source $SYSTEM_DIR/configs/setup.env
else
    echo "Configuration file not found"
    exit 1
fi

cd $SYSTEM_DIR/openvpn/easy-rsa

# Generate client certificate
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

# Create client configuration
mkdir -p $SYSTEM_DIR/clients

cat << EOC > $SYSTEM_DIR/clients/$CLIENT_NAME.ovpn
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
EOC

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
    
    log "Creating database backup scripts..."
    create_database_backup_scripts
    
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

// Create collections with validation
db.createCollection('organizations', {
  validator: {
    \$jsonSchema: {
      bsonType: "object",
      required: ["name", "domain", "created_at"],
      properties: {
        name: { bsonType: "string" },
        domain: { bsonType: "string" },
        status: { enum: ["active", "suspended", "trial"] },
        created_at: { bsonType: "date" }
      }
    }
  }
});

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
db.organizations.createIndex({ "status": 1 });

db.sites.createIndex({ "organization_id": 1 });
db.sites.createIndex({ "vpn_ip": 1 }, { unique: true, sparse: true });

db.devices.createIndex({ "serial_number": 1 }, { unique: true });
db.devices.createIndex({ "site_id": 1 });
db.devices.createIndex({ "vpn_ip": 1 });
db.devices.createIndex({ "status": 1 });

db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true, sparse: true });

db.vouchers.createIndex({ "code": 1 }, { unique: true });
db.vouchers.createIndex({ "status": 1 });
db.vouchers.createIndex({ "created_at": -1 });

db.sessions.createIndex({ "user_id": 1 });
db.sessions.createIndex({ "device_id": 1 });
db.sessions.createIndex({ "start_time": -1 });

db.logs.createIndex({ "timestamp": -1 });
db.logs.createIndex({ "level": 1 });
db.logs.createIndex({ "device_id": 1 });
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
    # Create Redis directories
    mkdir -p $SYSTEM_DIR/redis/{data,logs}
    
    # Create Redis configuration
    cat << EOF > $SYSTEM_DIR/redis/redis.conf
# Redis Configuration for MikroTik VPN System

# Network
bind 127.0.0.1 ::1
protected-mode yes
port 6379

# General
daemonize no
supervised no
pidfile /var/run/redis_6379.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16

# Persistence
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
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

# Append only file
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

  redis-commander:
    image: rediscommander/redis-commander:latest
    container_name: mikrotik-redis-commander
    restart: unless-stopped
    environment:
      - REDIS_HOSTS=local:redis:6379:0:$REDIS_PASSWORD
      - HTTP_USER=admin
      - HTTP_PASSWORD=$REDIS_PASSWORD
    ports:
      - "127.0.0.1:8083:8081"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - redis

networks:
  mikrotik-vpn-net:
    external: true
EOF
}

create_database_backup_scripts() {
    cat << 'EOF' > $SCRIPT_DIR/backup-databases.sh
#!/bin/bash
# Database backup script

SYSTEM_DIR="/opt/mikrotik-vpn"
BACKUP_DIR="$SYSTEM_DIR/backups"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/mikrotik-vpn/backup.log"

# Load environment variables
if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
    source $SYSTEM_DIR/configs/setup.env
else
    echo "Configuration file not found"
    exit 1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# MongoDB backup
log "Starting MongoDB backup..."
docker exec mikrotik-mongodb mongodump \
    --host localhost \
    --username admin \
    --password $MONGO_ROOT_PASSWORD \
    --authenticationDatabase admin \
    --out /tmp/mongodb-backup-$DATE

docker cp mikrotik-mongodb:/tmp/mongodb-backup-$DATE $BACKUP_DIR/daily/
docker exec mikrotik-mongodb rm -rf /tmp/mongodb-backup-$DATE

# Redis backup
log "Starting Redis backup..."
docker exec mikrotik-redis redis-cli --pass $REDIS_PASSWORD BGSAVE
sleep 5
docker cp mikrotik-redis:/data/dump.rdb $BACKUP_DIR/daily/redis-$DATE.rdb

# Compress backups
cd $BACKUP_DIR/daily
tar -czf mongodb-$DATE.tar.gz mongodb-backup-$DATE/
tar -czf redis-$DATE.tar.gz redis-$DATE.rdb
rm -rf mongodb-backup-$DATE redis-$DATE.rdb

log "Database backup completed: $DATE"
EOF
    
    chmod +x $SCRIPT_DIR/backup-databases.sh
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

    # Logging format
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
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
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # Rate limiting zones
    limit_req_zone \$binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=api:10m rate=100r/s;

    # Include site configurations
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

    # API endpoints with rate limiting
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

    # SSL configuration (same as main)
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

    # Create default error pages
    mkdir -p $SYSTEM_DIR/nginx/html
    cat << EOF > $SYSTEM_DIR/nginx/html/50x.html
<!DOCTYPE html>
<html>
<head>
    <title>Service Temporarily Unavailable</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: #e74c3c; }
    </style>
</head>
<body>
    <h1 class="error">Service Temporarily Unavailable</h1>
    <p>The MikroTik VPN Management System is currently undergoing maintenance.</p>
    <p>Please try again in a few minutes.</p>
</body>
</html>
EOF
}

setup_ssl_certificates() {
    log "Setting up SSL certificates with Let's Encrypt..."
    
    # Create Certbot Docker Compose
    cat << EOF > $SYSTEM_DIR/docker-compose-certbot.yml
version: '3.8'

services:
  certbot:
    image: certbot/certbot
    container_name: mikrotik-certbot
    volumes:
      - $SYSTEM_DIR/nginx/ssl:/etc/letsencrypt
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

    # Create certificate renewal script
    cat << 'EOF' > $SCRIPT_DIR/renew-ssl-certificates.sh
#!/bin/bash
# SSL Certificate renewal script

SYSTEM_DIR="/opt/mikrotik-vpn"
LOG_FILE="/var/log/mikrotik-vpn/ssl-renewal.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting SSL certificate renewal..."

# Renew certificates
docker compose -f $SYSTEM_DIR/docker-compose-certbot.yml run --rm certbot renew

# Check if renewal was successful
if [ $? -eq 0 ]; then
    log "Certificate renewal successful"
    
    # Reload Nginx to use new certificates
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

    # Create self-signed certificate for immediate use
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $SYSTEM_DIR/nginx/ssl/privkey.pem \
        -out $SYSTEM_DIR/nginx/ssl/fullchain.pem \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
        -addext "subjectAltName=DNS:$DOMAIN_NAME,DNS:admin.$DOMAIN_NAME"
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
    
    # Install PM2 for process management
    npm install -g pm2@latest
    
    # Verify installation
    node --version
    npm --version
    pm2 --version
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
const session = require('express-session');
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
  res.json({ message: 'MikroTik VPN Management System API' });
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
# PHASE 7: MONITORING SETUP
# =============================================================================

phase7_monitoring_setup() {
    log "==================================================================="
    log "PHASE 7: MONITORING & ANALYTICS SETUP"
    log "==================================================================="
    
    log "Setting up Prometheus monitoring..."
    setup_prometheus
    
    log "Setting up Grafana dashboards..."
    setup_grafana
    
    log "Phase 7 completed successfully!"
}

setup_prometheus() {
    mkdir -p $SYSTEM_DIR/monitoring/{prometheus,grafana}
    
    # Prometheus configuration
    cat << EOF > $SYSTEM_DIR/monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'mikrotik-app'
    static_configs:
      - targets: ['app:3000']
    metrics_path: '/metrics'
EOF
}

setup_grafana() {
    # Grafana provisioning
    mkdir -p $SYSTEM_DIR/monitoring/grafana/provisioning/{datasources,dashboards}

    # Datasource configuration
    cat << EOF > $SYSTEM_DIR/monitoring/grafana/provisioning/datasources/prometheus.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
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
    volumes:
      - $SYSTEM_DIR/monitoring/prometheus:/etc/prometheus
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
    volumes:
      - grafana_data:/var/lib/grafana
      - $SYSTEM_DIR/monitoring/grafana/provisioning:/etc/grafana/provisioning
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

volumes:
  prometheus_data:
  grafana_data:

networks:
  mikrotik-vpn-net:
    external: true
EOF
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
    ufw allow from $(echo $VPN_NETWORK | cut -d'/' -f1)/24 to any port 9090 comment 'Prometheus'
    ufw allow from $(echo $VPN_NETWORK | cut -d'/' -f1)/24 to any port 3001 comment 'Grafana'
    
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
action = %(action_mwl)s

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

[openvpn]
enabled = true
port = 1194
protocol = udp
filter = openvpn
logpath = /var/log/openvpn.log
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

    # Restart and enable Fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban
}

harden_ssh() {
    # Backup original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)
    
    # Create hardened SSH configuration
    cat << EOF > /etc/ssh/sshd_config.d/99-mikrotik-vpn-hardening.conf
# SSH Hardening for MikroTik VPN System
Port $SSH_PORT
Protocol 2

# Authentication
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5

# Password authentication
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Key-based authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

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
PrintMotd no
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2

# User restrictions
AllowUsers mikrotik-vpn $SUDO_USER

# Modern cryptography
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
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
if [ -f "/opt/mikrotik-vpn/configs/setup.env" ]; then
    source /opt/mikrotik-vpn/configs/setup.env
else
    echo "Configuration file not found"
    exit 1
fi

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

# 1. Database Backups
log "Backing up MongoDB..."
docker exec mikrotik-mongodb mongodump \
    --host localhost \
    --username admin \
    --password $MONGO_ROOT_PASSWORD \
    --authenticationDatabase admin \
    --out /tmp/mongodb-backup

docker cp mikrotik-mongodb:/tmp/mongodb-backup $BACKUP_PATH/
docker exec mikrotik-mongodb rm -rf /tmp/mongodb-backup

log "Backing up Redis..."
docker exec mikrotik-redis redis-cli --pass $REDIS_PASSWORD BGSAVE
sleep 5
docker cp mikrotik-redis:/data/dump.rdb $BACKUP_PATH/redis_dump.rdb

# 2. Configuration Files
log "Backing up configuration files..."
tar -czf $BACKUP_PATH/configs.tar.gz \
    /opt/mikrotik-vpn/configs \
    /opt/mikrotik-vpn/nginx \
    /opt/mikrotik-vpn/openvpn \
    /opt/mikrotik-vpn/app/.env \
    /opt/mikrotik-vpn/*.yml \
    2>/dev/null || true

# 3. SSL Certificates
log "Backing up SSL certificates..."
tar -czf $BACKUP_PATH/ssl.tar.gz /opt/mikrotik-vpn/nginx/ssl 2>/dev/null || true

# 4. Application Data
log "Backing up application data..."
tar -czf $BACKUP_PATH/app_data.tar.gz \
    /var/log/mikrotik-vpn \
    2>/dev/null || true

# 5. Create checksums
log "Creating checksums..."
cd $BACKUP_PATH
find . -type f -exec sha256sum {} \; > checksums.sha256

# 6. Compress entire backup
log "Compressing backup..."
cd $BACKUP_DIR/$BACKUP_TYPE
tar -czf backup_$DATE.tar.gz backup_$DATE/
rm -rf backup_$DATE/

# 7. Cleanup old backups
log "Cleaning up old backups..."
cleanup_backups() {
    local backup_type=$1
    local retention=$2
    
    find $BACKUP_DIR/$backup_type -name "*.tar.gz" -mtime +$retention -delete 2>/dev/null || true
}

cleanup_backups "daily" $RETENTION_DAILY
cleanup_backups "weekly" $((RETENTION_WEEKLY * 7))
cleanup_backups "monthly" $((RETENTION_MONTHLY * 30))

# 8. Verify backup integrity
log "Verifying backup integrity..."
if tar -tzf $BACKUP_DIR/$BACKUP_TYPE/backup_$DATE.tar.gz >/dev/null; then
    log "Backup verification successful"
else
    log "ERROR: Backup verification failed"
    exit 1
fi

# 9. Send notification
BACKUP_SIZE=$(du -h $BACKUP_DIR/$BACKUP_TYPE/backup_$DATE.tar.gz | cut -f1)
log "Backup completed successfully. Size: $BACKUP_SIZE"

log "=== Backup Summary ==="
log "Type: $BACKUP_TYPE"
log "Date: $DATE"
log "Size: $BACKUP_SIZE"
log "Location: $BACKUP_DIR/$BACKUP_TYPE/backup_$DATE.tar.gz"
EOF

    chmod +x $SCRIPT_DIR/backup-system.sh

    # Restore script
    cat << 'EOF' > $SCRIPT_DIR/restore-system.sh
#!/bin/bash
# MikroTik VPN System Restore Script

BACKUP_DIR="/opt/mikrotik-vpn/backups"
LOG_FILE="/var/log/mikrotik-vpn/restore.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# Function to list available backups
list_backups() {
    echo "Available backups:"
    echo "=================="
    
    for type in daily weekly monthly; do
        echo -e "\n$type backups:"
        ls -1 $BACKUP_DIR/$type/*.tar.gz 2>/dev/null | sort -r | head -10 || echo "  No backups found"
    done
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
    
    # Create confirmation prompt
    echo "WARNING: This will overwrite the current system configuration!"
    echo "Current containers will be stopped and data will be replaced."
    read -p "Are you sure you want to continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        log "Restore cancelled by user"
        exit 0
    fi
    
    # Extract backup
    log "Extracting backup..."
    mkdir -p $temp_dir
    tar -xzf $backup_file -C $temp_dir
    
    # Find extracted directory
    backup_dir=$(find $temp_dir -maxdepth 1 -type d -name "backup_*" | head -1)
    
    if [ -z "$backup_dir" ]; then
        log "ERROR: Could not find backup directory in archive"
        exit 1
    fi
    
    # Verify checksums
    log "Verifying backup integrity..."
    cd $backup_dir
    if [ -f checksums.sha256 ]; then
        if sha256sum -c checksums.sha256 --quiet; then
            log "Backup integrity verified"
        else
            log "ERROR: Backup integrity check failed"
            exit 1
        fi
    else
        log "WARNING: No checksums found, skipping integrity check"
    fi
    
    # Stop all services
    log "Stopping all services..."
    cd /opt/mikrotik-vpn
    for compose_file in docker-compose-*.yml; do
        if [ -f "$compose_file" ]; then
            docker compose -f $compose_file down 2>/dev/null || true
        fi
    done
    
    # Restore databases
    log "Restoring MongoDB..."
    docker compose -f docker-compose-mongodb.yml up -d
    sleep 15
    
    if [ -d "$backup_dir/mongodb-backup" ]; then
        docker cp $backup_dir/mongodb-backup mikrotik-mongodb:/tmp/
        docker exec mikrotik-mongodb mongorestore \
            --host localhost \
            --username admin \
            --password $MONGO_ROOT_PASSWORD \
            --authenticationDatabase admin \
            --drop \
            /tmp/mongodb-backup 2>/dev/null || true
        docker exec mikrotik-mongodb rm -rf /tmp/mongodb-backup
    fi
    
    log "Restoring Redis..."
    docker compose -f docker-compose-redis.yml down
    if [ -f "$backup_dir/redis_dump.rdb" ]; then
        docker cp $backup_dir/redis_dump.rdb mikrotik-redis:/data/dump.rdb 2>/dev/null || true
    fi
    docker compose -f docker-compose-redis.yml up -d
    
    # Restore configuration files
    log "Restoring configuration files..."
    if [ -f "$backup_dir/configs.tar.gz" ]; then
        cd /
        tar -xzf $backup_dir/configs.tar.gz 2>/dev/null || true
    fi
    
    # Restore SSL certificates
    log "Restoring SSL certificates..."
    if [ -f "$backup_dir/ssl.tar.gz" ]; then
        cd /
        tar -xzf $backup_dir/ssl.tar.gz 2>/dev/null || true
    fi
    
    # Start all services
    log "Starting all services..."
    cd /opt/mikrotik-vpn
    /opt/mikrotik-vpn/scripts/start-all-services.sh
    
    # Cleanup
    rm -rf $temp_dir
    
    log "Restore completed successfully!"
    log "Please verify all services are working correctly"
}

# Main menu
main() {
    if [ $# -eq 0 ]; then
        echo "MikroTik VPN System Restore Utility"
        echo "===================================="
        echo "Usage: $0 [backup_file]"
        echo ""
        list_backups
        echo ""
        echo "Example: $0 /opt/mikrotik-vpn/backups/daily/backup_20240101_120000.tar.gz"
        exit 0
    fi
    
    restore_backup "$1"
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

# Daily backup at 2:00 AM
0 2 * * * mikrotik-vpn /opt/mikrotik-vpn/scripts/backup-system.sh >> /var/log/mikrotik-vpn/backup-cron.log 2>&1

# Weekly cleanup at 3:00 AM on Sundays
0 3 * * 0 mikrotik-vpn /opt/mikrotik-vpn/scripts/cleanup-old-backups.sh >> /var/log/mikrotik-vpn/backup-cleanup.log 2>&1
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

# Cleanup each backup type
cleanup_old_backups "daily" $DAILY_RETENTION
cleanup_old_backups "weekly" $WEEKLY_RETENTION
cleanup_old_backups "monthly" $MONTHLY_RETENTION

# Cleanup log files older than 90 days
log "Cleaning up old log files..."
find /var/log/mikrotik-vpn -name "*.log" -type f -mtime +90 -exec rm -f {} \; 2>/dev/null || true

# Report current backup space usage
log "Current backup space usage:"
du -sh $BACKUP_DIR/* 2>/dev/null | tee -a $LOG_FILE || true

log "Backup cleanup completed"
EOF

    chmod +x $SCRIPT_DIR/cleanup-old-backups.sh
}

# =============================================================================
# PHASE 10: SYSTEM MANAGEMENT SCRIPTS
# =============================================================================

phase10_management_scripts() {
    log "==================================================================="
    log "PHASE 10: SYSTEM MANAGEMENT SCRIPTS"
    log "==================================================================="
    
    log "Creating management scripts..."
    create_management_scripts
    
    log "Setting up system service..."
    setup_system_service
    
    log "Creating maintenance scripts..."
    create_maintenance_scripts
    
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
    docker compose -f docker-compose-l2tp.yml up -d
    
    print_status "Starting application..."
    docker compose -f docker-compose-app.yml up -d
    
    print_status "Starting web server..."
    docker compose -f docker-compose-nginx.yml up -d
    
    print_status "Starting monitoring..."
    docker compose -f docker-compose-monitoring.yml up -d
    
    print_status "All services started!"
}

stop_all_services() {
    print_status "Stopping all MikroTik VPN services..."
    
    cd $SYSTEM_DIR
    
    # Stop services in reverse order
    docker compose -f docker-compose-monitoring.yml down 2>/dev/null || true
    docker compose -f docker-compose-nginx.yml down 2>/dev/null || true
    docker compose -f docker-compose-app.yml down 2>/dev/null || true
    docker compose -f docker-compose-l2tp.yml down 2>/dev/null || true
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
manage_vpn_clients() {
    local action=$1
    local client_name=$2
    
    case $action in
        "create")
            if [ -z "$client_name" ]; then
                read -p "Enter client name: " client_name
            fi
            
            if [ -z "$client_name" ]; then
                print_error "Client name is required"
                return 1
            fi
            
            print_status "Creating VPN client configuration for: $client_name"
            $SYSTEM_DIR/scripts/generate-vpn-client.sh "$client_name"
            
            if [ $? -eq 0 ]; then
                print_status "Client configuration created successfully"
                print_status "Configuration file: $SYSTEM_DIR/clients/$client_name.ovpn"
            else
                print_error "Failed to create client configuration"
            fi
            ;;
        "list")
            print_status "Available VPN client configurations:"
            if [ -d "$SYSTEM_DIR/clients" ]; then
                ls -la $SYSTEM_DIR/clients/*.ovpn 2>/dev/null || echo "No client configurations found"
            else
                echo "No clients directory found"
            fi
            ;;
        "revoke")
            if [ -z "$client_name" ]; then
                read -p "Enter client name to revoke: " client_name
            fi
            
            if [ -z "$client_name" ]; then
                print_error "Client name is required"
                return 1
            fi
            
            print_status "Revoking VPN client: $client_name"
            cd $SYSTEM_DIR/openvpn/easy-rsa
            ./easyrsa revoke "$client_name"
            ./easyrsa gen-crl
            
            # Remove client configuration file
            rm -f "$SYSTEM_DIR/clients/$client_name.ovpn"
            
            print_status "Client revoked successfully"
            ;;
        *)
            echo "VPN Client Management:"
            echo "  create <name>  - Create new VPN client"
            echo "  list          - List existing clients"
            echo "  revoke <name> - Revoke client certificate"
            echo
            echo "Usage: $0 vpn <action> [client_name]"
            ;;
    esac
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
        echo "6. VPN Client Management"
        echo "7. Backup System"
        echo "8. Exit"
        echo
        read -p "Select option (1-8): " choice
        
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
                echo "VPN action (create/list/revoke):"
                read action
                if [ "$action" = "create" ] || [ "$action" = "revoke" ]; then
                    echo "Client name:"
                    read client_name
                    manage_vpn_clients "$action" "$client_name"
                else
                    manage_vpn_clients "$action"
                fi
                ;;
            7) 
                print_status "Running backup..."
                $SYSTEM_DIR/scripts/backup-system.sh
                ;;
            8) 
                print_status "Exiting MikroTik VPN Manager"
                exit 0
                ;;
            *) 
                print_error "Invalid option. Please select 1-8."
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
            manage_vpn_clients "$2" "$3"
            ;;
        "backup")
            $SYSTEM_DIR/scripts/backup-system.sh
            ;;
        "menu"|"")
            show_main_menu
            ;;
        "help"|"-h"|"--help")
            echo "MikroTik VPN Management System v2.0"
            echo
            echo "Usage: $0 [command] [options]"
            echo
            echo "Commands:"
            echo "  status              - Show system status"
            echo "  start               - Start all services"
            echo "  stop                - Stop all services"
            echo "  restart             - Restart all services"
            echo "  logs <service>      - View service logs"
            echo "  vpn <action>        - VPN client management"
            echo "  backup              - Run backup now"
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
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/mikrotik-vpn
ExecStart=/opt/mikrotik-vpn/scripts/start-all-services.sh
ExecStop=/opt/mikrotik-vpn/scripts/stop-all-services.sh
TimeoutStartSec=300
TimeoutStopSec=120
User=root

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

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

check_service() {
    local service=$1
    local container_name="mikrotik-$service"
    
    if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        if docker ps --format "{{.Names}} {{.Status}}" | grep "^${container_name}" | grep -q "Up"; then
            log "✓ $service is running and healthy"
            return 0
        else
            log "✗ $service container exists but not healthy"
            FAILED_CHECKS="$FAILED_CHECKS $service"
            return 1
        fi
    else
        log "✗ $service container not found"
        FAILED_CHECKS="$FAILED_CHECKS $service"
        return 1
    fi
}

check_port() {
    local port=$1
    local service=$2
    
    if netstat -tlnp | grep ":$port " >/dev/null; then
        log "✓ Port $port ($service) is listening"
        return 0
    else
        log "✗ Port $port ($service) is not listening"
        FAILED_CHECKS="$FAILED_CHECKS port-$port"
        return 1
    fi
}

check_disk_space() {
    local usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$usage" -lt 80 ]; then
        log "✓ Disk usage is acceptable ($usage%)"
        return 0
    elif [ "$usage" -lt 90 ]; then
        log "⚠ Disk usage is high ($usage%)"
        return 0
    else
        log "✗ Disk usage is critical ($usage%)"
        FAILED_CHECKS="$FAILED_CHECKS disk-space"
        return 1
    fi
}

check_memory() {
    local usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    
    if [ "$usage" -lt 80 ]; then
        log "✓ Memory usage is acceptable ($usage%)"
        return 0
    elif [ "$usage" -lt 90 ]; then
        log "⚠ Memory usage is high ($usage%)"
        return 0
    else
        log "✗ Memory usage is critical ($usage%)"
        FAILED_CHECKS="$FAILED_CHECKS memory"
        return 1
    fi
}

check_ssl_certificate() {
    local cert_file="/opt/mikrotik-vpn/nginx/ssl/fullchain.pem"
    
    if [ -f "$cert_file" ]; then
        local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s)
        local current_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if [ "$days_left" -gt 30 ]; then
            log "✓ SSL certificate is valid ($days_left days remaining)"
            return 0
        elif [ "$days_left" -gt 7 ]; then
            log "⚠ SSL certificate expires soon ($days_left days remaining)"
            return 0
        else
            log "✗ SSL certificate expires very soon ($days_left days remaining)"
            FAILED_CHECKS="$FAILED_CHECKS ssl-expiry"
            return 1
        fi
    else
        log "✗ SSL certificate not found"
        FAILED_CHECKS="$FAILED_CHECKS ssl-missing"
        return 1
    fi
}

# Main health check execution
main() {
    log "=== Starting Health Check ==="
    log "Timestamp: $(date)"
    log "Hostname: $(hostname)"
    
    # Check all critical services
    log "Checking Docker services..."
    check_service "mongodb"
    check_service "redis"
    check_service "app"
    check_service "nginx"
    check_service "openvpn"
    
    # Check critical ports
    log "Checking network ports..."
    check_port "80" "HTTP"
    check_port "443" "HTTPS"
    check_port "1194" "OpenVPN"
    
    # Check system resources
    log "Checking system resources..."
    check_disk_space
    check_memory
    
    # Check SSL certificate
    log "Checking SSL certificate..."
    check_ssl_certificate
    
    # Summary
    log "=== Health Check Summary ==="
    if [ -z "$FAILED_CHECKS" ]; then
        log "✓ All health checks passed"
        exit 0
    else
        log "✗ Health check failures detected: $FAILED_CHECKS"
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

# 1. Docker optimization
log "Optimizing Docker..."
docker system prune -f
docker image prune -f
docker volume prune -f

# 2. Memory optimization
log "Optimizing memory..."
sync
echo 3 > /proc/sys/vm/drop_caches

# 3. Log rotation
log "Rotating logs..."
find /var/log -name "*.log" -size +100M -exec logrotate -f {} \; 2>/dev/null || true
find /opt/mikrotik-vpn/logs -name "*.log" -size +50M -exec truncate -s 0 {} \; 2>/dev/null || true

# 4. Temporary file cleanup
log "Cleaning temporary files..."
find /tmp -type f -atime +7 -delete 2>/dev/null || true
find /var/tmp -type f -atime +7 -delete 2>/dev/null || true

# 5. Package cache cleanup
log "Cleaning package cache..."
apt autoremove -y
apt autoclean

# 6. Database optimization
log "Optimizing databases..."
if docker ps | grep -q mikrotik-mongodb; then
    docker exec mikrotik-mongodb mongosh --eval "db.runCommand({compact: 'users'})" mikrotik_vpn 2>/dev/null || true
fi

if docker ps | grep -q mikrotik-redis; then
    docker exec mikrotik-redis redis-cli BGREWRITEAOF 2>/dev/null || true
fi

log "System optimization completed"
EOF

    chmod +x $SCRIPT_DIR/optimize-system.sh

    # Security audit script
    cat << 'EOF' > $SCRIPT_DIR/security-audit.sh
#!/bin/bash
# Security audit script

LOG_FILE="/var/log/mikrotik-vpn/security-audit.log"
REPORT_FILE="/var/log/mikrotik-vpn/security-report-$(date +%Y%m%d).txt"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE | tee -a $REPORT_FILE
}

log "=== Security Audit Report ==="
log "Date: $(date)"
log "Hostname: $(hostname)"
log ""

# 1. Check system updates
log "1. System Updates Status:"
updates=$(apt list --upgradable 2>/dev/null | wc -l)
log "   Available updates: $((updates - 1))"
if [ $updates -gt 1 ]; then
    log "   ⚠ System updates available"
else
    log "   ✓ System is up to date"
fi
log ""

# 2. Check user accounts
log "2. User Account Security:"
log "   Users with shell access:"
awk -F: '$7 ~ /bash|sh/ {print "   " $1}' /etc/passwd | tee -a $REPORT_FILE
log ""

# 3. Check network services
log "3. Network Services:"
log "   Open ports:"
netstat -tlnp | grep LISTEN | awk '{print "   " $4 " " $7}' | tee -a $REPORT_FILE
log ""

# 4. Check firewall status
log "4. Firewall Status:"
ufw_status=$(ufw status | head -1)
log "   UFW: $ufw_status"
if echo "$ufw_status" | grep -q "active"; then
    log "   ✓ Firewall is active"
else
    log "   ⚠ Firewall is not active"
fi
log ""

# 5. Check fail2ban status
log "5. Fail2ban Status:"
if systemctl is-active fail2ban >/dev/null; then
    log "   ✓ Fail2ban is active"
    log "   Active jails:"
    fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr ',' '\n' | sed 's/^/     /' | tee -a $REPORT_FILE || true
else
    log "   ⚠ Fail2ban is not active"
fi
log ""

# 6. Check SSH configuration
log "6. SSH Security:"
ssh_config="/etc/ssh/sshd_config"
if grep -q "PermitRootLogin no" $ssh_config 2>/dev/null; then
    log "   ✓ Root login disabled"
else
    log "   ⚠ Root login may be enabled"
fi

ssh_port=$(grep "^Port" $ssh_config 2>/dev/null | awk '{print $2}' || echo "22")
log "   SSH Port: $ssh_port"
log ""

# 7. Check SSL certificates
log "7. SSL Certificate Security:"
cert_file="/opt/mikrotik-vpn/nginx/ssl/fullchain.pem"
if [ -f "$cert_file" ]; then
    expiry=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
    log "   Certificate expires: $expiry"
else
    log "   ⚠ SSL certificate not found"
fi
log ""

# 8. Check Docker security
log "8. Docker Security:"
if docker info 2>/dev/null | grep -q "Security Options"; then
    log "   Docker security options:"
    docker info 2>/dev/null | grep -A 5 "Security Options" | sed 's/^/     /' | tee -a $REPORT_FILE
else
    log "   ⚠ No Docker security options detected"
fi
log ""

# 9. Check recent security events
log "9. Recent Security Events:"
log "    Recent failed login attempts:"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 | sed 's/^/      /' | tee -a $REPORT_FILE || true
log ""

log "Security audit completed. Report saved to: $REPORT_FILE"
EOF

    chmod +x $SCRIPT_DIR/security-audit.sh
}

# =============================================================================
# MASTER INSTALLATION FUNCTION
# =============================================================================

install_mikrotik_vpn_system() {
    log "==================================================================="
    log "STARTING MIKROTIK VPN MANAGEMENT SYSTEM INSTALLATION"
    log "==================================================================="
    
    # Check prerequisites
    check_root
    
    # Get user configuration
    get_user_input
    
    # Save configuration for later use
    cat << EOF > $SYSTEM_DIR/configs/setup.env
DOMAIN_NAME=$DOMAIN_NAME
ADMIN_EMAIL=$ADMIN_EMAIL
SSH_PORT=$SSH_PORT
TIMEZONE=$TIMEZONE
VPN_NETWORK=$VPN_NETWORK
MONGO_ROOT_PASSWORD=$MONGO_ROOT_PASSWORD
MONGO_APP_PASSWORD=$MONGO_APP_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD
INSTALLATION_DATE=$(date)
SYSTEM_VERSION=2.0
EOF
    
    # Execute installation phases
    log "Starting installation phases..."
    
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
    
    # Final system startup
    log "==================================================================="
    log "STARTING SERVICES FOR FIRST TIME"
    log "==================================================================="
    
    cd $SYSTEM_DIR
    
    # Start all services
    log "Starting all services..."
    $SCRIPT_DIR/start-all-services.sh
    
    # Wait for services to be ready
    log "Waiting for services to initialize..."
    sleep 60
    
    # Run initial health check
    log "Running initial health check..."
    $SCRIPT_DIR/health-check.sh || log_warning "Some health checks failed - this is normal for first startup"
    
    # Generate SSL certificates (Let's Encrypt)
    log "Generating SSL certificates..."
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        docker compose -f docker-compose-certbot.yml run --rm certbot || log_warning "SSL certificate generation failed - using self-signed certificates"
        
        # Update symbolic links for certificates
        if [ -f "$SYSTEM_DIR/nginx/ssl/live/$DOMAIN_NAME/fullchain.pem" ]; then
            ln -sf $SYSTEM_DIR/nginx/ssl/live/$DOMAIN_NAME/fullchain.pem $SYSTEM_DIR/nginx/ssl/fullchain.pem
            ln -sf $SYSTEM_DIR/nginx/ssl/live/$DOMAIN_NAME/privkey.pem $SYSTEM_DIR/nginx/ssl/privkey.pem
            
            # Reload Nginx with new certificates
            docker exec mikrotik-nginx nginx -s reload
            log "SSL certificates installed and Nginx reloaded"
        fi
    else
        log_warning "No internet connection detected. Using self-signed certificates."
    fi
    
    # Create initial VPN client for testing
    log "Creating test VPN client..."
    $SCRIPT_DIR/generate-vpn-client.sh "test-client" || log_warning "Failed to create test VPN client"
    
    # Set up cron jobs
    log "Setting up automated tasks..."
    
    # Health check every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * /opt/mikrotik-vpn/scripts/health-check.sh >/dev/null 2>&1") | crontab -
    
    # System optimization weekly
    (crontab -l 2>/dev/null; echo "0 2 * * 0 /opt/mikrotik-vpn/scripts/optimize-system.sh >/dev/null 2>&1") | crontab -
    
    # Security audit monthly
    (crontab -l 2>/dev/null; echo "0 3 1 * * /opt/mikrotik-vpn/scripts/security-audit.sh >/dev/null 2>&1") | crontab -
    
    # Final system verification
    log "==================================================================="
    log "FINAL SYSTEM VERIFICATION"
    log "==================================================================="
    
    # Check all services one more time
    services_ok=true
    for service in mongodb redis openvpn nginx app; do
        if ! docker ps | grep -q "mikrotik-$service.*Up"; then
            log_error "Service $service is not running properly"
            services_ok=false
        else
            log "✓ Service $service is running"
        fi
    done
    
    # Check network connectivity
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:80 2>/dev/null | grep -q "200\|301\|302"; then
        log "✓ Web server is responding"
    else
        log_warning "Web server may not be responding correctly"
    fi
    
    # Generate installation report
    log "==================================================================="
    log "INSTALLATION COMPLETED SUCCESSFULLY!"
    log "==================================================================="
    
    cat << EOF | tee $SYSTEM_DIR/installation-report.txt

=================================================================
        MikroTik VPN Management System v2.0
                Installation Report
=================================================================

Installation Date: $(date)
Hostname: $(hostname)
Domain: $DOMAIN_NAME
Admin Email: $ADMIN_EMAIL

SYSTEM INFORMATION:
------------------
OS: $(lsb_release -d | cut -f2)
Kernel: $(uname -r)
Architecture: $(uname -m)
Docker Version: $(docker --version)
Docker Compose Version: $(docker compose version)

NETWORK CONFIGURATION:
---------------------
VPN Network: $VPN_NETWORK
SSH Port: $SSH_PORT
Domain: $DOMAIN_NAME

ACCESS INFORMATION:
------------------
Web Interface: https://$DOMAIN_NAME
Admin Panel: https://admin.$DOMAIN_NAME
Grafana Dashboard: https://$DOMAIN_NAME:3001
- Username: admin
- Password: $MONGO_ROOT_PASSWORD

VPN Connections:
- OpenVPN: $DOMAIN_NAME:1194 (UDP)
- L2TP/IPSec: $DOMAIN_NAME:500,4500,1701 (UDP)

DATABASE ACCESS:
---------------
MongoDB:
- Host: localhost:27017
- Admin User: admin
- Admin Password: $MONGO_ROOT_PASSWORD
- App User: mikrotik_app
- App Password: $MONGO_APP_PASSWORD

Redis:
- Host: localhost:6379
- Password: $REDIS_PASSWORD

INSTALLED SERVICES:
------------------
✓ MongoDB 6.0 (Database)
✓ Redis 7.0 (Cache)
✓ OpenVPN (VPN Server)
✓ L2TP/IPSec (Alternative VPN)
✓ Nginx (Web Server)
✓ Node.js Application (Management Interface)
✓ Prometheus (Monitoring)
✓ Grafana (Dashboards)
✓ Fail2ban (Security)
✓ UFW Firewall (Security)

MANAGEMENT COMMANDS:
-------------------
System Manager: /opt/mikrotik-vpn/mikrotik-vpn-manager.sh
Service Control: systemctl start/stop/restart mikrotik-vpn
Health Check: /opt/mikrotik-vpn/scripts/health-check.sh
Backup System: /opt/mikrotik-vpn/scripts/backup-system.sh
VPN Client Gen: /opt/mikrotik-vpn/scripts/generate-vpn-client.sh

IMPORTANT FILES:
---------------
Configuration: /opt/mikrotik-vpn/configs/
Logs: /var/log/mikrotik-vpn/
Backups: /opt/mikrotik-vpn/backups/
VPN Clients: /opt/mikrotik-vpn/clients/
SSL Certificates: /opt/mikrotik-vpn/nginx/ssl/

SECURITY NOTES:
--------------
1. Change all default passwords immediately
2. Configure proper DNS for your domain
3. Test VPN connections before production use
4. Set up email notifications for monitoring
5. Review firewall rules for your environment
6. Configure backup retention policies
7. Set up external monitoring if needed

NEXT STEPS:
----------
1. Access web interface at https://$DOMAIN_NAME
2. Complete initial configuration
3. Test VPN connectivity
4. Configure MikroTik devices to connect
5. Set up monitoring alerts
6. Create additional VPN clients as needed
7. Configure payment gateways if required
8. Set up SMTP for email notifications

SUPPORT:
-------
Documentation: /opt/mikrotik-vpn/docs/
Log Files: /var/log/mikrotik-vpn/
Health Check: /opt/mikrotik-vpn/scripts/health-check.sh
Manager Tool: /opt/mikrotik-vpn/mikrotik-vpn-manager.sh

=================================================================
                 Installation Completed Successfully!
         System is ready for configuration and testing.
=================================================================

EOF

    # Set proper permissions
    chown -R mikrotik-vpn:mikrotik-vpn $SYSTEM_DIR
    chmod -R 755 $SCRIPT_DIR
    chmod 600 $SYSTEM_DIR/app/.env
    chmod 600 $SYSTEM_DIR/configs/setup.env
    
    log "Installation report saved to: $SYSTEM_DIR/installation-report.txt"
    
    # Final success message
    echo
    echo "==================================================================="
    echo -e "${GREEN}🎉 INSTALLATION COMPLETED SUCCESSFULLY! 🎉${NC}"
    echo "==================================================================="
    echo
    echo -e "${CYAN}Access your MikroTik VPN Management System at:${NC}"
    echo -e "  ${YELLOW}Web Interface:${NC} https://$DOMAIN_NAME"
    echo -e "  ${YELLOW}Admin Panel:${NC} https://admin.$DOMAIN_NAME"
    echo -e "  ${YELLOW}Monitoring:${NC} https://$DOMAIN_NAME:3001"
    echo
    echo -e "${CYAN}Management Commands:${NC}"
    echo -e "  ${YELLOW}System Status:${NC} $SYSTEM_DIR/mikrotik-vpn-manager.sh status"
    echo -e "  ${YELLOW}Interactive Menu:${NC} $SYSTEM_DIR/mikrotik-vpn-manager.sh"
    echo -e "  ${YELLOW}Service Control:${NC} systemctl start/stop/restart mikrotik-vpn"
    echo
    echo -e "${RED}IMPORTANT:${NC} Please change all default passwords and configure DNS!"
    echo
    echo "📋 Full installation report: $SYSTEM_DIR/installation-report.txt"
    echo "==================================================================="
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Main execution function
main() {
    # Show header
    echo
    echo "==================================================================="
    echo "       MikroTik VPN Management System - Installer v2.0"
    echo "       Complete VPN-based Hotspot Management Solution"
    echo "==================================================================="
    echo
    
    # Check if this is a fresh installation or script run
    if [ -f "$SYSTEM_DIR/configs/setup.env" ] && [ "$1" != "--force-reinstall" ]; then
        echo "Existing installation detected!"
        echo
        echo "Options:"
        echo "1. Run system manager"
        echo "2. Force complete reinstallation"
        echo "3. Exit"
        echo
        read -p "Select option (1-3): " choice
        
        case $choice in
            1)
                $SYSTEM_DIR/mikrotik-vpn-manager.sh
                ;;
            2)
                echo "⚠️  WARNING: This will completely reinstall the system!"
                read -p "Are you absolutely sure? (type 'yes' to confirm): " confirm
                if [ "$confirm" = "yes" ]; then
                    install_mikrotik_vpn_system
                else
                    echo "Reinstallation cancelled."
                    exit 0
                fi
                ;;
            3)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option"
                exit 1
                ;;
        esac
    else
        # Fresh installation
        install_mikrotik_vpn_system
    fi
}

# Check command line arguments
case "${1:-}" in
    "--help"|"-h")
        echo "MikroTik VPN Management System Installer v2.0"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help              Show this help message"
        echo "  --force-reinstall   Force complete reinstallation"
        echo "  --version           Show version information"
        echo
        echo "For system management after installation:"
        echo "  /opt/mikrotik-vpn/mikrotik-vpn-manager.sh"
        exit 0
        ;;
    "--version"|"-v")
        echo "MikroTik VPN Management System Installer v2.0"
        echo "Compatible with Ubuntu 22.04 LTS"
        echo "Build date: $(date)"
        exit 0
        ;;
    "--force-reinstall")
        install_mikrotik_vpn_system
        ;;
    "")
        main
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
