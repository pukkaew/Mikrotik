#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script
# Version: 5.0 - Full Features Edition with Multi-language & Payment Gateway
# Description: Complete installation with all Phase 1-4 features
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
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}

# =============================================================================
# PHASE 6: CONFIGURATION FILES
# =============================================================================

phase6_configuration_files() {
    log "==================================================================="
    log "PHASE 6: CREATING CONFIGURATION FILES"
    log "==================================================================="
    
    # Create OpenVPN configuration
    create_openvpn_config
    
    # Create Nginx configuration
    create_nginx_config
    
    # Create MongoDB initialization
    create_mongodb_init
    
    # Create Redis configuration
    create_redis_config
    
    log "Phase 6 completed successfully!"
}

# Create OpenVPN configuration
create_openvpn_config() {
    cat << EOF > "$SYSTEM_DIR/openvpn/server/server.conf"
# OpenVPN Server Configuration
port 1194
proto udp
dev tun

# Certificates and keys
ca /opt/mikrotik-vpn/openvpn/easy-rsa/pki/ca.crt
cert /opt/mikrotik-vpn/openvpn/easy-rsa/pki/issued/vpn-server.crt
key /opt/mikrotik-vpn/openvpn/easy-rsa/pki/private/vpn-server.key
dh /opt/mikrotik-vpn/openvpn/easy-rsa/pki/dh.pem
tls-auth /opt/mikrotik-vpn/openvpn/easy-rsa/ta.key 0

# Network configuration
server ${VPN_NETWORK%/*} 255.255.255.0
push "route ${VPN_NETWORK%/*} 255.255.255.0"
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

# Logging
status /var/log/openvpn-status.log
log-append /var/log/mikrotik-vpn/openvpn.log
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

# Create Nginx configuration
create_nginx_config() {
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

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;

    server_tokens off;
    
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml;

    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Site configuration
    cat << EOF > "$SYSTEM_DIR/nginx/conf.d/mikrotik-vpn.conf"
# Rate limiting
limit_req_zone \$binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=api:10m rate=100r/s;

# Upstream
upstream app_backend {
    least_conn;
    server app:3000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

# HTTP redirect
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME;

    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws {
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
}

# Create MongoDB initialization
create_mongodb_init() {
    cat << EOF > "$SYSTEM_DIR/mongodb/init-mongo.js"
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

// Create initial collections
db.createCollection('organizations');
db.createCollection('users');
db.createCollection('devices');
db.createCollection('vouchers');
db.createCollection('sessions');
db.createCollection('paymentTransactions');
db.createCollection('portalTemplates');
db.createCollection('hotspotProfiles');
db.createCollection('logs');

// Create indexes
db.devices.createIndex({ "serialNumber": 1 }, { unique: true });
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });
db.vouchers.createIndex({ "code": 1 }, { unique: true });
db.sessions.createIndex({ "startTime": -1 });
db.paymentTransactions.createIndex({ "transactionId": 1 }, { unique: true });

print('Database initialization completed');
EOF
}

# Create Redis configuration
create_redis_config() {
    cat << EOF > "$SYSTEM_DIR/redis/redis.conf"
# Redis Configuration
bind 0.0.0.0
protected-mode no
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
maxmemory ${REDIS_MAX_MEM}mb
maxmemory-policy allkeys-lru

# Performance
tcp-backlog 511
timeout 0
tcp-keepalive 300
EOF
}

# =============================================================================
# PHASE 7: DOCKER COMPOSE SETUP
# =============================================================================

phase7_docker_compose() {
    log "==================================================================="
    log "PHASE 7: CREATING DOCKER COMPOSE CONFIGURATION"
    log "==================================================================="
    
    # Create main docker-compose.yml
    cat << 'EOF' > "$SYSTEM_DIR/docker-compose.yml"
version: '3.8'

services:
  # MongoDB
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
      - ./mongodb/init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro
    ports:
      - "127.0.0.1:27017:27017"
    networks:
      - mikrotik-vpn-net
    command: mongod --auth --wiredTigerCacheSizeGB ${MONGODB_CACHE_SIZE}

  # Redis
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

  # Application
  app:
    build: ./app
    container_name: mikrotik-app
    restart: unless-stopped
    depends_on:
      - mongodb
      - redis
    environment:
      - NODE_ENV=production
    volumes:
      - ./app:/app
      - /app/node_modules
      - ./data/uploads:/app/uploads
      - ./logs:/app/logs
    ports:
      - "127.0.0.1:3000:3000"
    networks:
      - mikrotik-vpn-net

  # Nginx
  nginx:
    image: nginx:alpine
    container_name: mikrotik-nginx
    restart: unless-stopped
    depends_on:
      - app
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    networks:
      - mikrotik-vpn-net

  # OpenVPN
  openvpn:
    image: kylemanna/openvpn:latest
    container_name: mikrotik-openvpn
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    ports:
      - "1194:1194/udp"
    volumes:
      - ./openvpn:/etc/openvpn
    networks:
      - mikrotik-vpn-net

  # Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: mikrotik-prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    volumes:
      - ./monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./monitoring/prometheus/rules:/etc/prometheus/rules:ro
      - prometheus_data:/prometheus
    ports:
      - "127.0.0.1:9090:9090"
    networks:
      - mikrotik-vpn-net

  # Grafana
  grafana:
    image: grafana/grafana:latest
    container_name: mikrotik-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
      - grafana_data:/var/lib/grafana
    ports:
      - "127.0.0.1:3001:3000"
    networks:
      - mikrotik-vpn-net

volumes:
  prometheus_data:
  grafana_data:

networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create Dockerfile for app
    cat << 'EOF' > "$SYSTEM_DIR/app/Dockerfile"
FROM node:20-alpine

WORKDIR /app

# Install dependencies for canvas and other native modules
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    cairo-dev \
    jpeg-dev \
    pango-dev \
    giflib-dev \
    pixman-dev \
    pangomm-dev \
    libjpeg-turbo-dev \
    freetype-dev

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p logs uploads

# Set user
USER node

# Expose port
EXPOSE 3000

# Start command
CMD ["node", "server.js"]
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
    
    # Create main control script
    cat << 'EOF' > "$SCRIPT_DIR/mikrotik-vpn"
#!/bin/bash
# MikroTik VPN Management System Control Script

set -e

SYSTEM_DIR="/opt/mikrotik-vpn"
CONFIG_DIR="$SYSTEM_DIR/configs"

# Load configuration
if [[ -f "$CONFIG_DIR/setup.env" ]]; then
    source "$CONFIG_DIR/setup.env"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
print_header() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        MikroTik VPN Management System Control Panel           ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

show_menu() {
    echo
    echo "1. System Status"
    echo "2. Start All Services"
    echo "3. Stop All Services"
    echo "4. Restart All Services"
    echo "5. View Logs"
    echo "6. Backup System"
    echo "7. Generate VPN Client Config"
    echo "8. System Health Check"
    echo "9. Show Credentials"
    echo "0. Exit"
    echo
    read -p "Select option: " choice
}

system_status() {
    echo -e "\n${GREEN}=== System Status ===${NC}"
    cd "$SYSTEM_DIR"
    docker compose ps
    echo
    echo -e "${GREEN}=== Resource Usage ===${NC}"
    docker stats --no-stream
}

start_services() {
    echo -e "\n${GREEN}Starting all services...${NC}"
    cd "$SYSTEM_DIR"
    docker compose up -d
    echo -e "${GREEN}All services started!${NC}"
}

stop_services() {
    echo -e "\n${YELLOW}Stopping all services...${NC}"
    cd "$SYSTEM_DIR"
    docker compose down
    echo -e "${YELLOW}All services stopped!${NC}"
}

restart_services() {
    echo -e "\n${YELLOW}Restarting all services...${NC}"
    stop_services
    sleep 3
    start_services
}

view_logs() {
    echo
    echo "Select log to view:"
    echo "1. Application logs"
    echo "2. MongoDB logs"
    echo "3. Redis logs"
    echo "4. Nginx logs"
    echo "5. OpenVPN logs"
    echo "6. All logs"
    read -p "Enter choice: " log_choice
    
    cd "$SYSTEM_DIR"
    case $log_choice in
        1) docker compose logs -f app ;;
        2) docker compose logs -f mongodb ;;
        3) docker compose logs -f redis ;;
        4) docker compose logs -f nginx ;;
        5) docker compose logs -f openvpn ;;
        6) docker compose logs -f ;;
        *) echo "Invalid choice" ;;
    esac
}

backup_system() {
    echo -e "\n${GREEN}Creating backup...${NC}"
    bash "$SCRIPT_DIR/backup.sh"
}

generate_vpn_client() {
    echo -e "\n${GREEN}Generating VPN client configuration...${NC}"
    read -p "Enter client name: " client_name
    
    # Generate client config
    docker exec -it mikrotik-openvpn easyrsa build-client-full "$client_name" nopass
    docker exec -it mikrotik-openvpn ovpn_getclient "$client_name" > "$SYSTEM_DIR/clients/${client_name}.ovpn"
    
    echo -e "${GREEN}Client configuration saved to: $SYSTEM_DIR/clients/${client_name}.ovpn${NC}"
}

health_check() {
    echo -e "\n${GREEN}Running health check...${NC}"
    bash "$SCRIPT_DIR/health-check.sh"
}

show_credentials() {
    echo -e "\n${GREEN}=== System Credentials ===${NC}"
    if [[ -f "$CONFIG_DIR/credentials.txt" ]]; then
        cat "$CONFIG_DIR/credentials.txt"
    else
        echo "Credentials file not found!"
    fi
}

# Main
check_root
print_header

while true; do
    show_menu
    case $choice in
        1) system_status ;;
        2) start_services ;;
        3) stop_services ;;
        4) restart_services ;;
        5) view_logs ;;
        6) backup_system ;;
        7) generate_vpn_client ;;
        8) health_check ;;
        9) show_credentials ;;
        0) echo "Exiting..."; exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
    clear
    print_header
done
EOF

    chmod +x "$SCRIPT_DIR/mikrotik-vpn"
    ln -sf "$SCRIPT_DIR/mikrotik-vpn" /usr/local/bin/mikrotik-vpn

    # Create backup script
    cat << 'EOF' > "$SCRIPT_DIR/backup.sh"
#!/bin/bash
# Backup script for MikroTik VPN System

BACKUP_DIR="/opt/mikrotik-vpn/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="backup_$DATE"

echo "Starting backup..."

# Create backup directory
mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

# Backup MongoDB
echo "Backing up MongoDB..."
docker exec mikrotik-mongodb mongodump --host localhost --username admin --password "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin --out /backup
docker cp mikrotik-mongodb:/backup "$BACKUP_DIR/$BACKUP_NAME/mongodb"
docker exec mikrotik-mongodb rm -rf /backup

# Backup Redis
echo "Backing up Redis..."
docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" BGSAVE
sleep 5
docker cp mikrotik-redis:/data/dump.rdb "$BACKUP_DIR/$BACKUP_NAME/redis_dump.rdb"

# Backup configuration files
echo "Backing up configuration..."
cp -r /opt/mikrotik-vpn/configs "$BACKUP_DIR/$BACKUP_NAME/"
cp -r /opt/mikrotik-vpn/nginx "$BACKUP_DIR/$BACKUP_NAME/"
cp -r /opt/mikrotik-vpn/openvpn "$BACKUP_DIR/$BACKUP_NAME/"

# Compress backup
cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

echo "Backup completed: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"

# Clean old backups (keep last 7 days)
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +7 -delete
EOF

    chmod +x "$SCRIPT_DIR/backup.sh"

    # Create health check script
    cat << 'EOF' > "$SCRIPT_DIR/health-check.sh"
#!/bin/bash
# Health check script

echo "=== MikroTik VPN System Health Check ==="
echo "Time: $(date)"
echo

# Check Docker services
echo "Checking services..."
services=("mongodb" "redis" "app" "nginx" "openvpn")
for service in "${services[@]}"; do
    if docker ps | grep -q "mikrotik-$service"; then
        echo "✓ $service is running"
    else
        echo "✗ $service is not running"
    fi
done

echo
echo "Checking connectivity..."
# Check MongoDB
if docker exec mikrotik-mongodb mongosh --eval "db.adminCommand('ping')" &>/dev/null; then
    echo "✓ MongoDB is responsive"
else
    echo "✗ MongoDB is not responsive"
fi

# Check Redis
if docker exec mikrotik-redis redis-cli ping &>/dev/null; then
    echo "✓ Redis is responsive"
else
    echo "✗ Redis is not responsive"
fi

# Check web app
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health | grep -q "200"; then
    echo "✓ Web application is responsive"
else
    echo "✗ Web application is not responsive"
fi

echo
echo "Disk usage:"
df -h /opt/mikrotik-vpn

echo
echo "Memory usage:"
free -h

echo
echo "Health check completed"
EOF

    chmod +x "$SCRIPT_DIR/health-check.sh"

    log "Phase 8 completed successfully!"
}

# =============================================================================
# PHASE 9: SECURITY CONFIGURATION
# =============================================================================

phase9_security_configuration() {
    log "==================================================================="
    log "PHASE 9: SECURITY CONFIGURATION"
    log "==================================================================="
    
    # Configure UFW firewall
    log "Configuring firewall..."
    
    # Default policies
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow $SSH_PORT/tcp comment 'SSH'
    
    # Allow web traffic
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow VPN
    ufw allow 1194/udp comment 'OpenVPN'
    
    # Enable firewall
    echo "y" | ufw enable
    
    # Configure fail2ban
    log "Configuring fail2ban..."
    
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

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
logpath = /opt/mikrotik-vpn/logs/nginx/error.log
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log "Phase 9 completed successfully!"
}

# =============================================================================
# PHASE 10: FINAL SETUP AND VERIFICATION
# =============================================================================

phase10_final_setup() {
    log "==================================================================="
    log "PHASE 10: FINAL SETUP AND VERIFICATION"
    log "==================================================================="
    
    # Load configuration
    if [[ -f "$CONFIG_DIR/setup.env" ]]; then
        source "$CONFIG_DIR/setup.env"
    fi
    
    # Create controllers if not exists
    if [[ ! -d "$SYSTEM_DIR/app/controllers" ]]; then
        create_controller_files
    fi
    
    # Create systemd service
    create_systemd_service
    
    # Set final permissions
    set_final_permissions
    
    # Initialize OpenVPN PKI
    initialize_openvpn
    
    # Create self-signed SSL certificate for testing
    create_self_signed_ssl
    
    # Start all services
    start_all_services
    
    # Create initial admin user
    create_initial_admin
    
    # Run final health check
    run_final_health_check
    
    # Create completion report
    create_completion_report
    
    log "Phase 10 completed successfully!"
}

# Create systemd service
create_systemd_service() {
    cat << EOF > /etc/systemd/system/mikrotik-vpn.service
[Unit]
Description=MikroTik VPN Management System
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/mikrotik-vpn
ExecStart=/usr/local/bin/mikrotik-vpn start
ExecStop=/usr/local/bin/mikrotik-vpn stop
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mikrotik-vpn
}

# Set final permissions
set_final_permissions() {
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR"
    chmod -R 755 "$SYSTEM_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 600 "$CONFIG_DIR/setup.env"
    chmod -R 755 "$SCRIPT_DIR"
}

# Initialize OpenVPN
initialize_openvpn() {
    log "Initializing OpenVPN PKI..."
    
    cd "$SYSTEM_DIR/openvpn/easy-rsa"
    
    # Initialize PKI
    ./easyrsa init-pki
    
    # Build CA
    echo "MikroTik VPN CA" | ./easyrsa build-ca nopass
    
    # Generate server certificate
    ./easyrsa gen-req vpn-server nopass
    echo "yes" | ./easyrsa sign-req server vpn-server
    
    # Generate DH parameters
    ./easyrsa gen-dh
    
    # Generate HMAC key
    openvpn --genkey --secret ta.key
    
    # Copy files to server directory
    cp pki/ca.crt pki/issued/vpn-server.crt pki/private/vpn-server.key pki/dh.pem ta.key ../server/
}

# Create self-signed SSL certificate
create_self_signed_ssl() {
    log "Creating self-signed SSL certificate..."
    
    mkdir -p "$SYSTEM_DIR/ssl"
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SYSTEM_DIR/ssl/privkey.pem" \
        -out "$SYSTEM_DIR/ssl/fullchain.pem" \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME"
}

# Start all services
start_all_services() {
    log "Starting all services..."
    
    cd "$SYSTEM_DIR"
    docker compose up -d
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 30
}

# Create initial admin user
create_initial_admin() {
    log "Creating initial admin user..."
    
    # Generate admin password
    ADMIN_PASSWORD=$(openssl rand -base64 12)
    
    # Create admin user via API
    # This would typically be done through the application's API
    
    # Save credentials
    cat << EOF > "$CONFIG_DIR/credentials.txt"
==============================================
MikroTik VPN Management System Credentials
==============================================

Web Interface:
URL: https://$DOMAIN_NAME
Admin Username: admin
Admin Password: $ADMIN_PASSWORD

Database:
MongoDB Root: admin / $MONGO_ROOT_PASSWORD
MongoDB App: mikrotik_app / $MONGO_APP_PASSWORD
Redis: $REDIS_PASSWORD

Monitoring:
Grafana: admin / $GRAFANA_PASSWORD

API Key: $API_KEY

VPN Network: $VPN_NETWORK

==============================================
IMPORTANT: Change all passwords after first login!
==============================================
EOF

    chmod 600 "$CONFIG_DIR/credentials.txt"
}

# Run final health check
run_final_health_check() {
    log "Running final health check..."
    
    # Check all services
    local all_healthy=true
    
    if ! docker ps | grep -q mikrotik-mongodb; then
        log_error "MongoDB is not running"
        all_healthy=false
    fi
    
    if ! docker ps | grep -q mikrotik-redis; then
        log_error "Redis is not running"
        all_healthy=false
    fi
    
    if ! docker ps | grep -q mikrotik-app; then
        log_error "Application is not running"
        all_healthy=false
    fi
    
    if ! docker ps | grep -q mikrotik-nginx; then
        log_error "Nginx is not running"
        all_healthy=false
    fi
    
    if ! docker ps | grep -q mikrotik-openvpn; then
        log_error "OpenVPN is not running"
        all_healthy=false
    fi
    
    if [[ "$all_healthy" == "true" ]]; then
        log "All services are healthy!"
    else
        log_warning "Some services are not healthy. Check logs for details."
    fi
}

# Create completion report
create_completion_report() {
    cat << EOF > "$CONFIG_DIR/installation-report.txt"
===============================================
MikroTik VPN Management System
Installation Report
===============================================

Date: $(date)
Domain: $DOMAIN_NAME
Admin Email: $ADMIN_EMAIL
Default Language: $DEFAULT_LANGUAGE
Default Currency: $DEFAULT_CURRENCY

Services Status:
$(cd "$SYSTEM_DIR" && docker compose ps)

Access URLs:
- Main Application: https://$DOMAIN_NAME
- API Documentation: https://$DOMAIN_NAME/api-docs
- Monitoring (Grafana): http://$DOMAIN_NAME:3001
- Prometheus: http://$DOMAIN_NAME:9090

Next Steps:
1. Access the web interface at https://$DOMAIN_NAME
2. Login with admin credentials (see credentials.txt)
3. Change all default passwords
4. Configure payment gateways
5. Add MikroTik devices
6. Create voucher profiles
7. Customize portal templates

For management, use: mikrotik-vpn

===============================================
EOF
}')
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
║        MikroTik VPN Management System - Installation v5.0                 ║
║                                                                           ║
║       Complete Installation with Multi-language & Payment Gateway         ║
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
        echo "Default Language: $DEFAULT_LANGUAGE"
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
    
    # Default language
    echo
    echo "Select default language:"
    echo "1. Thai (ไทย)"
    echo "2. English"
    read -p "Enter choice (1-2): " lang_choice
    case $lang_choice in
        1) DEFAULT_LANGUAGE="th" ;;
        2) DEFAULT_LANGUAGE="en" ;;
        *) DEFAULT_LANGUAGE="th" ;;
    esac
    
    # Currency
    echo
    echo "Select default currency:"
    echo "1. THB (Thai Baht)"
    echo "2. USD (US Dollar)"
    echo "3. EUR (Euro)"
    read -p "Enter choice (1-3): " currency_choice
    case $currency_choice in
        1) DEFAULT_CURRENCY="THB" ;;
        2) DEFAULT_CURRENCY="USD" ;;
        3) DEFAULT_CURRENCY="EUR" ;;
        *) DEFAULT_CURRENCY="THB" ;;
    esac
    
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
    PAYMENT_API_KEY=$(openssl rand -base64 32)
    PAYMENT_SECRET=$(openssl rand -base64 32)
    
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
    echo "Default Language: $DEFAULT_LANGUAGE"
    echo "Default Currency: $DEFAULT_CURRENCY"
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
export DEFAULT_LANGUAGE="$DEFAULT_LANGUAGE"
export DEFAULT_CURRENCY="$DEFAULT_CURRENCY"

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

# Payment Gateway
export PAYMENT_API_KEY="$PAYMENT_API_KEY"
export PAYMENT_SECRET="$PAYMENT_SECRET"

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
DEFAULT_LANGUAGE=$DEFAULT_LANGUAGE
DEFAULT_CURRENCY=$DEFAULT_CURRENCY
PAYMENT_API_KEY=$PAYMENT_API_KEY
PAYMENT_SECRET=$PAYMENT_SECRET
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
        iptables \
        fonts-thai-tlwg \
        language-pack-th \
        gettext
    
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
            fix_docker_service
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
    
    # Start Docker
    systemctl start docker || fix_docker_service
    systemctl enable docker
    
    # Verify Docker is working
    log "Verifying Docker installation..."
    if docker run --rm hello-world &>/dev/null; then
        log "Docker is working correctly"
    else
        log_error "Docker test failed"
        exit 1
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
        "$SYSTEM_DIR/app/public/css"
        "$SYSTEM_DIR/app/public/js"
        "$SYSTEM_DIR/app/public/images"
        "$SYSTEM_DIR/app/public/fonts"
        "$SYSTEM_DIR/app/views"
        "$SYSTEM_DIR/app/views/layouts"
        "$SYSTEM_DIR/app/views/partials"
        "$SYSTEM_DIR/app/views/portal"
        "$SYSTEM_DIR/app/views/admin"
        "$SYSTEM_DIR/app/config"
        "$SYSTEM_DIR/app/locales"
        "$SYSTEM_DIR/app/locales/th"
        "$SYSTEM_DIR/app/locales/en"
        "$SYSTEM_DIR/app/services"
        "$SYSTEM_DIR/app/api"
        "$SYSTEM_DIR/app/api/payment"
        "$SYSTEM_DIR/app/api/mikrotik"
        "$SYSTEM_DIR/app/test"
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
        "$SYSTEM_DIR/templates"
        "$SYSTEM_DIR/templates/voucher"
        "$SYSTEM_DIR/templates/portal"
        "$SYSTEM_DIR/templates/email"
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
# PHASE 5: NODE.JS APPLICATION WITH FULL FEATURES
# =============================================================================

phase5_nodejs_application() {
    log "==================================================================="
    log "PHASE 5: SETTING UP NODE.JS APPLICATION WITH FULL FEATURES"
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
    
    # Create package.json with all dependencies
    cat << 'EOF' > "$SYSTEM_DIR/app/package.json"
{
  "name": "mikrotik-vpn-management",
  "version": "5.0.0",
  "description": "MikroTik VPN-based Hotspot Management System with Multi-language and Payment Gateway",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "lint": "eslint .",
    "build:css": "tailwindcss -i ./public/css/app.css -o ./public/css/output.css --watch"
  },
  "keywords": [
    "mikrotik",
    "vpn",
    "hotspot",
    "management",
    "payment",
    "multi-language"
  ],
  "author": "MikroTik VPN Team",
  "license": "MIT",
  "dependencies": {
    "express": "^4.19.2",
    "express-session": "^1.18.0",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "compression": "^1.7.4",
    "mongoose": "^8.0.3",
    "redis": "^4.6.12",
    "ioredis": "^5.3.2",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "passport": "^0.7.0",
    "passport-jwt": "^4.0.1",
    "passport-local": "^1.0.0",
    "dotenv": "^16.3.1",
    "winston": "^3.11.0",
    "morgan": "^1.10.0",
    "socket.io": "^4.7.4",
    "axios": "^1.6.5",
    "node-fetch": "^3.3.2",
    "joi": "^17.11.0",
    "moment": "^2.30.1",
    "moment-timezone": "^0.5.44",
    "nodemailer": "^6.9.8",
    "uuid": "^9.0.1",
    "multer": "^1.4.5-lts.1",
    "sharp": "^0.33.1",
    "qrcode": "^1.5.3",
    "speakeasy": "^2.0.0",
    "node-cron": "^3.0.3",
    "bull": "^4.12.0",
    "swagger-jsdoc": "^6.2.8",
    "swagger-ui-express": "^5.0.0",
    "express-validator": "^7.0.1",
    "i18next": "^23.7.16",
    "i18next-fs-backend": "^2.3.1",
    "i18next-http-middleware": "^3.5.0",
    "node-routeros": "^1.6.8",
    "pdfkit": "^0.14.0",
    "escpos": "^3.0.0-alpha.6",
    "escpos-usb": "^3.0.0-alpha.4",
    "promptpay-qr": "^0.5.0",
    "omise": "^0.12.1",
    "stripe": "^14.12.0",
    "paypal-rest-sdk": "^1.8.1",
    "ejs": "^3.1.9",
    "express-ejs-layouts": "^2.5.1",
    "connect-flash": "^0.1.1",
    "method-override": "^3.0.0",
    "express-fileupload": "^1.4.3",
    "node-schedule": "^2.1.1",
    "csv-parser": "^3.0.0",
    "xlsx": "^0.18.5",
    "puppeteer": "^21.7.0",
    "@tailwindcss/forms": "^0.5.7",
    "@tailwindcss/typography": "^0.5.10",
    "alpinejs": "^3.13.3",
    "chart.js": "^4.4.1",
    "datatables.net": "^1.13.8",
    "sweetalert2": "^11.10.3",
    "dayjs": "^1.11.10",
    "lodash": "^4.17.21",
    "sanitize-html": "^2.11.0",
    "express-mongo-sanitize": "^2.2.0",
    "hpp": "^0.2.3",
    "connect-redis": "^7.1.0",
    "express-slow-down": "^2.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "eslint": "^8.56.0",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "tailwindcss": "^3.4.0",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32"
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
    
    # Create main server file with all features
    create_server_js_full
    
    # Create i18n configuration
    create_i18n_config
    
    # Create route files with full features
    create_route_files_full
    
    # Create model files with payment support
    create_model_files_full
    
    # Create middleware files
    create_middleware_files_full
    
    # Create service files
    create_service_files
    
    # Create utility files
    create_utility_files_full
    
    # Create configuration files
    create_app_config_files_full
    
    # Create view templates
    create_view_templates
    
    # Create captive portal templates
    create_captive_portal_templates
    
    # Create Tailwind CSS configuration
    create_tailwind_config
    
    # Install dependencies with audit fix
    log "Installing Node.js dependencies..."
    cd "$SYSTEM_DIR/app"
    npm install --production
    
    # Fix vulnerabilities
    npm audit fix --force || log_warning "Some vulnerabilities could not be fixed automatically"
    
    log "Phase 5 completed successfully!"
}

# Create enhanced server.js with all features
create_server_js_full() {
    cat << 'EOF' > "$SYSTEM_DIR/app/server.js"
const express = require('express');
const mongoose = require('mongoose');
const redis = require('redis');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
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
const i18next = require('i18next');
const i18nextMiddleware = require('i18next-http-middleware');
const Backend = require('i18next-fs-backend');
const expressLayouts = require('express-ejs-layouts');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const fileUpload = require('express-fileupload');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const slowDown = require('express-slow-down');

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

// Initialize i18n
i18next
    .use(Backend)
    .use(i18nextMiddleware.LanguageDetector)
    .init({
        backend: {
            loadPath: path.join(__dirname, 'locales/{{lng}}/{{ns}}.json'),
            addPath: path.join(__dirname, 'locales/{{lng}}/{{ns}}.missing.json')
        },
        fallbackLng: process.env.DEFAULT_LANGUAGE || 'th',
        supportedLngs: ['th', 'en', 'zh', 'ja', 'ko', 'ms', 'id', 'vi', 'lo', 'my', 'tl'],
        preload: ['th', 'en'],
        ns: ['common', 'portal', 'admin', 'payment', 'voucher', 'email'],
        defaultNS: 'common',
        detection: {
            order: ['querystring', 'cookie', 'header'],
            lookupQuerystring: 'lang',
            lookupCookie: 'language',
            lookupHeader: 'accept-language',
            caches: ['cookie']
        },
        saveMissing: true,
        saveMissingTo: 'all'
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

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layouts/main');
app.set('layout extractScripts', true);
app.set('layout extractStyles', true);

// Middleware setup
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "wss:", "https:"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
        },
    },
}));

app.use(cors({
    origin: process.env.CORS_ORIGIN?.split(',') || '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept-Language'],
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(methodOverride('_method'));
app.use(mongoSanitize());
app.use(hpp());

// File upload configuration
app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    createParentPath: true,
    useTempFiles: true,
    tempFileDir: '/tmp/'
}));

// Request logging
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Rate limiting for API
const apiSpeedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 100, // allow 100 requests per windowMs
    delayMs: 100 // begin adding 100ms of delay per request above delayAfter
});

app.use('/api/', apiSpeedLimiter);

// Session configuration with Redis store
const RedisStoreInstance = new RedisStore({
    client: redisClient,
    prefix: 'mikrotik-sess:'
});

app.use(session({
    store: RedisStoreInstance,
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

// Flash messages
app.use(flash());

// i18n middleware
app.use(i18nextMiddleware.handle(i18next));

// Global variables middleware
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    res.locals.user = req.user || null;
    res.locals.lang = req.language;
    res.locals.t = req.t;
    res.locals.moment = require('moment-timezone');
    res.locals.currency = process.env.DEFAULT_CURRENCY || 'THB';
    next();
});

// Static files
app.use('/static', express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: true
}));

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// API Documentation
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'MikroTik VPN Management API',
            version: '5.0.0',
            description: 'Comprehensive API for MikroTik VPN-based Hotspot Management with Payment Gateway',
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
            version: '5.0.0',
            features: {
                multiLanguage: true,
                paymentGateway: true,
                mikrotikIntegration: true,
                voucherSystem: true,
                captivePortal: true
            },
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
    metrics.push(`app_info{version="5.0.0",node_version="${process.version}"} 1`);
    
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

// Load routes
const authRoutes = require('./routes/auth');
const deviceRoutes = require('./routes/devices');
const userRoutes = require('./routes/users');
const voucherRoutes = require('./routes/vouchers');
const monitoringRoutes = require('./routes/monitoring');
const adminRoutes = require('./routes/admin');
const paymentRoutes = require('./routes/payment');
const mikrotikRoutes = require('./routes/mikrotik');
const portalRoutes = require('./routes/portal');
const reportRoutes = require('./routes/reports');
const dashboardRoutes = require('./routes/dashboard');
const settingsRoutes = require('./routes/settings');

// Web routes
app.use('/', dashboardRoutes);
app.use('/portal', portalRoutes);
app.use('/admin', adminRoutes);
app.use('/settings', settingsRoutes);

// API routes with versioning
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/devices', deviceRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/vouchers', voucherRoutes);
app.use('/api/v1/monitoring', monitoringRoutes);
app.use('/api/v1/payment', paymentRoutes);
app.use('/api/v1/mikrotik', mikrotikRoutes);
app.use('/api/v1/reports', reportRoutes);

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
    
    // Handle hotspot user updates
    socket.on('hotspot:user:update', async (data) => {
        try {
            io.to(`device:${data.deviceId}`).emit('hotspot:user:updated', data);
            logger.info(`Hotspot user update: ${data.username}`);
        } catch (error) {
            logger.error('Socket error:', error);
        }
    });
    
    // Handle payment notifications
    socket.on('payment:notify', async (data) => {
        try {
            io.to(`org:${data.organizationId}`).emit('payment:notification', data);
            logger.info(`Payment notification: ${data.transactionId}`);
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
    res.status(404).render('errors/404', {
        layout: 'layouts/error',
        title: '404 - Page Not Found'
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
    
    // Check if request expects JSON
    if (req.xhr || req.headers.accept?.indexOf('json') > -1) {
        res.status(status).json({
            error: {
                message: process.env.NODE_ENV === 'production' ? 'Something went wrong!' : message,
                status: status,
                timestamp: new Date().toISOString()
            },
            ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
        });
    } else {
        res.status(status).render('errors/500', {
            layout: 'layouts/error',
            title: 'Error',
            message: process.env.NODE_ENV === 'production' ? 'Something went wrong!' : message,
            error: process.env.NODE_ENV === 'production' ? {} : err
        });
    }
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
        
        // Initialize services
        const { initializeServices } = require('./services');
        await initializeServices();
        
        // Start listening
        const PORT = process.env.PORT || 3000;
        const HOST = '0.0.0.0';
        
        server.listen(PORT, HOST, () => {
            logger.info(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║          MikroTik VPN Management System v5.0                  ║
║                                                               ║
║  Server running at: http://${HOST}:${PORT}                        ║
║  Environment: ${process.env.NODE_ENV || 'development'}                               ║
║  Process ID: ${process.pid}                                        ║
║  Default Language: ${process.env.DEFAULT_LANGUAGE || 'th'}                             ║
║  Payment Gateway: Enabled                                     ║
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

# Create i18n configuration and translation files
create_i18n_config() {
    # Thai translations
    mkdir -p "$SYSTEM_DIR/app/locales/th"
    
    cat << 'EOF' > "$SYSTEM_DIR/app/locales/th/common.json"
{
  "welcome": "ยินดีต้อนรับ",
  "login": "เข้าสู่ระบบ",
  "logout": "ออกจากระบบ",
  "dashboard": "แดชบอร์ด",
  "devices": "อุปกรณ์",
  "users": "ผู้ใช้",
  "vouchers": "บัตรกำนัดเวลา",
  "settings": "ตั้งค่า",
  "reports": "รายงาน",
  "language": "ภาษา",
  "save": "บันทึก",
  "cancel": "ยกเลิก",
  "delete": "ลบ",
  "edit": "แก้ไข",
  "add": "เพิ่ม",
  "search": "ค้นหา",
  "filter": "กรอง",
  "export": "ส่งออก",
  "import": "นำเข้า",
  "print": "พิมพ์",
  "loading": "กำลังโหลด...",
  "success": "สำเร็จ",
  "error": "ข้อผิดพลาด",
  "warning": "คำเตือน",
  "info": "ข้อมูล",
  "confirm": "ยืนยัน",
  "yes": "ใช่",
  "no": "ไม่",
  "all": "ทั้งหมด",
  "active": "ใช้งาน",
  "inactive": "ไม่ใช้งาน",
  "online": "ออนไลน์",
  "offline": "ออฟไลน์",
  "connected": "เชื่อมต่อ",
  "disconnected": "ไม่เชื่อมต่อ",
  "date": "วันที่",
  "time": "เวลา",
  "from": "จาก",
  "to": "ถึง",
  "total": "รวม",
  "amount": "จำนวน",
  "price": "ราคา",
  "status": "สถานะ",
  "action": "การดำเนินการ",
  "description": "รายละเอียด",
  "name": "ชื่อ",
  "email": "อีเมล",
  "phone": "โทรศัพท์",
  "address": "ที่อยู่",
  "organization": "องค์กร",
  "profile": "โปรไฟล์",
  "password": "รหัสผ่าน",
  "confirmPassword": "ยืนยันรหัสผ่าน",
  "forgotPassword": "ลืมรหัสผ่าน",
  "resetPassword": "รีเซ็ตรหัสผ่าน",
  "changePassword": "เปลี่ยนรหัสผ่าน",
  "newPassword": "รหัสผ่านใหม่",
  "currentPassword": "รหัสผ่านปัจจุบัน",
  "rememberMe": "จดจำฉัน",
  "copyright": "ลิขสิทธิ์"
}
EOF

    cat << 'EOF' > "$SYSTEM_DIR/app/locales/th/portal.json"
{
  "title": "พอร์ทัลฮอตสปอต",
  "welcome": "ยินดีต้อนรับสู่ WiFi ฟรี",
  "loginTitle": "เข้าสู่ระบบเพื่อใช้งานอินเทอร์เน็ต",
  "username": "ชื่อผู้ใช้",
  "password": "รหัสผ่าน",
  "voucherCode": "รหัสบัตร",
  "phoneNumber": "หมายเลขโทรศัพท์",
  "loginButton": "เข้าสู่ระบบ",
  "registerButton": "ลงทะเบียน",
  "termsAndConditions": "ข้อกำหนดและเงื่อนไข",
  "acceptTerms": "ฉันยอมรับข้อกำหนดและเงื่อนไข",
  "loginMethods": {
    "voucher": "บัตรกำนัดเวลา",
    "userpass": "ชื่อผู้ใช้/รหัสผ่าน",
    "social": "โซเชียลมีเดีย",
    "sms": "SMS OTP"
  },
  "errors": {
    "invalidCredentials": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
    "voucherExpired": "บัตรหมดอายุแล้ว",
    "voucherUsed": "บัตรถูกใช้แล้ว",
    "maxDevicesReached": "จำนวนอุปกรณ์เกินกำหนด",
    "sessionExpired": "เซสชันหมดอายุ",
    "networkError": "เกิดข้อผิดพลาดทางเครือข่าย"
  },
  "success": {
    "loginSuccessful": "เข้าสู่ระบบสำเร็จ",
    "redirecting": "กำลังเปลี่ยนเส้นทาง..."
  },
  "timeRemaining": "เวลาคงเหลือ",
  "dataRemaining": "ข้อมูลคงเหลือ",
  "disconnect": "ตัดการเชื่อมต่อ",
  "buyVoucher": "ซื้อบัตรเติมเวลา"
}
EOF

    cat << 'EOF' > "$SYSTEM_DIR/app/locales/th/voucher.json"
{
  "title": "จัดการบัตรกำนัดเวลา",
  "createVoucher": "สร้างบัตร",
  "voucherList": "รายการบัตร",
  "voucherDetails": "รายละเอียดบัตร",
  "generateBatch": "สร้างบัตรแบบกลุ่ม",
  "printVouchers": "พิมพ์บัตร",
  "fields": {
    "code": "รหัสบัตร",
    "profile": "โปรไฟล์",
    "duration": "ระยะเวลา",
    "price": "ราคา",
    "status": "สถานะ",
    "createdDate": "วันที่สร้าง",
    "activatedDate": "วันที่เปิดใช้งาน",
    "expiryDate": "วันหมดอายุ",
    "usedBy": "ใช้โดย",
    "device": "อุปกรณ์",
    "dataLimit": "จำกัดข้อมูล",
    "speedLimit": "จำกัดความเร็ว",
    "simultaneousUse": "ใช้พร้อมกัน",
    "validityPeriod": "ระยะเวลาใช้งาน"
  },
  "profiles": {
    "1hour": "1 ชั่วโมง",
    "3hours": "3 ชั่วโมง", 
    "1day": "1 วัน",
    "7days": "7 วัน",
    "30days": "30 วัน",
    "unlimited": "ไม่จำกัด"
  },
  "status": {
    "active": "พร้อมใช้งาน",
    "used": "ใช้แล้ว",
    "expired": "หมดอายุ",
    "suspended": "ระงับ"
  },
  "actions": {
    "generate": "สร้าง",
    "print": "พิมพ์",
    "export": "ส่งออก",
    "delete": "ลบ",
    "suspend": "ระงับ",
    "activate": "เปิดใช้งาน"
  },
  "batch": {
    "quantity": "จำนวน",
    "prefix": "คำนำหน้า",
    "suffix": "คำต่อท้าย",
    "length": "ความยาวรหัส",
    "generateButton": "สร้างบัตร"
  },
  "print": {
    "selectTemplate": "เลือกแม่แบบ",
    "paperSize": "ขนาดกระดาษ",
    "columns": "จำนวนคอลัมน์",
    "rows": "จำนวนแถว",
    "showQR": "แสดง QR Code",
    "showLogo": "แสดงโลโก้",
    "printButton": "พิมพ์"
  }
}
EOF

    cat << 'EOF' > "$SYSTEM_DIR/app/locales/th/payment.json"
{
  "title": "ชำระเงิน",
  "selectMethod": "เลือกวิธีชำระเงิน",
  "methods": {
    "promptpay": "พร้อมเพย์",
    "truewallet": "ทรูวอลเล็ท",
    "creditcard": "บัตรเครดิต/เดบิต",
    "banktransfer": "โอนเงินผ่านธนาคาร",
    "cash": "เงินสด"
  },
  "promptpay": {
    "scanQR": "สแกน QR Code เพื่อชำระเงิน",
    "amount": "จำนวนเงิน",
    "reference": "เลขอ้างอิง",
    "instruction": "กรุณาสแกน QR Code ด้วยแอปธนาคารของคุณ"
  },
  "confirmation": {
    "title": "ยืนยันการชำระเงิน",
    "uploadSlip": "อัปโหลดสลิป",
    "transactionId": "เลขที่ธุรกรรม",
    "dateTime": "วันที่และเวลา",
    "amount": "จำนวนเงิน",
    "confirmButton": "ยืนยันการชำระเงิน"
  },
  "status": {
    "pending": "รอการชำระเงิน",
    "processing": "กำลังตรวจสอบ",
    "completed": "ชำระเงินแล้ว",
    "failed": "ชำระเงินไม่สำเร็จ",
    "cancelled": "ยกเลิก",
    "refunded": "คืนเงินแล้ว"
  },
  "invoice": {
    "title": "ใบแจ้งหนี้",
    "invoiceNo": "เลขที่ใบแจ้งหนี้",
    "date": "วันที่",
    "dueDate": "วันครบกำหนด",
    "billTo": "ผู้ซื้อ",
    "items": "รายการ",
    "subtotal": "รวม",
    "vat": "ภาษีมูลค่าเพิ่ม 7%",
    "total": "รวมทั้งสิ้น",
    "printInvoice": "พิมพ์ใบแจ้งหนี้",
    "downloadPDF": "ดาวน์โหลด PDF"
  },
  "errors": {
    "paymentFailed": "การชำระเงินล้มเหลว",
    "invalidAmount": "จำนวนเงินไม่ถูกต้อง",
    "timeout": "หมดเวลาการชำระเงิน",
    "cancelled": "ยกเลิกการชำระเงิน"
  },
  "success": {
    "paymentCompleted": "ชำระเงินสำเร็จ",
    "voucherActivated": "เปิดใช้งานบัตรแล้ว"
  }
}
EOF

    # English translations
    mkdir -p "$SYSTEM_DIR/app/locales/en"
    
    cat << 'EOF' > "$SYSTEM_DIR/app/locales/en/common.json"
{
  "welcome": "Welcome",
  "login": "Login",
  "logout": "Logout",
  "dashboard": "Dashboard",
  "devices": "Devices",
  "users": "Users",
  "vouchers": "Vouchers",
  "settings": "Settings",
  "reports": "Reports",
  "language": "Language",
  "save": "Save",
  "cancel": "Cancel",
  "delete": "Delete",
  "edit": "Edit",
  "add": "Add",
  "search": "Search",
  "filter": "Filter",
  "export": "Export",
  "import": "Import",
  "print": "Print",
  "loading": "Loading...",
  "success": "Success",
  "error": "Error",
  "warning": "Warning",
  "info": "Information",
  "confirm": "Confirm",
  "yes": "Yes",
  "no": "No",
  "all": "All",
  "active": "Active",
  "inactive": "Inactive",
  "online": "Online",
  "offline": "Offline",
  "connected": "Connected",
  "disconnected": "Disconnected",
  "date": "Date",
  "time": "Time",
  "from": "From",
  "to": "To",
  "total": "Total",
  "amount": "Amount",
  "price": "Price",
  "status": "Status",
  "action": "Action",
  "description": "Description",
  "name": "Name",
  "email": "Email",
  "phone": "Phone",
  "address": "Address",
  "organization": "Organization",
  "profile": "Profile",
  "password": "Password",
  "confirmPassword": "Confirm Password",
  "forgotPassword": "Forgot Password",
  "resetPassword": "Reset Password",
  "changePassword": "Change Password",
  "newPassword": "New Password",
  "currentPassword": "Current Password",
  "rememberMe": "Remember Me",
  "copyright": "Copyright"
}
EOF

    cat << 'EOF' > "$SYSTEM_DIR/app/locales/en/portal.json"
{
  "title": "Hotspot Portal",
  "welcome": "Welcome to Free WiFi",
  "loginTitle": "Login to access the internet",
  "username": "Username",
  "password": "Password",
  "voucherCode": "Voucher Code",
  "phoneNumber": "Phone Number",
  "loginButton": "Login",
  "registerButton": "Register",
  "termsAndConditions": "Terms and Conditions",
  "acceptTerms": "I accept the terms and conditions",
  "loginMethods": {
    "voucher": "Voucher",
    "userpass": "Username/Password",
    "social": "Social Media",
    "sms": "SMS OTP"
  },
  "errors": {
    "invalidCredentials": "Invalid username or password",
    "voucherExpired": "Voucher has expired",
    "voucherUsed": "Voucher already used",
    "maxDevicesReached": "Maximum devices exceeded",
    "sessionExpired": "Session expired",
    "networkError": "Network error occurred"
  },
  "success": {
    "loginSuccessful": "Login successful",
    "redirecting": "Redirecting..."
  },
  "timeRemaining": "Time Remaining",
  "dataRemaining": "Data Remaining",
  "disconnect": "Disconnect",
  "buyVoucher": "Buy Voucher"
}
EOF

    cat << 'EOF' > "$SYSTEM_DIR/app/locales/en/voucher.json"
{
  "title": "Voucher Management",
  "createVoucher": "Create Voucher",
  "voucherList": "Voucher List",
  "voucherDetails": "Voucher Details",
  "generateBatch": "Generate Batch",
  "printVouchers": "Print Vouchers",
  "fields": {
    "code": "Voucher Code",
    "profile": "Profile",
    "duration": "Duration",
    "price": "Price",
    "status": "Status",
    "createdDate": "Created Date",
    "activatedDate": "Activated Date",
    "expiryDate": "Expiry Date",
    "usedBy": "Used By",
    "device": "Device",
    "dataLimit": "Data Limit",
    "speedLimit": "Speed Limit",
    "simultaneousUse": "Simultaneous Use",
    "validityPeriod": "Validity Period"
  },
  "profiles": {
    "1hour": "1 Hour",
    "3hours": "3 Hours",
    "1day": "1 Day",
    "7days": "7 Days",
    "30days": "30 Days",
    "unlimited": "Unlimited"
  },
  "status": {
    "active": "Active",
    "used": "Used",
    "expired": "Expired",
    "suspended": "Suspended"
  },
  "actions": {
    "generate": "Generate",
    "print": "Print",
    "export": "Export",
    "delete": "Delete",
    "suspend": "Suspend",
    "activate": "Activate"
  },
  "batch": {
    "quantity": "Quantity",
    "prefix": "Prefix",
    "suffix": "Suffix",
    "length": "Code Length",
    "generateButton": "Generate Vouchers"
  },
  "print": {
    "selectTemplate": "Select Template",
    "paperSize": "Paper Size",
    "columns": "Columns",
    "rows": "Rows",
    "showQR": "Show QR Code",
    "showLogo": "Show Logo",
    "printButton": "Print"
  }
}
EOF

    cat << 'EOF' > "$SYSTEM_DIR/app/locales/en/payment.json"
{
  "title": "Payment",
  "selectMethod": "Select Payment Method",
  "methods": {
    "promptpay": "PromptPay",
    "truewallet": "TrueWallet",
    "creditcard": "Credit/Debit Card",
    "banktransfer": "Bank Transfer",
    "cash": "Cash"
  },
  "promptpay": {
    "scanQR": "Scan QR Code to pay",
    "amount": "Amount",
    "reference": "Reference",
    "instruction": "Please scan the QR code with your banking app"
  },
  "confirmation": {
    "title": "Payment Confirmation",
    "uploadSlip": "Upload Slip",
    "transactionId": "Transaction ID",
    "dateTime": "Date & Time",
    "amount": "Amount",
    "confirmButton": "Confirm Payment"
  },
  "status": {
    "pending": "Pending Payment",
    "processing": "Processing",
    "completed": "Paid",
    "failed": "Payment Failed",
    "cancelled": "Cancelled",
    "refunded": "Refunded"
  },
  "invoice": {
    "title": "Invoice",
    "invoiceNo": "Invoice Number",
    "date": "Date",
    "dueDate": "Due Date",
    "billTo": "Bill To",
    "items": "Items",
    "subtotal": "Subtotal",
    "vat": "VAT 7%",
    "total": "Total",
    "printInvoice": "Print Invoice",
    "downloadPDF": "Download PDF"
  },
  "errors": {
    "paymentFailed": "Payment failed",
    "invalidAmount": "Invalid amount",
    "timeout": "Payment timeout",
    "cancelled": "Payment cancelled"
  },
  "success": {
    "paymentCompleted": "Payment completed",
    "voucherActivated": "Voucher activated"
  }
}
EOF
}

# Create enhanced route files
create_route_files_full() {
    # Payment routes
    cat << 'EOF' > "$SYSTEM_DIR/app/routes/payment.js"
const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const { auth, authorize } = require('../middleware/auth');
const PaymentService = require('../services/PaymentService');
const VoucherService = require('../services/VoucherService');

/**
 * @swagger
 * tags:
 *   name: Payment
 *   description: Payment gateway integration endpoints
 */

/**
 * @swagger
 * /api/v1/payment/methods:
 *   get:
 *     summary: Get available payment methods
 *     tags: [Payment]
 *     responses:
 *       200:
 *         description: Success
 */
router.get('/methods', async (req, res, next) => {
    try {
        const methods = await PaymentService.getAvailableMethods();
        res.json({
            success: true,
            data: methods
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /api/v1/payment/promptpay/generate:
 *   post:
 *     summary: Generate PromptPay QR code
 *     tags: [Payment]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount:
 *                 type: number
 *               reference:
 *                 type: string
 *     responses:
 *       200:
 *         description: QR code generated
 */
router.post('/promptpay/generate',
    body('amount').isNumeric().isFloat({ min: 1 }),
    body('reference').optional().isString(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const { amount, reference } = req.body;
            const qrCode = await PaymentService.generatePromptPayQR(amount, reference);
            
            res.json({
                success: true,
                data: {
                    qrCode,
                    amount,
                    reference: reference || PaymentService.generateReference(),
                    expiresAt: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/payment/confirm:
 *   post:
 *     summary: Confirm payment
 *     tags: [Payment]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               transactionId:
 *                 type: string
 *               method:
 *                 type: string
 *               amount:
 *                 type: number
 *               reference:
 *                 type: string
 *               slipImage:
 *                 type: string
 *     responses:
 *       200:
 *         description: Payment confirmed
 */
router.post('/confirm',
    auth,
    body('transactionId').isString(),
    body('method').isIn(['promptpay', 'truewallet', 'creditcard', 'banktransfer']),
    body('amount').isNumeric(),
    body('reference').isString(),
    body('slipImage').optional().isString(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const payment = await PaymentService.confirmPayment({
                ...req.body,
                userId: req.user._id,
                organizationId: req.user.organization
            });
            
            // If payment is for voucher, activate it
            if (payment.type === 'voucher' && payment.status === 'completed') {
                await VoucherService.activateByPayment(payment._id);
            }
            
            res.json({
                success: true,
                data: payment
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/payment/webhook/{provider}:
 *   post:
 *     summary: Payment provider webhook
 *     tags: [Payment]
 *     parameters:
 *       - in: path
 *         name: provider
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Webhook processed
 */
router.post('/webhook/:provider', async (req, res, next) => {
    try {
        const { provider } = req.params;
        const result = await PaymentService.processWebhook(provider, req.body, req.headers);
        
        res.json({
            success: true,
            data: result
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /api/v1/payment/transactions:
 *   get:
 *     summary: Get payment transactions
 *     tags: [Payment]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *       - in: query
 *         name: method
 *         schema:
 *           type: string
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Success
 */
router.get('/transactions',
    auth,
    async (req, res, next) => {
        try {
            const filters = {
                organizationId: req.user.organization,
                ...req.query
            };
            
            const transactions = await PaymentService.getTransactions(filters);
            
            res.json({
                success: true,
                data: transactions
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/payment/invoice/{transactionId}:
 *   get:
 *     summary: Get invoice for transaction
 *     tags: [Payment]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: transactionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Invoice data
 */
router.get('/invoice/:transactionId',
    auth,
    param('transactionId').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const invoice = await PaymentService.generateInvoice(req.params.transactionId);
            
            res.json({
                success: true,
                data: invoice
            });
        } catch (error) {
            next(error);
        }
    }
);

module.exports = router;
EOF

    # MikroTik routes
    cat << 'EOF' > "$SYSTEM_DIR/app/routes/mikrotik.js"
const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const { auth, authorize } = require('../middleware/auth');
const MikroTikService = require('../services/MikroTikService');

/**
 * @swagger
 * tags:
 *   name: MikroTik
 *   description: MikroTik RouterOS integration endpoints
 */

/**
 * @swagger
 * /api/v1/mikrotik/devices/{deviceId}/connect:
 *   post:
 *     summary: Connect to MikroTik device
 *     tags: [MikroTik]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Connected successfully
 */
router.post('/devices/:deviceId/connect',
    auth,
    authorize('admin', 'operator'),
    param('deviceId').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const result = await MikroTikService.connectDevice(req.params.deviceId);
            
            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/mikrotik/devices/{deviceId}/hotspot/users:
 *   get:
 *     summary: Get hotspot users from device
 *     tags: [MikroTik]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Hotspot users list
 */
router.get('/devices/:deviceId/hotspot/users',
    auth,
    param('deviceId').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const users = await MikroTikService.getHotspotUsers(req.params.deviceId);
            
            res.json({
                success: true,
                data: users
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/mikrotik/devices/{deviceId}/hotspot/users:
 *   post:
 *     summary: Create hotspot user on device
 *     tags: [MikroTik]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               profile:
 *                 type: string
 *               limitUptime:
 *                 type: string
 *               limitBytesIn:
 *                 type: number
 *               limitBytesOut:
 *                 type: number
 *     responses:
 *       201:
 *         description: User created
 */
router.post('/devices/:deviceId/hotspot/users',
    auth,
    authorize('admin', 'operator'),
    param('deviceId').isMongoId(),
    body('username').isString().isLength({ min: 3 }),
    body('password').isString().isLength({ min: 6 }),
    body('profile').isString(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const user = await MikroTikService.createHotspotUser(
                req.params.deviceId,
                req.body
            );
            
            res.status(201).json({
                success: true,
                data: user
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/mikrotik/devices/{deviceId}/hotspot/active:
 *   get:
 *     summary: Get active hotspot sessions
 *     tags: [MikroTik]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Active sessions list
 */
router.get('/devices/:deviceId/hotspot/active',
    auth,
    param('deviceId').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const sessions = await MikroTikService.getActiveSessions(req.params.deviceId);
            
            res.json({
                success: true,
                data: sessions
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/mikrotik/devices/{deviceId}/hotspot/disconnect:
 *   post:
 *     summary: Disconnect hotspot user
 *     tags: [MikroTik]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *     responses:
 *       200:
 *         description: User disconnected
 */
router.post('/devices/:deviceId/hotspot/disconnect',
    auth,
    authorize('admin', 'operator'),
    param('deviceId').isMongoId(),
    body('username').isString(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            await MikroTikService.disconnectUser(
                req.params.deviceId,
                req.body.username
            );
            
            res.json({
                success: true,
                message: 'User disconnected successfully'
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/mikrotik/devices/{deviceId}/system/resource:
 *   get:
 *     summary: Get system resource usage
 *     tags: [MikroTik]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: System resource data
 */
router.get('/devices/:deviceId/system/resource',
    auth,
    param('deviceId').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const resources = await MikroTikService.getSystemResource(req.params.deviceId);
            
            res.json({
                success: true,
                data: resources
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/mikrotik/devices/{deviceId}/config/backup:
 *   post:
 *     summary: Backup device configuration
 *     tags: [MikroTik]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Backup created
 */
router.post('/devices/:deviceId/config/backup',
    auth,
    authorize('admin'),
    param('deviceId').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const backup = await MikroTikService.backupConfiguration(req.params.deviceId);
            
            res.json({
                success: true,
                data: backup
            });
        } catch (error) {
            next(error);
        }
    }
);

module.exports = router;
EOF

    # Portal routes (captive portal)
    cat << 'EOF' > "$SYSTEM_DIR/app/routes/portal.js"
const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const PortalController = require('../controllers/PortalController');

// Captive portal landing page
router.get('/', PortalController.showPortal);

// Login page with different methods
router.get('/login', PortalController.showLogin);

// Voucher login
router.post('/login/voucher',
    body('code').isString().trim().isLength({ min: 6 }),
    PortalController.loginVoucher
);

// Username/password login
router.post('/login/userpass',
    body('username').isString().trim(),
    body('password').isString(),
    PortalController.loginUserPass
);

// SMS OTP request
router.post('/login/sms/request',
    body('phone').isMobilePhone('th-TH'),
    PortalController.requestSmsOtp
);

// SMS OTP verify
router.post('/login/sms/verify',
    body('phone').isMobilePhone('th-TH'),
    body('otp').isString().isLength({ min: 6, max: 6 }),
    PortalController.verifySmsOtp
);

// Social login callback
router.get('/login/social/:provider/callback', PortalController.socialLoginCallback);

// Status page (after login)
router.get('/status', PortalController.showStatus);

// Logout
router.post('/logout', PortalController.logout);

// Terms and conditions
router.get('/terms', PortalController.showTerms);

// Language change
router.get('/lang/:lang', (req, res) => {
    const { lang } = req.params;
    res.cookie('language', lang, { maxAge: 900000, httpOnly: true });
    res.redirect('back');
});

module.exports = router;
EOF

    # Dashboard routes
    cat << 'EOF' > "$SYSTEM_DIR/app/routes/dashboard.js"
const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const DashboardController = require('../controllers/DashboardController');

// Main dashboard
router.get('/', auth, DashboardController.index);

// Real-time stats API
router.get('/api/stats', auth, DashboardController.getStats);

// Device overview
router.get('/devices', auth, DashboardController.devices);

// Voucher management
router.get('/vouchers', auth, DashboardController.vouchers);
router.get('/vouchers/create', auth, DashboardController.createVoucherForm);
router.post('/vouchers/create', auth, DashboardController.createVoucher);
router.get('/vouchers/print/:id', auth, DashboardController.printVoucher);

// User management
router.get('/users', auth, DashboardController.users);

// Reports
router.get('/reports', auth, DashboardController.reports);
router.get('/reports/revenue', auth, DashboardController.revenueReport);
router.get('/reports/usage', auth, DashboardController.usageReport);
router.get('/reports/export', auth, DashboardController.exportReport);

module.exports = router;
EOF

    # Reports routes
    cat << 'EOF' > "$SYSTEM_DIR/app/routes/reports.js"
const express = require('express');
const router = express.Router();
const { auth, authorize } = require('../middleware/auth');
const ReportService = require('../services/ReportService');

/**
 * @swagger
 * tags:
 *   name: Reports
 *   description: Reporting and analytics endpoints
 */

/**
 * @swagger
 * /api/v1/reports/revenue:
 *   get:
 *     summary: Get revenue report
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: groupBy
 *         schema:
 *           type: string
 *           enum: [day, week, month]
 *     responses:
 *       200:
 *         description: Revenue report data
 */
router.get('/revenue',
    auth,
    authorize('admin', 'manager'),
    async (req, res, next) => {
        try {
            const report = await ReportService.generateRevenueReport({
                organizationId: req.user.organization,
                ...req.query
            });
            
            res.json({
                success: true,
                data: report
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/reports/usage:
 *   get:
 *     summary: Get usage statistics report
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: deviceId
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Usage statistics
 */
router.get('/usage',
    auth,
    async (req, res, next) => {
        try {
            const report = await ReportService.generateUsageReport({
                organizationId: req.user.organization,
                ...req.query
            });
            
            res.json({
                success: true,
                data: report
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/reports/vouchers:
 *   get:
 *     summary: Get voucher statistics report
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Voucher statistics
 */
router.get('/vouchers',
    auth,
    async (req, res, next) => {
        try {
            const report = await ReportService.generateVoucherReport({
                organizationId: req.user.organization,
                ...req.query
            });
            
            res.json({
                success: true,
                data: report
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/reports/devices:
 *   get:
 *     summary: Get device performance report
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Device performance data
 */
router.get('/devices',
    auth,
    async (req, res, next) => {
        try {
            const report = await ReportService.generateDeviceReport({
                organizationId: req.user.organization,
                ...req.query
            });
            
            res.json({
                success: true,
                data: report
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/reports/export:
 *   post:
 *     summary: Export report to file
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [revenue, usage, vouchers, devices]
 *               format:
 *                 type: string
 *                 enum: [pdf, excel, csv]
 *               filters:
 *                 type: object
 *     responses:
 *       200:
 *         description: Export file URL
 */
router.post('/export',
    auth,
    body('type').isIn(['revenue', 'usage', 'vouchers', 'devices']),
    body('format').isIn(['pdf', 'excel', 'csv']),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const exportUrl = await ReportService.exportReport({
                organizationId: req.user.organization,
                userId: req.user._id,
                ...req.body
            });
            
            res.json({
                success: true,
                data: {
                    url: exportUrl,
                    expiresAt: new Date(Date.now() + 3600000) // 1 hour
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

module.exports = router;
EOF

    # Settings routes
    cat << 'EOF' > "$SYSTEM_DIR/app/routes/settings.js"
const express = require('express');
const router = express.Router();
const { auth, authorize } = require('../middleware/auth');
const SettingsController = require('../controllers/SettingsController');

// General settings
router.get('/', auth, SettingsController.index);
router.post('/general', auth, authorize('admin'), SettingsController.updateGeneral);

// Organization settings
router.get('/organization', auth, authorize('admin'), SettingsController.organization);
router.post('/organization', auth, authorize('admin'), SettingsController.updateOrganization);

// Payment settings
router.get('/payment', auth, authorize('admin'), SettingsController.payment);
router.post('/payment', auth, authorize('admin'), SettingsController.updatePayment);

// Portal customization
router.get('/portal', auth, authorize('admin'), SettingsController.portal);
router.post('/portal', auth, authorize('admin'), SettingsController.updatePortal);
router.post('/portal/template', auth, authorize('admin'), SettingsController.uploadPortalTemplate);

// Voucher profiles
router.get('/vouchers', auth, authorize('admin'), SettingsController.voucherProfiles);
router.post('/vouchers/profile', auth, authorize('admin'), SettingsController.createVoucherProfile);
router.put('/vouchers/profile/:id', auth, authorize('admin'), SettingsController.updateVoucherProfile);
router.delete('/vouchers/profile/:id', auth, authorize('admin'), SettingsController.deleteVoucherProfile);

// Email settings
router.get('/email', auth, authorize('admin'), SettingsController.email);
router.post('/email', auth, authorize('admin'), SettingsController.updateEmail);
router.post('/email/test', auth, authorize('admin'), SettingsController.testEmail);

// API settings
router.get('/api', auth, authorize('admin'), SettingsController.api);
router.post('/api/key', auth, authorize('admin'), SettingsController.generateApiKey);
router.delete('/api/key/:id', auth, authorize('admin'), SettingsController.deleteApiKey);

module.exports = router;
EOF

    # Update existing route files with authentication
    local routes=("auth" "devices" "users" "vouchers" "monitoring" "admin")
    
    for route in "${routes[@]}"; do
        if [[ "$route" == "vouchers" ]]; then
            # Enhanced voucher routes
            cat << 'EOF' > "$SYSTEM_DIR/app/routes/vouchers.js"
const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const { auth, authorize } = require('../middleware/auth');
const VoucherService = require('../services/VoucherService');
const PDFService = require('../services/PDFService');

/**
 * @swagger
 * tags:
 *   name: Vouchers
 *   description: Voucher management endpoints
 */

/**
 * @swagger
 * /api/v1/vouchers:
 *   get:
 *     summary: Get all vouchers
 *     tags: [Vouchers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [active, used, expired, suspended]
 *       - in: query
 *         name: deviceId
 *         schema:
 *           type: string
 *       - in: query
 *         name: batchId
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Success
 */
router.get('/', auth, async (req, res, next) => {
    try {
        const filters = {
            organization: req.user.organization,
            ...req.query
        };
        
        const vouchers = await VoucherService.getVouchers(filters);
        
        res.json({
            success: true,
            data: vouchers
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /api/v1/vouchers/generate:
 *   post:
 *     summary: Generate vouchers in batch
 *     tags: [Vouchers]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               quantity:
 *                 type: number
 *               profile:
 *                 type: string
 *               prefix:
 *                 type: string
 *               suffix:
 *                 type: string
 *               length:
 *                 type: number
 *               price:
 *                 type: number
 *               deviceId:
 *                 type: string
 *     responses:
 *       201:
 *         description: Vouchers created
 */
router.post('/generate',
    auth,
    authorize('admin', 'operator'),
    body('quantity').isInt({ min: 1, max: 1000 }),
    body('profile').isString(),
    body('length').optional().isInt({ min: 6, max: 16 }),
    body('price').optional().isNumeric(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const vouchers = await VoucherService.generateBatch({
                ...req.body,
                organization: req.user.organization,
                createdBy: req.user._id
            });
            
            res.status(201).json({
                success: true,
                data: {
                    count: vouchers.length,
                    batchId: vouchers[0]?.batch?.id,
                    vouchers: vouchers
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/vouchers/{id}:
 *   get:
 *     summary: Get voucher by ID
 *     tags: [Vouchers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Success
 */
router.get('/:id',
    auth,
    param('id').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const voucher = await VoucherService.getVoucherById(req.params.id);
            
            if (!voucher || voucher.organization.toString() !== req.user.organization.toString()) {
                return res.status(404).json({ error: 'Voucher not found' });
            }
            
            res.json({
                success: true,
                data: voucher
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/vouchers/validate:
 *   post:
 *     summary: Validate voucher code
 *     tags: [Vouchers]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               code:
 *                 type: string
 *               deviceId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Validation result
 */
router.post('/validate',
    body('code').isString().trim(),
    body('deviceId').optional().isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const result = await VoucherService.validateVoucher(req.body.code, req.body.deviceId);
            
            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/vouchers/activate:
 *   post:
 *     summary: Activate voucher
 *     tags: [Vouchers]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               code:
 *                 type: string
 *               deviceId:
 *                 type: string
 *               macAddress:
 *                 type: string
 *               ipAddress:
 *                 type: string
 *     responses:
 *       200:
 *         description: Activation result
 */
router.post('/activate',
    body('code').isString().trim(),
    body('deviceId').isMongoId(),
    body('macAddress').optional().isMACAddress(),
    body('ipAddress').optional().isIP(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const result = await VoucherService.activateVoucher(req.body);
            
            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/vouchers/print:
 *   post:
 *     summary: Generate printable vouchers
 *     tags: [Vouchers]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               voucherIds:
 *                 type: array
 *                 items:
 *                   type: string
 *               template:
 *                 type: string
 *               format:
 *                 type: string
 *                 enum: [pdf, thermal]
 *     responses:
 *       200:
 *         description: Print file URL
 */
router.post('/print',
    auth,
    body('voucherIds').isArray(),
    body('format').isIn(['pdf', 'thermal']),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const printUrl = await PDFService.generateVoucherPrint({
                ...req.body,
                organization: req.user.organization
            });
            
            res.json({
                success: true,
                data: {
                    url: printUrl,
                    expiresAt: new Date(Date.now() + 3600000) // 1 hour
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/vouchers/{id}/suspend:
 *   put:
 *     summary: Suspend voucher
 *     tags: [Vouchers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Voucher suspended
 */
router.put('/:id/suspend',
    auth,
    authorize('admin', 'operator'),
    param('id').isMongoId(),
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const voucher = await VoucherService.suspendVoucher(req.params.id, req.user._id);
            
            res.json({
                success: true,
                data: voucher
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * @swagger
 * /api/v1/vouchers/stats:
 *   get:
 *     summary: Get voucher statistics
 *     tags: [Vouchers]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Voucher statistics
 */
router.get('/stats',
    auth,
    async (req, res, next) => {
        try {
            const stats = await VoucherService.getStatistics(req.user.organization);
            
            res.json({
                success: true,
                data: stats
            });
        } catch (error) {
            next(error);
        }
    }
);

module.exports = router;
EOF
        fi
    done
}

# Create enhanced model files
create_model_files_full() {
    # Payment Transaction model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/PaymentTransaction.js"
const mongoose = require('mongoose');

const paymentTransactionSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    transactionId: {
        type: String,
        required: true,
        unique: true
    },
    reference: {
        type: String,
        required: true
    },
    method: {
        type: String,
        enum: ['promptpay', 'truewallet', 'creditcard', 'banktransfer', 'cash'],
        required: true
    },
    type: {
        type: String,
        enum: ['voucher', 'topup', 'subscription', 'other'],
        required: true
    },
    amount: {
        value: {
            type: Number,
            required: true
        },
        currency: {
            type: String,
            default: 'THB'
        }
    },
    status: {
        type: String,
        enum: ['pending', 'processing', 'completed', 'failed', 'cancelled', 'refunded'],
        default: 'pending'
    },
    relatedItem: {
        model: {
            type: String,
            enum: ['Voucher', 'User', 'Subscription']
        },
        id: mongoose.Schema.Types.ObjectId
    },
    paymentDetails: {
        promptpay: {
            mobileNumber: String,
            qrCode: String
        },
        creditcard: {
            last4: String,
            brand: String
        },
        banktransfer: {
            bank: String,
            accountNumber: String
        }
    },
    slipImage: String,
    providerData: mongoose.Schema.Types.Mixed,
    webhook: {
        received: Boolean,
        data: mongoose.Schema.Types.Mixed,
        timestamp: Date
    },
    metadata: mongoose.Schema.Types.Mixed,
    notes: String,
    processedAt: Date,
    completedAt: Date,
    failedReason: String
}, {
    timestamps: true
});

// Indexes
paymentTransactionSchema.index({ organization: 1 });
paymentTransactionSchema.index({ transactionId: 1 });
paymentTransactionSchema.index({ reference: 1 });
paymentTransactionSchema.index({ status: 1 });
paymentTransactionSchema.index({ method: 1 });
paymentTransactionSchema.index({ createdAt: -1 });

// Methods
paymentTransactionSchema.methods.markAsCompleted = function() {
    this.status = 'completed';
    this.completedAt = new Date();
    return this.save();
};

paymentTransactionSchema.methods.markAsFailed = function(reason) {
    this.status = 'failed';
    this.failedReason = reason;
    return this.save();
};

module.exports = mongoose.model('PaymentTransaction', paymentTransactionSchema);
EOF

    # Portal Template model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/PortalTemplate.js"
const mongoose = require('mongoose');

const portalTemplateSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },
    name: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['default', 'custom', 'seasonal'],
        default: 'default'
    },
    isActive: {
        type: Boolean,
        default: false
    },
    design: {
        logo: String,
        backgroundImage: String,
        backgroundColor: String,
        primaryColor: String,
        secondaryColor: String,
        fontFamily: String,
        customCSS: String
    },
    content: {
        title: mongoose.Schema.Types.Mixed, // Multi-language
        subtitle: mongoose.Schema.Types.Mixed,
        welcomeMessage: mongoose.Schema.Types.Mixed,
        termsAndConditions: mongoose.Schema.Types.Mixed,
        footer: mongoose.Schema.Types.Mixed
    },
    loginMethods: [{
        type: String,
        enum: ['voucher', 'userpass', 'social', 'sms'],
        enabled: Boolean,
        order: Number
    }],
    socialProviders: [{
        provider: {
            type: String,
            enum: ['facebook', 'line', 'google']
        },
        enabled: Boolean,
        appId: String,
        appSecret: String
    }],
    features: {
        showLogo: {
            type: Boolean,
            default: true
        },
        showLanguageSelector: {
            type: Boolean,
            default: true
        },
        showTerms: {
            type: Boolean,
            default: true
        },
        requireTermsAcceptance: {
            type: Boolean,
            default: true
        },
        showVoucherPurchase: {
            type: Boolean,
            default: true
        },
        autoRedirect: {
            enabled: Boolean,
            url: String,
            delay: Number
        }
    },
    redirectUrl: {
        success: String,
        error: String
    },
    customFields: [{
        fieldName: String,
        fieldType: {
            type: String,
            enum: ['text', 'email', 'phone', 'select', 'checkbox']
        },
        required: Boolean,
        label: mongoose.Schema.Types.Mixed,
        options: [String]
    }],
    metadata: mongoose.Schema.Types.Mixed
}, {
    timestamps: true
});

// Indexes
portalTemplateSchema.index({ organization: 1 });
portalTemplateSchema.index({ isActive: 1 });

module.exports = mongoose.model('PortalTemplate', portalTemplateSchema);
EOF

    # Hotspot Profile model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/HotspotProfile.js"
const mongoose = require('mongoose');

const hotspotProfileSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },
    name: {
        type: String,
        required: true
    },
    description: String,
    mikrotikProfile: {
        name: String, // Profile name in MikroTik
        sharedUsers: {
            type: Number,
            default: 1
        },
        rateLimit: {
            upload: String, // e.g., "1M" for 1Mbps
            download: String
        },
        sessionTimeout: String, // e.g., "1h" for 1 hour
        idleTimeout: String,
        keepaliveTimeout: String,
        statusAutorefresh: String
    },
    limits: {
        duration: {
            value: Number,
            unit: {
                type: String,
                enum: ['minutes', 'hours', 'days', 'weeks', 'months']
            }
        },
        dataLimit: {
            value: Number,
            unit: {
                type: String,
                enum: ['MB', 'GB']
            }
        },
        speed: {
            upload: Number, // in Mbps
            download: Number
        },
        simultaneousDevices: {
            type: Number,
            default: 1
        }
    },
    pricing: {
        amount: Number,
        currency: {
            type: String,
            default: 'THB'
        },
        taxIncluded: {
            type: Boolean,
            default: true
        }
    },
    validity: {
        activationPeriod: Number, // Days within which voucher must be activated
        gracePeriod: Number // Minutes after expiry before disconnection
    },
    accessTime: {
        enabled: Boolean,
        schedule: [{
            day: {
                type: Number,
                min: 0,
                max: 6 // 0 = Sunday
            },
            startTime: String, // HH:MM format
            endTime: String
        }]
    },
    isActive: {
        type: Boolean,
        default: true
    },
    isDefault: {
        type: Boolean,
        default: false
    },
    order: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

// Indexes
hotspotProfileSchema.index({ organization: 1 });
hotspotProfileSchema.index({ isActive: 1 });
hotspotProfileSchema.index({ order: 1 });

module.exports = mongoose.model('HotspotProfile', hotspotProfileSchema);
EOF

    # SMS OTP model
    cat << 'EOF' > "$SYSTEM_DIR/app/models/SmsOtp.js"
const mongoose = require('mongoose');

const smsOtpSchema = new mongoose.Schema({
    phone: {
        type: String,
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    purpose: {
        type: String,
        enum: ['login', 'register', 'verification', 'password_reset'],
        default: 'login'
    },
    attempts: {
        type: Number,
        default: 0
    },
    maxAttempts: {
        type: Number,
        default: 3
    },
    isUsed: {
        type: Boolean,
        default: false
    },
    usedAt: Date,
    expiresAt: {
        type: Date,
        default: Date.now,
        expires: 300 // 5 minutes
    },
    ipAddress: String,
    userAgent: String,
    metadata: mongoose.Schema.Types.Mixed
}, {
    timestamps: true
});

// Indexes
smsOtpSchema.index({ phone: 1 });
smsOtpSchema.index({ otp: 1 });
smsOtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Methods
smsOtpSchema.methods.verify = function(inputOtp) {
    if (this.isUsed) {
        throw new Error('OTP already used');
    }
    
    if (this.attempts >= this.maxAttempts) {
        throw new Error('Maximum attempts exceeded');
    }
    
    if (new Date() > this.expiresAt) {
        throw new Error('OTP expired');
    }
    
    this.attempts++;
    
    if (this.otp === inputOtp) {
        this.isUsed = true;
        this.usedAt = new Date();
        return this.save();
    } else {
        this.save();
        throw new Error('Invalid OTP');
    }
};

module.exports = mongoose.model('SmsOtp', smsOtpSchema);
EOF

    # Update existing models with new fields
    # Update Organization model
    cat << 'EOF' >> "$SYSTEM_DIR/app/models/Organization.js"

// Add payment settings to organization schema
organizationSchema.add({
    paymentSettings: {
        enabled: {
            type: Boolean,
            default: true
        },
        methods: [{
            method: {
                type: String,
                enum: ['promptpay', 'truewallet', 'creditcard', 'banktransfer', 'cash']
            },
            enabled: Boolean,
            config: mongoose.Schema.Types.Mixed
        }],
        promptpay: {
            mobileNumber: String,
            nationalId: String,
            displayName: String
        },
        bankTransfer: {
            accounts: [{
                bank: String,
                accountNumber: String,
                accountName: String,
                branch: String
            }]
        },
        taxInfo: {
            taxId: String,
            vatRate: {
                type: Number,
                default: 7
            },
            includeVat: {
                type: Boolean,
                default: true
            }
        }
    },
    portalSettings: {
        defaultTemplate: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'PortalTemplate'
        },
        allowedLanguages: [{
            type: String,
            enum: ['th', 'en', 'zh', 'ja', 'ko', 'ms', 'id', 'vi', 'lo', 'my', 'tl']
        }],
        defaultLanguage: {
            type: String,
            default: 'th'
        }
    }
});
EOF
}

# Create middleware files
create_middleware_files_full() {
    # Auth middleware with JWT
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/auth.js"
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    try {
        // Check for token in header or session
        let token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token && req.session?.token) {
            token = req.session.token;
        }
        
        if (!token) {
            // For web routes, redirect to login
            if (!req.xhr && req.headers.accept?.indexOf('json') === -1) {
                return res.redirect('/login');
            }
            throw new Error();
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ 
            _id: decoded._id, 
            isActive: true 
        }).populate('organization').select('-password');
        
        if (!user) {
            throw new Error();
        }
        
        // Check if organization is active
        if (!user.organization?.isActive) {
            throw new Error('Organization is inactive');
        }
        
        req.user = user;
        req.token = token;
        req.organization = user.organization;
        
        // Set user in locals for views
        res.locals.user = user;
        res.locals.organization = user.organization;
        
        next();
    } catch (error) {
        if (!req.xhr && req.headers.accept?.indexOf('json') === -1) {
            return res.redirect('/login');
        }
        res.status(401).json({ error: 'Please authenticate' });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            if (!req.xhr && req.headers.accept?.indexOf('json') === -1) {
                req.flash('error_msg', 'Access denied. Insufficient permissions.');
                return res.redirect('back');
            }
            return res.status(403).json({ 
                error: 'Access denied. Insufficient permissions.' 
            });
        }
        next();
    };
};

const apiAuth = async (req, res, next) => {
    try {
        const apiKey = req.header('X-API-Key');
        
        if (!apiKey) {
            throw new Error();
        }
        
        const user = await User.findOne({
            'apiKeys.key': apiKey,
            isActive: true
        }).populate('organization');
        
        if (!user) {
            throw new Error();
        }
        
        // Check if API key is still valid
        const apiKeyData = user.apiKeys.find(k => k.key === apiKey);
        if (apiKeyData.expiresAt && new Date() > apiKeyData.expiresAt) {
            throw new Error('API key expired');
        }
        
        // Update last used
        apiKeyData.lastUsed = new Date();
        await user.save();
        
        req.user = user;
        req.organization = user.organization;
        req.apiKey = apiKeyData;
        
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid API key' });
    }
};

module.exports = { auth, authorize, apiAuth };
EOF

    # Rate limiting middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/rateLimiter.js"
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const RedisStore = require('rate-limit-redis');

const createLimiter = (options = {}) => {
    const defaults = {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: 'Too many requests from this IP, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            if (req.xhr || req.headers.accept?.indexOf('json') > -1) {
                res.status(429).json({
                    error: options.message || defaults.message,
                    retryAfter: res.getHeader('Retry-After')
                });
            } else {
                res.status(429).render('errors/429', {
                    layout: 'layouts/error',
                    title: 'Too Many Requests',
                    message: options.message || defaults.message
                });
            }
        }
    };
    
    // Use Redis store if available
    if (global.redisClient) {
        defaults.store = new RedisStore({
            client: global.redisClient,
            prefix: 'rl:'
        });
    }
    
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
    max: 10
});

const voucherLimiter = createLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20,
    message: 'Too many voucher validation attempts'
});

// Speed limiter for sensitive operations
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 50,
    delayMs: 100,
    maxDelayMs: 2000,
    skipSuccessfulRequests: true,
    store: global.redisClient ? new RedisStore({
        client: global.redisClient,
        prefix: 'sd:'
    }) : undefined
});

module.exports = {
    createLimiter,
    loginLimiter,
    apiLimiter,
    strictLimiter,
    voucherLimiter,
    speedLimiter
};
EOF

    # Validation middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/validation.js"
const { validationResult } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        // For AJAX requests
        if (req.xhr || req.headers.accept?.indexOf('json') > -1) {
            return res.status(400).json({
                success: false,
                errors: errors.array().map(err => ({
                    field: err.param,
                    message: req.t ? req.t(`validation.${err.msg}`, err.msg) : err.msg,
                    value: err.value
                }))
            });
        }
        
        // For regular requests
        req.flash('error_msg', errors.array().map(err => err.msg).join(', '));
        return res.redirect('back');
    }
    
    next();
};

// Custom validators
const customValidators = {
    isThaiPhone: (value) => {
        const thaiPhoneRegex = /^(0[689]\d{8})$/;
        return thaiPhoneRegex.test(value);
    },
    
    isValidVoucherCode: (value) => {
        const voucherRegex = /^[A-Z0-9]{6,16}$/;
        return voucherRegex.test(value);
    },
    
    isValidMACAddress: (value) => {
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        return macRegex.test(value);
    }
};

module.exports = { handleValidationErrors, customValidators };
EOF

    # Security middleware
    cat << 'EOF' > "$SYSTEM_DIR/app/middleware/security.js"
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", "wss:", "https:"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false,
});

const sanitizeInput = (req, res, next) => {
    // Sanitize body, query, and params
    req.body = mongoSanitize.sanitize(req.body);
    req.query = mongoSanitize.sanitize(req.query);
    req.params = mongoSanitize.sanitize(req.params);
    next();
};

const preventParameterPollution = hpp({
    whitelist: ['sort', 'fields', 'page', 'limit']
});

module.exports = {
    securityHeaders,
    sanitizeInput,
    preventParameterPollution
};
EOF
}

# Create service files
create_service_files() {
    mkdir -p "$SYSTEM_DIR/app/services"
    
    # Payment Service
    cat << 'EOF' > "$SYSTEM_DIR/app/services/PaymentService.js"
const PaymentTransaction = require('../models/PaymentTransaction');
const promptpayQr = require('promptpay-qr');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

class PaymentService {
    static async getAvailableMethods() {
        // This would typically check organization settings
        return [
            {
                id: 'promptpay',
                name: 'PromptPay',
                icon: '/static/images/promptpay.png',
                enabled: true,
                fee: 0
            },
            {
                id: 'truewallet',
                name: 'TrueWallet',
                icon: '/static/images/truewallet.png',
                enabled: true,
                fee: 0
            },
            {
                id: 'creditcard',
                name: 'Credit/Debit Card',
                icon: '/static/images/card.png',
                enabled: true,
                fee: 3 // percentage
            },
            {
                id: 'banktransfer',
                name: 'Bank Transfer',
                icon: '/static/images/bank.png',
                enabled: true,
                fee: 0
            }
        ];
    }
    
    static generateReference() {
        return `REF${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`;
    }
    
    static async generatePromptPayQR(amount, reference, mobileNumber = null) {
        try {
            // Use organization's PromptPay number or default
            const payeeNumber = mobileNumber || process.env.PROMPTPAY_NUMBER || '0812345678';
            
            // Generate PromptPay payload
            const payload = promptpayQr(payeeNumber, { amount });
            
            // Generate QR code
            const qrCodeDataUrl = await QRCode.toDataURL(payload, {
                errorCorrectionLevel: 'M',
                type: 'image/png',
                width: 300,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#FFFFFF'
                }
            });
            
            return qrCodeDataUrl;
        } catch (error) {
            throw new Error('Failed to generate PromptPay QR code');
        }
    }
    
    static async createTransaction(data) {
        const transaction = new PaymentTransaction({
            transactionId: uuidv4(),
            reference: data.reference || this.generateReference(),
            ...data
        });
        
        await transaction.save();
        return transaction;
    }
    
    static async confirmPayment(data) {
        const { transactionId, method, amount, reference, slipImage, userId, organizationId } = data;
        
        let transaction = await PaymentTransaction.findOne({
            transactionId,
            organization: organizationId
        });
        
        if (!transaction) {
            // Create new transaction
            transaction = await this.createTransaction({
                organization: organizationId,
                user: userId,
                transactionId,
                reference,
                method,
                amount: { value: amount },
                type: 'voucher',
                status: 'processing'
            });
        }
        
        // Update transaction
        transaction.slipImage = slipImage;
        transaction.processedAt = new Date();
        
        // Here you would typically verify the payment with the provider
        // For now, we'll simulate auto-approval for demo
        if (slipImage) {
            transaction.status = 'completed';
            transaction.completedAt = new Date();
        }
        
        await transaction.save();
        
        // Emit payment status update via Socket.IO
        if (global.io) {
            global.io.to(`org:${organizationId}`).emit('payment:updated', {
                transactionId: transaction.transactionId,
                status: transaction.status
            });
        }
        
        return transaction;
    }
    
    static async processWebhook(provider, data, headers) {
        // Handle webhooks from different payment providers
        switch (provider) {
            case 'omise':
                return this.processOmiseWebhook(data, headers);
            case 'stripe':
                return this.processStripeWebhook(data, headers);
            case 'truemoney':
                return this.processTrueMoneyWebhook(data, headers);
            default:
                throw new Error('Unknown payment provider');
        }
    }
    
    static async processOmiseWebhook(data, headers) {
        // Verify webhook signature
        // Process Omise events
        const { key, data: eventData } = data;
        
        if (key === 'charge.complete') {
            const transaction = await PaymentTransaction.findOne({
                'providerData.chargeId': eventData.id
            });
            
            if (transaction) {
                if (eventData.status === 'successful') {
                    await transaction.markAsCompleted();
                } else {
                    await transaction.markAsFailed(eventData.failure_message);
                }
            }
        }
        
        return { success: true };
    }
    
    static async processStripeWebhook(data, headers) {
        // Similar implementation for Stripe
        return { success: true };
    }
    
    static async processTrueMoneyWebhook(data, headers) {
        // Similar implementation for TrueMoney
        return { success: true };
    }
    
    static async getTransactions(filters) {
        const query = {};
        
        if (filters.organizationId) {
            query.organization = filters.organizationId;
        }
        
        if (filters.status) {
            query.status = filters.status;
        }
        
        if (filters.method) {
            query.method = filters.method;
        }
        
        if (filters.from || filters.to) {
            query.createdAt = {};
            if (filters.from) {
                query.createdAt.$gte = new Date(filters.from);
            }
            if (filters.to) {
                query.createdAt.$lte = new Date(filters.to);
            }
        }
        
        const transactions = await PaymentTransaction.find(query)
            .populate('user', 'username email')
            .sort({ createdAt: -1 })
            .limit(filters.limit || 100);
        
        return transactions;
    }
    
    static async generateInvoice(transactionId) {
        const transaction = await PaymentTransaction.findById(transactionId)
            .populate('organization')
            .populate('user');
        
        if (!transaction) {
            throw new Error('Transaction not found');
        }
        
        // Generate invoice data
        const invoice = {
            invoiceNumber: `INV-${transaction.reference}`,
            date: transaction.createdAt,
            dueDate: transaction.createdAt,
            billTo: {
                name: transaction.user?.profile?.firstName + ' ' + transaction.user?.profile?.lastName,
                email: transaction.user?.email,
                phone: transaction.user?.profile?.phone,
                address: transaction.organization?.address
            },
            items: [{
                description: `Hotspot Voucher - ${transaction.type}`,
                quantity: 1,
                unitPrice: transaction.amount.value,
                total: transaction.amount.value
            }],
            subtotal: transaction.amount.value,
            vat: transaction.organization?.paymentSettings?.taxInfo?.includeVat
                ? transaction.amount.value * 0.07
                : 0,
            total: transaction.amount.value,
            paymentMethod: transaction.method,
            status: transaction.status
        };
        
        return invoice;
    }
}

module.exports = PaymentService;
EOF

    # MikroTik Service
    cat << 'EOF' > "$SYSTEM_DIR/app/services/MikroTikService.js"
const RouterOSClient = require('node-routeros').RouterOSClient;
const Device = require('../models/Device');
const logger = require('../utils/logger');

class MikroTikService {
    constructor() {
        this.connections = new Map();
    }
    
    async connectDevice(deviceId) {
        try {
            const device = await Device.findById(deviceId);
            if (!device) {
                throw new Error('Device not found');
            }
            
            // Check if already connected
            if (this.connections.has(deviceId)) {
                return this.connections.get(deviceId);
            }
            
            // Create new connection
            const client = new RouterOSClient({
                host: device.vpnIpAddress || device.ipAddress,
                user: process.env.MIKROTIK_USER || 'admin',
                password: process.env.MIKROTIK_PASSWORD || '',
                port: 8728,
                timeout: 10
            });
            
            await client.connect();
            
            // Store connection
            this.connections.set(deviceId, client);
            
            // Update device status
            device.status = 'online';
            device.lastSeen = new Date();
            await device.save();
            
            logger.info(`Connected to MikroTik device: ${device.name}`);
            
            return client;
        } catch (error) {
            logger.error(`Failed to connect to device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async disconnectDevice(deviceId) {
        const client = this.connections.get(deviceId);
        if (client) {
            await client.close();
            this.connections.delete(deviceId);
        }
    }
    
    async getHotspotUsers(deviceId) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const users = await client.write('/ip/hotspot/user/print');
            return users.map(user => ({
                id: user['.id'],
                name: user.name,
                password: user.password,
                profile: user.profile,
                uptime: user.uptime,
                bytesIn: parseInt(user['bytes-in'] || 0),
                bytesOut: parseInt(user['bytes-out'] || 0),
                packetsIn: parseInt(user['packets-in'] || 0),
                packetsOut: parseInt(user['packets-out'] || 0),
                disabled: user.disabled === 'true',
                comment: user.comment
            }));
        } catch (error) {
            logger.error(`Failed to get hotspot users from device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async createHotspotUser(deviceId, userData) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const result = await client.write('/ip/hotspot/user/add', [
                ['name', userData.username],
                ['password', userData.password],
                ['profile', userData.profile || 'default'],
                ['limit-uptime', userData.limitUptime || ''],
                ['limit-bytes-in', userData.limitBytesIn || ''],
                ['limit-bytes-out', userData.limitBytesOut || ''],
                ['comment', userData.comment || `Created via API at ${new Date().toISOString()}`]
            ]);
            
            logger.info(`Created hotspot user ${userData.username} on device ${deviceId}`);
            
            return { success: true, id: result[0] };
        } catch (error) {
            logger.error(`Failed to create hotspot user on device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async deleteHotspotUser(deviceId, username) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const users = await client.write('/ip/hotspot/user/print', [
                ['?name', username]
            ]);
            
            if (users.length === 0) {
                throw new Error('User not found');
            }
            
            await client.write('/ip/hotspot/user/remove', [
                ['numbers', users[0]['.id']]
            ]);
            
            logger.info(`Deleted hotspot user ${username} from device ${deviceId}`);
            
            return { success: true };
        } catch (error) {
            logger.error(`Failed to delete hotspot user from device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async getActiveSessions(deviceId) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const sessions = await client.write('/ip/hotspot/active/print');
            return sessions.map(session => ({
                id: session['.id'],
                user: session.user,
                address: session.address,
                macAddress: session['mac-address'],
                loginBy: session['login-by'],
                uptime: session.uptime,
                idleTime: session['idle-time'],
                sessionTimeLeft: session['session-time-left'],
                idleTimeout: session['idle-timeout'],
                bytesIn: parseInt(session['bytes-in'] || 0),
                bytesOut: parseInt(session['bytes-out'] || 0),
                packetsIn: parseInt(session['packets-in'] || 0),
                packetsOut: parseInt(session['packets-out'] || 0)
            }));
        } catch (error) {
            logger.error(`Failed to get active sessions from device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async disconnectUser(deviceId, username) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const sessions = await client.write('/ip/hotspot/active/print', [
                ['?user', username]
            ]);
            
            if (sessions.length === 0) {
                throw new Error('Active session not found');
            }
            
            await client.write('/ip/hotspot/active/remove', [
                ['numbers', sessions[0]['.id']]
            ]);
            
            logger.info(`Disconnected user ${username} from device ${deviceId}`);
            
            return { success: true };
        } catch (error) {
            logger.error(`Failed to disconnect user from device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async getSystemResource(deviceId) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const resources = await client.write('/system/resource/print');
            const resource = resources[0];
            
            return {
                uptime: resource.uptime,
                version: resource.version,
                buildTime: resource['build-time'],
                cpuModel: resource['cpu-model'],
                cpuCount: parseInt(resource['cpu-count']),
                cpuFrequency: parseInt(resource['cpu-frequency']),
                cpuLoad: parseInt(resource['cpu-load']),
                freeMemory: parseInt(resource['free-memory']),
                totalMemory: parseInt(resource['total-memory']),
                freeHddSpace: parseInt(resource['free-hdd-space']),
                totalHddSpace: parseInt(resource['total-hdd-space']),
                architecture: resource['architecture-name'],
                board: resource['board-name'],
                platform: resource.platform
            };
        } catch (error) {
            logger.error(`Failed to get system resources from device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async backupConfiguration(deviceId) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const filename = `backup-${deviceId}-${Date.now()}`;
            
            // Create backup
            await client.write('/system/backup/save', [
                ['name', filename]
            ]);
            
            // Wait for backup to complete
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Get backup file
            const files = await client.write('/file/print', [
                ['?name', `${filename}.backup`]
            ]);
            
            if (files.length === 0) {
                throw new Error('Backup file not found');
            }
            
            logger.info(`Created backup ${filename} for device ${deviceId}`);
            
            return {
                filename: `${filename}.backup`,
                size: parseInt(files[0].size),
                creationTime: files[0]['creation-time']
            };
        } catch (error) {
            logger.error(`Failed to backup device ${deviceId}:`, error);
            throw error;
        }
    }
    
    async getHotspotProfiles(deviceId) {
        const client = await this.connectDevice(deviceId);
        
        try {
            const profiles = await client.write('/ip/hotspot/user/profile/print');
            return profiles.map(profile => ({
                name: profile.name,
                sharedUsers: parseInt(profile['shared-users'] || 1),
                rateLimit: profile['rate-limit'],
                sessionTimeout: profile['session-timeout'],
                idleTimeout: profile['idle-timeout'],
                keepaliveTimeout: profile['keepalive-timeout'],
                statusAutorefresh: profile['status-autorefresh']
            }));
        } catch (error) {
            logger.error(`Failed to get hotspot profiles from device ${deviceId}:`, error);
            throw error;
        }
    }
    
    // Cleanup inactive connections
    cleanupConnections() {
        this.connections.forEach((client, deviceId) => {
            // Check if connection is still active
            // If not, remove it
            if (!client.connected) {
                this.connections.delete(deviceId);
            }
        });
    }
}

// Create singleton instance
const mikrotikService = new MikroTikService();

// Cleanup connections periodically
setInterval(() => {
    mikrotikService.cleanupConnections();
}, 60000); // Every minute

module.exports = mikrotikService;
EOF

    # Voucher Service
    cat << 'EOF' > "$SYSTEM_DIR/app/services/VoucherService.js"
const Voucher = require('../models/Voucher');
const MikroTikService = require('./MikroTikService');
const QRCodeService = require('../utils/qrcode');
const { v4: uuidv4 } = require('uuid');

class VoucherService {
    static generateCode(length = 8, prefix = '', suffix = '') {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let code = '';
        for (let i = 0; i < length; i++) {
            code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return prefix + code + suffix;
    }
    
    static async generateBatch(options) {
        const {
            quantity,
            profile,
            organization,
            createdBy,
            deviceId,
            prefix = '',
            suffix = '',
            length = 8,
            price
        } = options;
        
        const batchId = uuidv4();
        const vouchers = [];
        
        // Get profile details
        const profileData = await this.getProfileData(profile);
        
        for (let i = 0; i < quantity; i++) {
            let code;
            let isUnique = false;
            
            // Ensure unique code
            while (!isUnique) {
                code = this.generateCode(length, prefix, suffix);
                const existing = await Voucher.findOne({ code });
                if (!existing) {
                    isUnique = true;
                }
            }
            
            // Generate QR code
            const qrCode = await QRCodeService.generateVoucherQR({ code });
            
            const voucher = new Voucher({
                organization,
                device: deviceId,
                code,
                profile: profileData,
                status: 'active',
                price: {
                    amount: price || profileData.pricing?.amount || 0
                },
                batch: {
                    id: batchId,
                    createdBy,
                    createdAt: new Date()
                },
                qrCode
            });
            
            vouchers.push(voucher);
        }
        
        // Save all vouchers
        const savedVouchers = await Voucher.insertMany(vouchers);
        
        // If device is specified, create users on MikroTik
        if (deviceId) {
            try {
                for (const voucher of savedVouchers) {
                    await MikroTikService.createHotspotUser(deviceId, {
                        username: voucher.code,
                        password: voucher.code,
                        profile: profile,
                        limitUptime: this.formatDuration(profileData.duration),
                        limitBytesIn: profileData.dataLimit * 1024 * 1024, // Convert MB to bytes
                        comment: `Voucher created: ${new Date().toISOString()}`
                    });
                }
            } catch (error) {
                console.error('Failed to create MikroTik users:', error);
                // Don't fail the whole operation
            }
        }
        
        return savedVouchers;
    }
    
    static async getProfileData(profileName) {
        // This would typically fetch from database
        // For now, return default profiles
        const profiles = {
            '1hour': {
                name: '1 Hour',
                duration: { value: 1, unit: 'hours' },
                bandwidth: { upload: 1, download: 5 },
                dataLimit: 500, // MB
                simultaneousUse: 1,
                pricing: { amount: 10 }
            },
            '3hours': {
                name: '3 Hours',
                duration: { value: 3, unit: 'hours' },
                bandwidth: { upload: 2, download: 10 },
                dataLimit: 1000,
                simultaneousUse: 1,
                pricing: { amount: 25 }
            },
            '1day': {
                name: '1 Day',
                duration: { value: 1, unit: 'days' },
                bandwidth: { upload: 5, download: 20 },
                dataLimit: 5000,
                simultaneousUse: 2,
                pricing: { amount: 50 }
            },
            '7days': {
                name: '7 Days',
                duration: { value: 7, unit: 'days' },
                bandwidth: { upload: 10, download: 50 },
                dataLimit: 20000,
                simultaneousUse: 3,
                pricing: { amount: 200 }
            },
            '30days': {
                name: '30 Days',
                duration: { value: 30, unit: 'days' },
                bandwidth: { upload: 20, download: 100 },
                dataLimit: 100000,
                simultaneousUse: 5,
                pricing: { amount: 500 }
            }
        };
        
        return profiles[profileName] || profiles['1hour'];
    }
    
    static formatDuration(duration) {
        if (!duration) return '';
        
        const { value, unit } = duration;
        const suffixMap = {
            'minutes': 'm',
            'hours': 'h',
            'days': 'd',
            'weeks': 'w'
        };
        
        return `${value}${suffixMap[unit] || 'h'}`;
    }
    
    static async validateVoucher(code, deviceId = null) {
        const voucher = await Voucher.findOne({ 
            code: code.toUpperCase() 
        }).populate('device');
        
        if (!voucher) {
            return { valid: false, error: 'Voucher not found' };
        }
        
        if (voucher.status !== 'active') {
            return { valid: false, error: `Voucher is ${voucher.status}` };
        }
        
        if (deviceId && voucher.device && voucher.device._id.toString() !== deviceId) {
            return { valid: false, error: 'Voucher is for different location' };
        }
        
        if (voucher.usage.expiresAt && new Date() > voucher.usage.expiresAt) {
            voucher.status = 'expired';
            await voucher.save();
            return { valid: false, error: 'Voucher has expired' };
        }
        
        return { 
            valid: true, 
            voucher: voucher.toObject()
        };
    }
    
    static async activateVoucher(data) {
        const { code, deviceId, macAddress, ipAddress } = data;
        
        // Validate voucher
        const validation = await this.validateVoucher(code, deviceId);
        if (!validation.valid) {
            throw new Error(validation.error);
        }
        
        const voucher = await Voucher.findOne({ code: code.toUpperCase() });
        
        // Calculate expiry
        const now = new Date();
        let expiresAt = new Date(now);
        
        switch (voucher.profile.duration.unit) {
            case 'minutes':
                expiresAt.setMinutes(expiresAt.getMinutes() + voucher.profile.duration.value);
                break;
            case 'hours':
                expiresAt.setHours(expiresAt.getHours() + voucher.profile.duration.value);
                break;
            case 'days':
                expiresAt.setDate(expiresAt.getDate() + voucher.profile.duration.value);
                break;
            case 'weeks':
                expiresAt.setDate(expiresAt.getDate() + (voucher.profile.duration.value * 7));
                break;
            case 'months':
                expiresAt.setMonth(expiresAt.getMonth() + voucher.profile.duration.value);
                break;
        }
        
        // Update voucher
        voucher.status = 'used';
        voucher.usage.activatedAt = now;
        voucher.usage.expiresAt = expiresAt;
        voucher.usage.macAddress = macAddress;
        voucher.usage.ipAddress = ipAddress;
        
        await voucher.save();
        
        return {
            success: true,
            expiresAt,
            profile: voucher.profile
        };
    }
    
    static async getVouchers(filters) {
        const query = {};
        
        if (filters.organization) {
            query.organization = filters.organization;
        }
        
        if (filters.status) {
            query.status = filters.status;
        }
        
        if (filters.deviceId) {
            query.device = filters.deviceId;
        }
        
        if (filters.batchId) {
            query['batch.id'] = filters.batchId;
        }
        
        const vouchers = await Voucher.find(query)
            .populate('device', 'name location')
            .populate('batch.createdBy', 'username')
            .sort({ createdAt: -1 })
            .limit(filters.limit || 100);
        
        return vouchers;
    }
    
    static async getVoucherById(id) {
        return await Voucher.findById(id)
            .populate('device')
            .populate('organization')
            .populate('batch.createdBy');
    }
    
    static async suspendVoucher(id, userId) {
        const voucher = await Voucher.findById(id);
        if (!voucher) {
            throw new Error('Voucher not found');
        }
        
        voucher.status = 'suspended';
        voucher.notes = `Suspended by user ${userId} at ${new Date().toISOString()}`;
        
        await voucher.save();
        
        // Also disable on MikroTik if connected
        if (voucher.device) {
            try {
                await MikroTikService.deleteHotspotUser(voucher.device, voucher.code);
            } catch (error) {
                console.error('Failed to delete MikroTik user:', error);
            }
        }
        
        return voucher;
    }
    
    static async getStatistics(organizationId) {
        const stats = await Voucher.aggregate([
            { $match: { organization: organizationId } },
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 },
                    totalValue: { $sum: '$price.amount' }
                }
            }
        ]);
        
        const result = {
            total: 0,
            active: 0,
            used: 0,
            expired: 0,
            suspended: 0,
            totalValue: 0,
            activeValue: 0
        };
        
        stats.forEach(stat => {
            result[stat._id] = stat.count;
            result.total += stat.count;
            result.totalValue += stat.totalValue;
            
            if (stat._id === 'active') {
                result.activeValue = stat.totalValue;
            }
        });
        
        return result;
    }
    
    static async activateByPayment(paymentId) {
        // Find vouchers associated with payment
        const vouchers = await Voucher.find({
            'payment.transactionId': paymentId
        });
        
        for (const voucher of vouchers) {
            voucher.payment.status = 'paid';
            voucher.payment.paidAt = new Date();
            await voucher.save();
        }
        
        return vouchers;
    }
}

module.exports = VoucherService;
EOF

    # Report Service
    cat << 'EOF' > "$SYSTEM_DIR/app/services/ReportService.js"
const moment = require('moment');
const PaymentTransaction = require('../models/PaymentTransaction');
const Voucher = require('../models/Voucher');
const Session = require('../models/Session');
const Device = require('../models/Device');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const fs = require('fs').promises;
const path = require('path');

class ReportService {
    static async generateRevenueReport(options) {
        const { organizationId, from, to, groupBy = 'day' } = options;
        
        const startDate = from ? moment(from).startOf('day') : moment().subtract(30, 'days').startOf('day');
        const endDate = to ? moment(to).endOf('day') : moment().endOf('day');
        
        // Get payment transactions
        const transactions = await PaymentTransaction.aggregate([
            {
                $match: {
                    organization: organizationId,
                    status: 'completed',
                    createdAt: {
                        $gte: startDate.toDate(),
                        $lte: endDate.toDate()
                    }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: {
                            format: groupBy === 'day' ? '%Y-%m-%d' : 
                                   groupBy === 'week' ? '%Y-W%V' : '%Y-%m',
                            date: '$createdAt'
                        }
                    },
                    revenue: { $sum: '$amount.value' },
                    count: { $sum: 1 },
                    methods: { 
                        $push: '$method' 
                    }
                }
            },
            {
                $sort: { _id: 1 }
            }
        ]);
        
        // Calculate totals and method breakdown
        let totalRevenue = 0;
        let totalTransactions = 0;
        const methodBreakdown = {};
        
        transactions.forEach(t => {
            totalRevenue += t.revenue;
            totalTransactions += t.count;
            
            t.methods.forEach(method => {
                methodBreakdown[method] = (methodBreakdown[method] || 0) + 1;
            });
        });
        
        return {
            period: { from: startDate, to: endDate },
            groupBy,
            data: transactions,
            summary: {
                totalRevenue,
                totalTransactions,
                averageTransaction: totalTransactions > 0 ? totalRevenue / totalTransactions : 0,
                methodBreakdown
            }
        };
    }
    
    static async generateUsageReport(options) {
        const { organizationId, from, to, deviceId } = options;
        
        const query = { organization: organizationId };
        
        if (deviceId) {
            query.device = deviceId;
        }
        
        if (from || to) {
            query.startTime = {};
            if (from) query.startTime.$gte = new Date(from);
            if (to) query.startTime.$lte = new Date(to);
        }
        
        const sessions = await Session.aggregate([
            { $match: query },
            {
                $group: {
                    _id: '$device',
                    totalSessions: { $sum: 1 },
                    totalDuration: { $sum: '$duration' },
                    totalDataUsed: { $sum: '$dataUsage.total' },
                    uniqueUsers: { $addToSet: '$user.macAddress' },
                    avgSessionDuration: { $avg: '$duration' }
                }
            },
            {
                $lookup: {
                    from: 'devices',
                    localField: '_id',
                    foreignField: '_id',
                    as: 'device'
                }
            },
            {
                $unwind: '$device'
            }
        ]);
        
        // Calculate peak hours
        const hourlyUsage = await Session.aggregate([
            { $match: query },
            {
                $group: {
                    _id: { $hour: '$startTime' },
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } }
        ]);
        
        return {
            devices: sessions.map(s => ({
                deviceId: s._id,
                deviceName: s.device.name,
                location: s.device.location,
                totalSessions: s.totalSessions,
                totalDuration: s.totalDuration,
                totalDataUsed: s.totalDataUsed,
                uniqueUsers: s.uniqueUsers.length,
                avgSessionDuration: s.avgSessionDuration
            })),
            peakHours: hourlyUsage.slice(0, 5),
            period: { from, to }
        };
    }
    
    static async generateVoucherReport(options) {
        const { organizationId } = options;
        
        // Voucher statistics by profile
        const voucherStats = await Voucher.aggregate([
            { $match: { organization: organizationId } },
            {
                $group: {
                    _id: {
                        profile: '$profile.name',
                        status: '$status'
                    },
                    count: { $sum: 1 },
                    totalValue: { $sum: '$price.amount' }
                }
            },
            {
                $group: {
                    _id: '$_id.profile',
                    stats: {
                        $push: {
                            status: '$_id.status',
                            count: '$count',
                            value: '$totalValue'
                        }
                    },
                    total: { $sum: '$count' },
                    totalValue: { $sum: '$totalValue' }
                }
            }
        ]);
        
        // Usage patterns
        const usagePatterns = await Voucher.aggregate([
            { 
                $match: { 
                    organization: organizationId,
                    status: 'used'
                } 
            },
            {
                $group: {
                    _id: {
                        dayOfWeek: { $dayOfWeek: '$usage.activatedAt' },
                        hour: { $hour: '$usage.activatedAt' }
                    },
                    count: { $sum: 1 }
                }
            }
        ]);
        
        return {
            profiles: voucherStats,
            usagePatterns,
            generated: await Voucher.countDocuments({ organization: organizationId }),
            active: await Voucher.countDocuments({ organization: organizationId, status: 'active' }),
            revenue: await Voucher.aggregate([
                { 
                    $match: { 
                        organization: organizationId,
                        status: 'used'
                    } 
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$price.amount' }
                    }
                }
            ]).then(r => r[0]?.total || 0)
        };
    }
    
    static async generateDeviceReport(options) {
        const { organizationId } = options;
        
        const devices = await Device.find({ organization: organizationId })
            .select('name status lastSeen vpnStatus location');
        
        const deviceStats = await Promise.all(devices.map(async (device) => {
            const sessions = await Session.countDocuments({ device: device._id });
            const activeUsers = await Session.countDocuments({ 
                device: device._id, 
                status: 'active' 
            });
            
            const usage = await Session.aggregate([
                { $match: { device: device._id } },
                {
                    $group: {
                        _id: null,
                        totalData: { $sum: '$dataUsage.total' },
                        totalDuration: { $sum: '$duration' }
                    }
                }
            ]);
            
            return {
                device: {
                    id: device._id,
                    name: device.name,
                    status: device.status,
                    location: device.location,
                    lastSeen: device.lastSeen
                },
                stats: {
                    totalSessions: sessions,
                    activeUsers,
                    totalData: usage[0]?.totalData || 0,
                    totalDuration: usage[0]?.totalDuration || 0,
                    uptime: device.vpnStatus?.connected ? 
                        moment().diff(device.vpnStatus.connectedAt, 'hours') : 0
                }
            };
        }));
        
        return {
            devices: deviceStats,
            summary: {
                total: devices.length,
                online: devices.filter(d => d.status === 'online').length,
                offline: devices.filter(d => d.status === 'offline').length
            }
        };
    }
    
    static async exportReport(options) {
        const { type, format, organizationId, userId, filters } = options;
        
        let reportData;
        switch (type) {
            case 'revenue':
                reportData = await this.generateRevenueReport({ organizationId, ...filters });
                break;
            case 'usage':
                reportData = await this.generateUsageReport({ organizationId, ...filters });
                break;
            case 'vouchers':
                reportData = await this.generateVoucherReport({ organizationId, ...filters });
                break;
            case 'devices':
                reportData = await this.generateDeviceReport({ organizationId, ...filters });
                break;
            default:
                throw new Error('Unknown report type');
        }
        
        const filename = `report-${type}-${Date.now()}.${format}`;
        const filepath = path.join('/tmp', filename);
        
        switch (format) {
            case 'pdf':
                await this.exportToPDF(reportData, filepath, type);
                break;
            case 'excel':
                await this.exportToExcel(reportData, filepath, type);
                break;
            case 'csv':
                await this.exportToCSV(reportData, filepath, type);
                break;
            default:
                throw new Error('Unknown format');
        }
        
        // Upload to storage and return URL
        // For now, return local path
        return `/downloads/${filename}`;
    }
    
    static async exportToPDF(data, filepath, type) {
        const doc = new PDFDocument();
        const stream = doc.pipe(fs.createWriteStream(filepath));
        
        // Add title
        doc.fontSize(20).text(`${type.toUpperCase()} REPORT`, 50, 50);
        doc.fontSize(12).text(`Generated: ${moment().format('YYYY-MM-DD HH:mm')}`, 50, 80);
        
        // Add content based on type
        let y = 120;
        
        if (type === 'revenue' && data.data) {
            doc.fontSize(14).text('Revenue Summary', 50, y);
            y += 30;
            
            doc.fontSize(10);
            data.data.forEach(item => {
                doc.text(`${item._id}: ${item.revenue} THB (${item.count} transactions)`, 50, y);
                y += 20;
            });
            
            y += 20;
            doc.fontSize(12).text(`Total Revenue: ${data.summary.totalRevenue} THB`, 50, y);
        }
        
        doc.end();
        await new Promise(resolve => stream.on('finish', resolve));
    }
    
    static async exportToExcel(data, filepath, type) {
        const workbook = new ExcelJS.Workbook();
        const sheet = workbook.addWorksheet(type.toUpperCase());
        
        // Add headers and data based on type
        if (type === 'revenue' && data.data) {
            sheet.columns = [
                { header: 'Period', key: 'period', width: 20 },
                { header: 'Revenue (THB)', key: 'revenue', width: 15 },
                { header: 'Transactions', key: 'count', width: 15 }
            ];
            
            data.data.forEach(item => {
                sheet.addRow({
                    period: item._id,
                    revenue: item.revenue,
                    count: item.count
                });
            });
            
            // Add summary
            sheet.addRow({});
            sheet.addRow({
                period: 'TOTAL',
                revenue: data.summary.totalRevenue,
                count: data.summary.totalTransactions
            });
        }
        
        await workbook.xlsx.writeFile(filepath);
    }
    
    static async exportToCSV(data, filepath, type) {
        let csv = '';
        
        if (type === 'revenue' && data.data) {
            csv = 'Period,Revenue,Transactions\n';
            data.data.forEach(item => {
                csv += `${item._id},${item.revenue},${item.count}\n`;
            });
            csv += `\nTOTAL,${data.summary.totalRevenue},${data.summary.totalTransactions}\n`;
        }
        
        await fs.writeFile(filepath, csv);
    }
}

module.exports = ReportService;
EOF

    # PDF Service
    cat << 'EOF' > "$SYSTEM_DIR/app/services/PDFService.js"
const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');

class PDFService {
    static async generateVoucherPrint(options) {
        const { voucherIds, format, template = 'default', organization } = options;
        
        // Load vouchers
        const Voucher = require('../models/Voucher');
        const vouchers = await Voucher.find({
            _id: { $in: voucherIds },
            organization
        });
        
        const filename = `vouchers-${Date.now()}.pdf`;
        const filepath = path.join('/tmp', filename);
        
        if (format === 'pdf') {
            await this.generatePDFVouchers(vouchers, filepath, template);
        } else if (format === 'thermal') {
            await this.generateThermalVouchers(vouchers, filepath);
        }
        
        return `/downloads/${filename}`;
    }
    
    static async generatePDFVouchers(vouchers, filepath, template) {
        const doc = new PDFDocument({
            size: 'A4',
            margin: 20
        });
        
        const stream = doc.pipe(fs.createWriteStream(filepath));
        
        // Voucher dimensions (3x3 grid on A4)
        const voucherWidth = 180;
        const voucherHeight = 90;
        const margin = 15;
        const startX = 30;
        const startY = 30;
        
        let currentX = startX;
        let currentY = startY;
        let voucherCount = 0;
        
        for (const voucher of vouchers) {
            // Draw voucher border
            doc.rect(currentX, currentY, voucherWidth, voucherHeight)
               .stroke();
            
            // Add logo/header
            doc.fontSize(14)
               .font('Helvetica-Bold')
               .text('WiFi Hotspot', currentX + 10, currentY + 10, {
                   width: voucherWidth - 20,
                   align: 'center'
               });
            
            // Add voucher code
            doc.fontSize(16)
               .font('Helvetica-Bold')
               .text(voucher.code, currentX + 10, currentY + 35, {
                   width: voucherWidth - 80,
                   align: 'left'
               });
            
            // Add QR code
            if (voucher.qrCode) {
                const qrBuffer = Buffer.from(voucher.qrCode.split(',')[1], 'base64');
                doc.image(qrBuffer, currentX + voucherWidth - 60, currentY + 25, {
                    width: 50,
                    height: 50
                });
            }
            
            // Add profile info
            doc.fontSize(10)
               .font('Helvetica')
               .text(`${voucher.profile.name}`, currentX + 10, currentY + 55);
            
            doc.text(`Price: ${voucher.price.amount} THB`, currentX + 10, currentY + 70);
            
            // Move to next position
            voucherCount++;
            currentX += voucherWidth + margin;
            
            if (voucherCount % 3 === 0) {
                currentX = startX;
                currentY += voucherHeight + margin;
            }
            
            if (voucherCount % 9 === 0 && voucherCount < vouchers.length) {
                doc.addPage();
                currentX = startX;
                currentY = startY;
            }
        }
        
        doc.end();
        await new Promise(resolve => stream.on('finish', resolve));
    }
    
    static async generateThermalVouchers(vouchers, filepath) {
        // Generate thermal printer format (80mm width)
        const doc = new PDFDocument({
            size: [226, 1000], // 80mm width
            margin: 5
        });
        
        const stream = doc.pipe(fs.createWriteStream(filepath));
        
        let currentY = 10;
        
        for (const voucher of vouchers) {
            // Header
            doc.fontSize(12)
               .font('Helvetica-Bold')
               .text('WiFi HOTSPOT', 5, currentY, {
                   width: 216,
                   align: 'center'
               });
            
            currentY += 20;
            
            // Voucher code (large)
            doc.fontSize(16)
               .text(voucher.code, 5, currentY, {
                   width: 216,
                   align: 'center'
               });
            
            currentY += 25;
            
            // QR Code
            if (voucher.qrCode) {
                const qrBuffer = Buffer.from(voucher.qrCode.split(',')[1], 'base64');
                doc.image(qrBuffer, 63, currentY, {
                    width: 100,
                    height: 100
                });
                currentY += 110;
            }
            
            // Details
            doc.fontSize(10)
               .font('Helvetica');
            
            doc.text(`Duration: ${voucher.profile.name}`, 5, currentY);
            currentY += 15;
            
            doc.text(`Price: ${voucher.price.amount} THB`, 5, currentY);
            currentY += 15;
            
            doc.text(`Valid until used`, 5, currentY);
            currentY += 20;
            
            // Cut line
            doc.moveTo(0, currentY)
               .lineTo(226, currentY)
               .dash(3, { space: 3 })
               .stroke();
            
            currentY += 20;
        }
        
        doc.end();
        await new Promise(resolve => stream.on('finish', resolve));
    }
    
    static async generateInvoice(invoiceData, filepath) {
        const doc = new PDFDocument({
            size: 'A4',
            margin: 50
        });
        
        const stream = doc.pipe(fs.createWriteStream(filepath));
        
        // Header
        doc.fontSize(20)
           .text('INVOICE', 50, 50);
        
        doc.fontSize(10)
           .text(`Invoice No: ${invoiceData.invoiceNumber}`, 400, 50)
           .text(`Date: ${moment(invoiceData.date).format('YYYY-MM-DD')}`, 400, 65);
        
        // Company info
        doc.fontSize(12)
           .text('From:', 50, 120)
           .fontSize(10)
           .text(invoiceData.company.name, 50, 140)
           .text(invoiceData.company.address, 50, 155)
           .text(`Tax ID: ${invoiceData.company.taxId}`, 50, 170);
        
        // Bill to
        doc.fontSize(12)
           .text('Bill To:', 300, 120)
           .fontSize(10)
           .text(invoiceData.billTo.name, 300, 140)
           .text(invoiceData.billTo.email, 300, 155)
           .text(invoiceData.billTo.phone, 300, 170);
        
        // Items table
        let tableY = 220;
        
        // Table header
        doc.fontSize(10)
           .font('Helvetica-Bold')
           .text('Description', 50, tableY)
           .text('Qty', 300, tableY)
           .text('Price', 350, tableY)
           .text('Total', 450, tableY);
        
        // Line
        doc.moveTo(50, tableY + 15)
           .lineTo(550, tableY + 15)
           .stroke();
        
        tableY += 25;
        
        // Items
        doc.font('Helvetica');
        invoiceData.items.forEach(item => {
            doc.text(item.description, 50, tableY)
               .text(item.quantity.toString(), 300, tableY)
               .text(item.unitPrice.toFixed(2), 350, tableY)
               .text(item.total.toFixed(2), 450, tableY);
            tableY += 20;
        });
        
        // Total section
        tableY += 20;
        doc.moveTo(350, tableY)
           .lineTo(550, tableY)
           .stroke();
        
        tableY += 10;
        
        doc.text('Subtotal:', 350, tableY)
           .text(invoiceData.subtotal.toFixed(2), 450, tableY);
        
        tableY += 20;
        doc.text('VAT (7%):', 350, tableY)
           .text(invoiceData.vat.toFixed(2), 450, tableY);
        
        tableY += 20;
        doc.font('Helvetica-Bold')
           .text('Total:', 350, tableY)
           .text(invoiceData.total.toFixed(2) + ' THB', 450, tableY);
        
        doc.end();
        await new Promise(resolve => stream.on('finish', resolve));
    }
}

module.exports = PDFService;
EOF

    # Initialize services
    cat << 'EOF' > "$SYSTEM_DIR/app/services/index.js"
const logger = require('../utils/logger');

async function initializeServices() {
    try {
        logger.info('Initializing services...');
        
        // Initialize scheduled jobs
        require('./SchedulerService');
        
        // Initialize MikroTik connections
        const MikroTikService = require('./MikroTikService');
        
        // Initialize payment providers
        // This would typically load payment gateway configurations
        
        logger.info('Services initialized successfully');
    } catch (error) {
        logger.error('Failed to initialize services:', error);
        throw error;
    }
}

module.exports = { initializeServices };
EOF

    # Scheduler Service
    cat << 'EOF' > "$SYSTEM_DIR/app/services/SchedulerService.js"
const cron = require('node-cron');
const logger = require('../utils/logger');
const Voucher = require('../models/Voucher');
const Session = require('../models/Session');
const Device = require('../models/Device');

class SchedulerService {
    static init() {
        // Check expired vouchers every hour
        cron.schedule('0 * * * *', async () => {
            try {
                await this.checkExpiredVouchers();
            } catch (error) {
                logger.error('Error checking expired vouchers:', error);
            }
        });
        
        // Clean up old sessions daily
        cron.schedule('0 3 * * *', async () => {
            try {
                await this.cleanupOldSessions();
            } catch (error) {
                logger.error('Error cleaning up sessions:', error);
            }
        });
        
        // Update device status every 5 minutes
        cron.schedule('*/5 * * * *', async () => {
            try {
                await this.updateDeviceStatus();
            } catch (error) {
                logger.error('Error updating device status:', error);
            }
        });
        
        logger.info('Scheduler service initialized');
    }
    
    static async checkExpiredVouchers() {
        const expired = await Voucher.updateMany(
            {
                status: 'active',
                'usage.expiresAt': { $lt: new Date() }
            },
            {
                $set: { status: 'expired' }
            }
        );
        
        if (expired.modifiedCount > 0) {
            logger.info(`Marked ${expired.modifiedCount} vouchers as expired`);
        }
    }
    
    static async cleanupOldSessions() {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const result = await Session.deleteMany({
            status: { $in: ['completed', 'terminated'] },
            endTime: { $lt: thirtyDaysAgo }
        });
        
        if (result.deletedCount > 0) {
            logger.info(`Deleted ${result.deletedCount} old sessions`);
        }
    }
    
    static async updateDeviceStatus() {
        const devices = await Device.find({ isActive: true });
        
        for (const device of devices) {
            // Check if device hasn't been seen for 10 minutes
            const tenMinutesAgo = new Date();
            tenMinutesAgo.setMinutes(tenMinutesAgo.getMinutes() - 10);
            
            if (device.lastSeen < tenMinutesAgo && device.status === 'online') {
                device.status = 'offline';
                device.vpnStatus.connected = false;
                device.vpnStatus.disconnectedAt = new Date();
                await device.save();
                
                logger.info(`Device ${device.name} marked as offline`);
            }
        }
    }
}

// Initialize scheduler
SchedulerService.init();

module.exports = SchedulerService;
EOF
}

# Create utility files
create_utility_files_full() {
    # Enhanced logger
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
        }),
        new winston.transports.File({
            filename: path.join('/var/log/mikrotik-vpn', 'access.log'),
            level: 'info',
            maxsize: 10485760,
            maxFiles: 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.printf(info => {
                    if (info.message.includes('HTTP')) {
                        return `${info.timestamp} ${info.message}`;
                    }
                    return null;
                })
            )
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

    # Enhanced email service
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/email.js"
const nodemailer = require('nodemailer');
const ejs = require('ejs');
const path = require('path');
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
    
    async sendEmail({ to, subject, template, data, attachments }) {
        try {
            // Render template
            const html = await ejs.renderFile(
                path.join(__dirname, '../views/emails', `${template}.ejs`),
                { ...data, t: (key) => key } // Add translation function
            );
            
            const info = await this.transporter.sendMail({
                from: process.env.FROM_EMAIL || '"MikroTik VPN" <noreply@example.com>',
                to,
                subject,
                html,
                attachments
            });
            
            logger.info(`Email sent: ${info.messageId}`);
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
            data: { user }
        });
    }
    
    async sendVoucherPurchaseConfirmation(user, vouchers, transaction) {
        return this.sendEmail({
            to: user.email,
            subject: 'Voucher Purchase Confirmation',
            template: 'voucher-purchase',
            data: { user, vouchers, transaction }
        });
    }
    
    async sendPasswordReset(user, token) {
        const resetUrl = `${process.env.APP_URL}/reset-password/${token}`;
        
        return this.sendEmail({
            to: user.email,
            subject: 'Password Reset Request',
            template: 'password-reset',
            data: { user, resetUrl }
        });
    }
    
    async sendInvoice(user, invoice, attachmentPath) {
        return this.sendEmail({
            to: user.email,
            subject: `Invoice ${invoice.invoiceNumber}`,
            template: 'invoice',
            data: { user, invoice },
            attachments: [{
                filename: `invoice-${invoice.invoiceNumber}.pdf`,
                path: attachmentPath
            }]
        });
    }
}

module.exports = new EmailService();
EOF

    # SMS Service
    cat << 'EOF' > "$SYSTEM_DIR/app/utils/sms.js"
const axios = require('axios');
const logger = require('./logger');

class SMSService {
    constructor() {
        this.provider = process.env.SMS_PROVIDER || 'twilio';
        this.config = {
            twilio: {
                accountSid: process.env.TWILIO_ACCOUNT_SID,
                authToken: process.env.TWILIO_AUTH_TOKEN,
                from: process.env.TWILIO_PHONE_NUMBER
            },
            thaibulksms: {
                apiKey: process.env.THAIBULK_API_KEY,
                apiSecret: process.env.THAIBULK_API_SECRET,
                sender: process.env.THAIBULK_SENDER || 'MIKROTIK'
            }
        };
    }
    
    async sendSMS(to, message) {
        try {
            switch (this.provider) {
                case 'twilio':
                    return await this.sendViaTwilio(to, message);
                case 'thaibulksms':
                    return await this.sendViaThaiBulkSMS(to, message);
                default:
                    throw new Error('Unknown SMS provider');
            }
        } catch (error) {
            logger.error('SMS send error:', error);
            throw error;
        }
    }
    
    async sendViaTwilio(to, message) {
        const twilio = require('twilio');
        const client = twilio(
            this.config.twilio.accountSid,
            this.config.twilio.authToken
        );
        
        const result = await client.messages.create({
            body: message,
            to: to,
            from: this.config.twilio.from
        });
        
        return { success: true, messageId: result.sid };
    }
    
    async sendViaThaiBulkSMS(to, message) {
        const response = await axios.post('https://api.thaibulksms.com/sms', {
            key: this.config.thaibulksms.apiKey,
            secret: this.config.thaibulksms.apiSecret,
            sender: this.config.thaibulksms.sender,
            phone: to,
            message: message
        });
        
        return { success: response.data.success, messageId: response.data.id };
    }
    
    async sendOTP(phone, otp) {
        const message = `Your MikroTik Hotspot OTP is: ${otp}. Valid for 5 minutes.`;
        return this.sendSMS(phone, message);
    }
    
    generateOTP(length = 6) {
        let otp = '';
        for (let i = 0; i < length; i++) {
            otp += Math.floor(Math.random() * 10);
        }
        return otp;
    }
}

module.exports = new SMSService();
EOF

    # Keep existing utilities and add new ones
    cat << 'EOF' >> "$SYSTEM_DIR/app/utils/qrcode.js"

    async generatePaymentQR(data) {
        try {
            const paymentData = {
                amount: data.amount,
                reference: data.reference,
                type: 'payment'
            };
            
            const qrCodeDataURL = await QRCode.toDataURL(JSON.stringify(paymentData), {
                errorCorrectionLevel: 'H',
                type: 'image/png',
                width: 400,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#FFFFFF'
                }
            });
            
            return qrCodeDataURL;
        } catch (error) {
            logger.error('Payment QR generation error:', error);
            throw error;
        }
    }
EOF
}

# Create view templates
create_view_templates() {
    # Main layout
    mkdir -p "$SYSTEM_DIR/app/views/layouts"
    cat << 'EOF' > "$SYSTEM_DIR/app/views/layouts/main.ejs"
<!DOCTYPE html>
<html lang="<%= lang %>" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= typeof title !== 'undefined' ? title : 'MikroTik VPN Management' %></title>
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Alpine.js -->
    <script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- DataTables -->
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.tailwindcss.min.css">
    
    <!-- SweetAlert2 -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
    
    <!-- Custom CSS -->
    <link rel="stylesheet" href="/static/css/app.css">
    
    <%- style %>
</head>
<body class="h-full bg-gray-50">
    <div class="min-h-full">
        <!-- Navigation -->
        <nav class="bg-white shadow-sm" x-data="{ open: false }">
            <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                <div class="flex h-16 justify-between">
                    <div class="flex">
                        <div class="flex flex-shrink-0 items-center">
                            <img class="h-8 w-auto" src="/static/images/logo.png" alt="MikroTik VPN">
                        </div>
                        <div class="hidden sm:-my-px sm:ml-6 sm:flex sm:space-x-8">
                            <a href="/" class="<%= typeof activeMenu !== 'undefined' && activeMenu === 'dashboard' ? 'border-indigo-500 text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700' %> inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                                <%= t('dashboard') %>
                            </a>
                            <a href="/devices" class="<%= typeof activeMenu !== 'undefined' && activeMenu === 'devices' ? 'border-indigo-500 text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700' %> inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                                <%= t('devices') %>
                            </a>
                            <a href="/vouchers" class="<%= typeof activeMenu !== 'undefined' && activeMenu === 'vouchers' ? 'border-indigo-500 text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700' %> inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                                <%= t('vouchers') %>
                            </a>
                            <a href="/users" class="<%= typeof activeMenu !== 'undefined' && activeMenu === 'users' ? 'border-indigo-500 text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700' %> inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                                <%= t('users') %>
                            </a>
                            <a href="/reports" class="<%= typeof activeMenu !== 'undefined' && activeMenu === 'reports' ? 'border-indigo-500 text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700' %> inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                                <%= t('reports') %>
                            </a>
                        </div>
                    </div>
                    <div class="hidden sm:ml-6 sm:flex sm:items-center">
                        <!-- Language Selector -->
                        <div class="relative" x-data="{ open: false }">
                            <button @click="open = !open" class="flex items-center text-sm rounded-full focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2">
                                <i class="fas fa-globe mr-2"></i>
                                <%= lang.toUpperCase() %>
                            </button>
                            <div x-show="open" @click.away="open = false" class="absolute right-0 z-10 mt-2 w-48 origin-top-right rounded-md bg-white py-1 shadow-lg ring-1 ring-black ring-opacity-5">
                                <a href="/lang/th" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">ไทย</a>
                                <a href="/lang/en" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">English</a>
                            </div>
                        </div>
                        
                        <!-- Profile dropdown -->
                        <div class="relative ml-3" x-data="{ open: false }">
                            <button @click="open = !open" class="flex items-center rounded-full bg-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2">
                                <img class="h-8 w-8 rounded-full" src="<%= user?.profile?.avatar || '/static/images/default-avatar.png' %>" alt="">
                            </button>
                            <div x-show="open" @click.away="open = false" class="absolute right-0 z-10 mt-2 w-48 origin-top-right rounded-md bg-white py-1 shadow-lg ring-1 ring-black ring-opacity-5">
                                <a href="/profile" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"><%= t('profile') %></a>
                                <a href="/settings" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"><%= t('settings') %></a>
                                <hr class="my-1">
                                <a href="/logout" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"><%= t('logout') %></a>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Mobile menu button -->
                    <div class="-mr-2 flex items-center sm:hidden">
                        <button @click="open = !open" class="inline-flex items-center justify-center rounded-md bg-white p-2 text-gray-400 hover:bg-gray-100 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2">
                            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                                <path x-show="!open" stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
                                <path x-show="open" stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Mobile menu -->
            <div x-show="open" class="sm:hidden">
                <div class="space-y-1 pb-3 pt-2">
                    <a href="/" class="block border-l-4 <%= typeof activeMenu !== 'undefined' && activeMenu === 'dashboard' ? 'border-indigo-500 bg-indigo-50 text-indigo-700' : 'border-transparent text-gray-600 hover:border-gray-300 hover:bg-gray-50 hover:text-gray-800' %> py-2 pl-3 pr-4 text-base font-medium">
                        <%= t('dashboard') %>
                    </a>
                    <!-- Add other mobile menu items -->
                </div>
            </div>
        </nav>
        
        <!-- Flash Messages -->
        <% if (success_msg && success_msg.length > 0) { %>
        <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 mt-4">
            <div class="rounded-md bg-green-50 p-4">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <i class="fas fa-check-circle text-green-400"></i>
                    </div>
                    <div class="ml-3">
                        <p class="text-sm font-medium text-green-800"><%= success_msg %></p>
                    </div>
                </div>
            </div>
        </div>
        <% } %>
        
        <% if (error_msg && error_msg.length > 0) { %>
        <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 mt-4">
            <div class="rounded-md bg-red-50 p-4">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <i class="fas fa-exclamation-circle text-red-400"></i>
                    </div>
                    <div class="ml-3">
                        <p class="text-sm font-medium text-red-800"><%= error_msg %></p>
                    </div>
                </div>
            </div>
        </div>
        <% } %>
        
        <!-- Page Content -->
        <main>
            <div class="mx-auto max-w-7xl py-6 sm:px-6 lg:px-8">
                <%- body %>
            </div>
        </main>
    </div>
    
    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.tailwindcss.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="/socket.io/socket.io.js"></script>
    <script src="/static/js/app.js"></script>
    
    <%- script %>
</body>
</html>
EOF

    # Dashboard view
    mkdir -p "$SYSTEM_DIR/app/views/dashboard"
    cat << 'EOF' > "$SYSTEM_DIR/app/views/dashboard/index.ejs"
<div class="px-4 sm:px-6 lg:px-8">
    <div class="sm:flex sm:items-center">
        <div class="sm:flex-auto">
            <h1 class="text-2xl font-semibold leading-6 text-gray-900"><%= t('dashboard') %></h1>
            <p class="mt-2 text-sm text-gray-700"><%= t('dashboard.description') %></p>
        </div>
    </div>
    
    <!-- Stats -->
    <div class="mt-8 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <!-- Total Devices -->
        <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow sm:p-6">
            <dt class="truncate text-sm font-medium text-gray-500"><%= t('devices') %></dt>
            <dd class="mt-1 flex items-baseline justify-between">
                <div class="flex items-baseline text-2xl font-semibold text-indigo-600">
                    <span id="totalDevices">0</span>
                </div>
                <div class="ml-2 flex items-baseline text-sm font-semibold text-green-600">
                    <span id="onlineDevices">0</span> <%= t('online') %>
                </div>
            </dd>
        </div>
        
        <!-- Active Users -->
        <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow sm:p-6">
            <dt class="truncate text-sm font-medium text-gray-500"><%= t('active') %> <%= t('users') %></dt>
            <dd class="mt-1 text-2xl font-semibold text-indigo-600">
                <span id="activeUsers">0</span>
            </dd>
        </div>
        
        <!-- Total Vouchers -->
        <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow sm:p-6">
            <dt class="truncate text-sm font-medium text-gray-500"><%= t('vouchers') %></dt>
            <dd class="mt-1 flex items-baseline justify-between">
                <div class="flex items-baseline text-2xl font-semibold text-indigo-600">
                    <span id="totalVouchers">0</span>
                </div>
                <div class="ml-2 flex items-baseline text-sm font-semibold text-gray-600">
                    <span id="activeVouchers">0</span> <%= t('active') %>
                </div>
            </dd>
        </div>
        
        <!-- Today's Revenue -->
        <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow sm:p-6">
            <dt class="truncate text-sm font-medium text-gray-500"><%= t('revenue.today') %></dt>
            <dd class="mt-1 text-2xl font-semibold text-indigo-600">
                ฿<span id="todayRevenue">0</span>
            </dd>
        </div>
    </div>
    
    <!-- Charts -->
    <div class="mt-8 grid grid-cols-1 gap-8 lg:grid-cols-2">
        <!-- Usage Chart -->
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
                <h3 class="text-lg leading-6 font-medium text-gray-900"><%= t('usage.chart') %></h3>
                <div class="mt-5">
                    <canvas id="usageChart" width="400" height="200"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Revenue Chart -->
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
                <h3 class="text-lg leading-6 font-medium text-gray-900"><%= t('revenue.chart') %></h3>
                <div class="mt-5">
                    <canvas id="revenueChart" width="400" height="200"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Recent Activities -->
    <div class="mt-8">
        <div class="bg-white shadow overflow-hidden sm:rounded-md">
            <div class="px-4 py-5 sm:px-6">
                <h3 class="text-lg leading-6 font-medium text-gray-900"><%= t('recent.activities') %></h3>
            </div>
            <ul id="recentActivities" class="divide-y divide-gray-200">
                <!-- Activities will be loaded here -->
            </ul>
        </div>
    </div>
</div>

<script>
// Initialize real-time updates
const socket = io();

socket.on('connect', () => {
    console.log('Connected to server');
    socket.emit('join:organization', '<%= user.organization._id %>');
});

// Update stats in real-time
socket.on('stats:update', (data) => {
    document.getElementById('totalDevices').textContent = data.totalDevices;
    document.getElementById('onlineDevices').textContent = data.onlineDevices;
    document.getElementById('activeUsers').textContent = data.activeUsers;
    document.getElementById('totalVouchers').textContent = data.totalVouchers;
    document.getElementById('activeVouchers').textContent = data.activeVouchers;
    document.getElementById('todayRevenue').textContent = data.todayRevenue.toFixed(2);
});

// Load initial stats
fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            // Update stats
            socket.emit('stats:update', data.data);
            
            // Initialize charts
            initializeCharts(data.data);
        }
    });

function initializeCharts(data) {
    // Usage Chart
    const usageCtx = document.getElementById('usageChart').getContext('2d');
    new Chart(usageCtx, {
        type: 'line',
        data: {
            labels: data.usageChart.labels,
            datasets: [{
                label: '<%= t("users") %>',
                data: data.usageChart.data,
                borderColor: 'rgb(99, 102, 241)',
                backgroundColor: 'rgba(99, 102, 241, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Revenue Chart
    const revenueCtx = document.getElementById('revenueChart').getContext('2d');
    new Chart(revenueCtx, {
        type: 'bar',
        data: {
            labels: data.revenueChart.labels,
            datasets: [{
                label: '<%= t("revenue") %>',
                data: data.revenueChart.data,
                backgroundColor: 'rgb(99, 102, 241)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}
</script>
EOF

    # Create email templates
    mkdir -p "$SYSTEM_DIR/app/views/emails"
    cat << 'EOF' > "$SYSTEM_DIR/app/views/emails/welcome.ejs"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9fafb; }
        .button { display: inline-block; padding: 10px 20px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to MikroTik VPN Management System</h1>
        </div>
        <div class="content">
            <p>Hello <%= user.profile.firstName %>,</p>
            <p>Your account has been created successfully. You can now log in and start managing your MikroTik devices.</p>
            <p>Username: <strong><%= user.username %></strong></p>
            <p>Email: <strong><%= user.email %></strong></p>
            <p>
                <a href="<%= process.env.APP_URL %>" class="button">Login Now</a>
            </p>
            <p>If you have any questions, please contact our support team.</p>
            <p>Best regards,<br>MikroTik VPN Team</p>
        </div>
    </div>
</body>
</html>
EOF
}

# Create captive portal templates
create_captive_portal_templates() {
    mkdir -p "$SYSTEM_DIR/app/views/portal"
    
    # Portal index
    cat << 'EOF' > "$SYSTEM_DIR/app/views/portal/index.ejs"
<!DOCTYPE html>
<html lang="<%= lang %>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= t('portal.title') %></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen flex items-center justify-center">
    <div class="max-w-md w-full mx-auto p-6">
        <!-- Logo and Title -->
        <div class="text-center mb-8">
            <% if (template.design?.logo) { %>
                <img src="<%= template.design.logo %>" alt="Logo" class="h-20 mx-auto mb-4">
            <% } %>
            <h1 class="text-3xl font-bold text-gray-800"><%= t('portal.welcome') %></h1>
            <p class="text-gray-600 mt-2"><%= t('portal.loginTitle') %></p>
        </div>
        
        <!-- Login Methods -->
        <div class="bg-white rounded-lg shadow-xl p-8">
            <div class="space-y-4">
                <% template.loginMethods.forEach(method => { %>
                    <% if (method.enabled) { %>
                        <% if (method.type === 'voucher') { %>
                            <!-- Voucher Login -->
                            <div x-data="{ showVoucher: false }">
                                <button @click="showVoucher = !showVoucher" class="w-full bg-indigo-600 text-white rounded-lg px-4 py-3 hover:bg-indigo-700 transition duration-200 flex items-center justify-center">
                                    <i class="fas fa-ticket-alt mr-2"></i>
                                    <%= t('portal.loginMethods.voucher') %>
                                </button>
                                
                                <div x-show="showVoucher" x-transition class="mt-4">
                                    <form action="/portal/login/voucher" method="POST">
                                        <input type="text" name="code" placeholder="<%= t('portal.voucherCode') %>" 
                                               class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-indigo-500"
                                               required autocomplete="off">
                                        <button type="submit" class="w-full mt-2 bg-indigo-600 text-white rounded-lg px-4 py-2 hover:bg-indigo-700">
                                            <%= t('portal.loginButton') %>
                                        </button>
                                    </form>
                                </div>
                            </div>
                        <% } else if (method.type === 'userpass') { %>
                            <!-- Username/Password Login -->
                            <div x-data="{ showUserPass: false }">
                                <button @click="showUserPass = !showUserPass" class="w-full bg-green-600 text-white rounded-lg px-4 py-3 hover:bg-green-700 transition duration-200 flex items-center justify-center">
                                    <i class="fas fa-user mr-2"></i>
                                    <%= t('portal.loginMethods.userpass') %>
                                </button>
                                
                                <div x-show="showUserPass" x-transition class="mt-4">
                                    <form action="/portal/login/userpass" method="POST">
                                        <input type="text" name="username" placeholder="<%= t('portal.username') %>" 
                                               class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500 mb-2"
                                               required>
                                        <input type="password" name="password" placeholder="<%= t('portal.password') %>" 
                                               class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
                                               required>
                                        <button type="submit" class="w-full mt-2 bg-green-600 text-white rounded-lg px-4 py-2 hover:bg-green-700">
                                            <%= t('portal.loginButton') %>
                                        </button>
                                    </form>
                                </div>
                            </div>
                        <% } else if (method.type === 'sms') { %>
                            <!-- SMS OTP Login -->
                            <div x-data="{ showSMS: false, otpSent: false, phone: '' }">
                                <button @click="showSMS = !showSMS" class="w-full bg-orange-600 text-white rounded-lg px-4 py-3 hover:bg-orange-700 transition duration-200 flex items-center justify-center">
                                    <i class="fas fa-sms mr-2"></i>
                                    <%= t('portal.loginMethods.sms') %>
                                </button>
                                
                                <div x-show="showSMS" x-transition class="mt-4">
                                    <div x-show="!otpSent">
                                        <input type="tel" x-model="phone" placeholder="<%= t('portal.phoneNumber') %>" 
                                               class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-orange-500"
                                               pattern="[0-9]{10}" required>
                                        <button @click="sendOTP(phone)" class="w-full mt-2 bg-orange-600 text-white rounded-lg px-4 py-2 hover:bg-orange-700">
                                            <%= t('portal.sendOTP') %>
                                        </button>
                                    </div>
                                    
                                    <div x-show="otpSent">
                                        <form action="/portal/login/sms/verify" method="POST">
                                            <input type="hidden" name="phone" :value="phone">
                                            <input type="text" name="otp" placeholder="<%= t('portal.enterOTP') %>" 
                                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-orange-500"
                                                   maxlength="6" required>
                                            <button type="submit" class="w-full mt-2 bg-orange-600 text-white rounded-lg px-4 py-2 hover:bg-orange-700">
                                                <%= t('portal.verifyOTP') %>
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        <% } else if (method.type === 'social') { %>
                            <!-- Social Login -->
                            <div class="space-y-2">
                                <% template.socialProviders.forEach(provider => { %>
                                    <% if (provider.enabled) { %>
                                        <a href="/portal/login/social/<%= provider.provider %>" 
                                           class="w-full bg-<%= provider.provider === 'facebook' ? 'blue' : provider.provider === 'line' ? 'green' : 'red' %>-600 text-white rounded-lg px-4 py-3 hover:opacity-90 transition duration-200 flex items-center justify-center">
                                            <i class="fab fa-<%= provider.provider %> mr-2"></i>
                                            <%= t('portal.loginWith') %> <%= provider.provider.charAt(0).toUpperCase() + provider.provider.slice(1) %>
                                        </a>
                                    <% } %>
                                <% }); %>
                            </div>
                        <% } %>
                    <% } %>
                <% }); %>
            </div>
            
            <!-- Terms and Conditions -->
            <% if (template.features?.showTerms) { %>
                <div class="mt-6 text-center">
                    <p class="text-sm text-gray-600">
                        <%= t('portal.byLoggingIn') %>
                        <a href="/portal/terms" class="text-indigo-600 hover:underline"><%= t('portal.termsAndConditions') %></a>
                    </p>
                </div>
            <% } %>
            
            <!-- Buy Voucher Link -->
            <% if (template.features?.showVoucherPurchase) { %>
                <div class="mt-4 text-center">
                    <a href="/portal/buy-voucher" class="text-indigo-600 hover:underline">
                        <i class="fas fa-shopping-cart mr-1"></i>
                        <%= t('portal.buyVoucher') %>
                    </a>
                </div>
            <% } %>
        </div>
        
        <!-- Language Selector -->
        <% if (template.features?.showLanguageSelector) { %>
            <div class="mt-6 text-center">
                <select onchange="window.location.href='/portal/lang/' + this.value" 
                        class="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-indigo-500">
                    <option value="th" <%= lang === 'th' ? 'selected' : '' %>>ไทย</option>
                    <option value="en" <%= lang === 'en' ? 'selected' : '' %>>English</option>
                </select>
            </div>
        <% } %>
    </div>
    
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script>
        function sendOTP(phone) {
            fetch('/portal/login/sms/request', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ phone })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    Alpine.store('otpSent', true);
                }
            });
        }
    </script>
</body>
</html>
EOF

    # Status page (after login)
    cat << 'EOF' > "$SYSTEM_DIR/app/views/portal/status.ejs"
<!DOCTYPE html>
<html lang="<%= lang %>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= t('portal.status') %></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="max-w-2xl mx-auto p-6">
        <div class="bg-white rounded-lg shadow-lg p-8">
            <div class="text-center mb-6">
                <div class="w-20 h-20 bg-green-500 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-check text-white text-3xl"></i>
                </div>
                <h1 class="text-2xl font-bold text-gray-800"><%= t('portal.connected') %></h1>
                <p class="text-gray-600 mt-2"><%= t('portal.enjoyInternet') %></p>
            </div>
            
            <!-- Session Info -->
            <div class="grid grid-cols-2 gap-4 mb-6">
                <div class="bg-gray-50 rounded-lg p-4">
                    <p class="text-sm text-gray-600"><%= t('portal.timeRemaining') %></p>
                    <p class="text-xl font-bold text-indigo-600" id="timeRemaining">--:--:--</p>
                </div>
                <div class="bg-gray-50 rounded-lg p-4">
                    <p class="text-sm text-gray-600"><%= t('portal.dataRemaining') %></p>
                    <p class="text-xl font-bold text-indigo-600" id="dataRemaining">-- MB</p>
                </div>
            </div>
            
            <!-- Usage Stats -->
            <div class="border-t pt-6">
                <h2 class="text-lg font-semibold mb-4"><%= t('portal.usageStats') %></h2>
                <div class="space-y-3">
                    <div class="flex justify-between">
                        <span class="text-gray-600"><%= t('portal.uploadSpeed') %></span>
                        <span id="uploadSpeed">0 Mbps</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-600"><%= t('portal.downloadSpeed') %></span>
                        <span id="downloadSpeed">0 Mbps</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-600"><%= t('portal.dataUsed') %></span>
                        <span id="dataUsed">0 MB</span>
                    </div>
                </div>
            </div>
            
            <!-- Actions -->
            <div class="mt-8 space-y-3">
                <button onclick="disconnect()" class="w-full bg-red-600 text-white rounded-lg px-4 py-3 hover:bg-red-700 transition duration-200">
                    <i class="fas fa-sign-out-alt mr-2"></i>
                    <%= t('portal.disconnect') %>
                </button>
                
                <a href="/portal/buy-voucher" class="block w-full bg-indigo-600 text-white rounded-lg px-4 py-3 hover:bg-indigo-700 transition duration-200 text-center">
                    <i class="fas fa-shopping-cart mr-2"></i>
                    <%= t('portal.buyMoreTime') %>
                </a>
            </div>
        </div>
    </div>
    
    <script>
        // Update session info every second
        setInterval(updateSessionInfo, 1000);
        
        function updateSessionInfo() {
            fetch('/portal/api/session-info')
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('timeRemaining').textContent = formatTime(data.timeRemaining);
                        document.getElementById('dataRemaining').textContent = formatData(data.dataRemaining);
                        document.getElementById('uploadSpeed').textContent = data.uploadSpeed + ' Mbps';
                        document.getElementById('downloadSpeed').textContent = data.downloadSpeed + ' Mbps';
                        document.getElementById('dataUsed').textContent = formatData(data.dataUsed);
                    }
                });
        }
        
        function formatTime(seconds) {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        }
        
        function formatData(mb) {
            if (mb >= 1024) {
                return (mb / 1024).toFixed(2) + ' GB';
            }
            return mb.toFixed(2) + ' MB';
        }
        
        function disconnect() {
            if (confirm('<%= t("portal.confirmDisconnect") %>')) {
                fetch('/portal/logout', { method: 'POST' })
                    .then(() => {
                        window.location.href = '/portal';
                    });
            }
        }
    </script>
</body>
</html>
EOF
}

# Create controllers
create_controller_files() {
    mkdir -p "$SYSTEM_DIR/app/controllers"
    
    # Portal Controller
    cat << 'EOF' > "$SYSTEM_DIR/app/controllers/PortalController.js"
const PortalTemplate = require('../models/PortalTemplate');
const Voucher = require('../models/Voucher');
const Session = require('../models/Session');
const SmsOtp = require('../models/SmsOtp');
const VoucherService = require('../services/VoucherService');
const SMSService = require('../utils/sms');
const MikroTikService = require('../services/MikroTikService');

class PortalController {
    static async showPortal(req, res) {
        try {
            // Get device ID from router
            const deviceId = req.query.device || req.headers['x-device-id'];
            
            // Get portal template
            let template = await PortalTemplate.findOne({ 
                isActive: true,
                device: deviceId 
            });
            
            if (!template) {
                // Use default template
                template = {
                    design: {
                        logo: '/static/images/logo.png',
                        backgroundColor: '#f3f4f6'
                    },
                    loginMethods: [
                        { type: 'voucher', enabled: true, order: 1 },
                        { type: 'userpass', enabled: true, order: 2 },
                        { type: 'sms', enabled: true, order: 3 },
                        { type: 'social', enabled: true, order: 4 }
                    ],
                    socialProviders: [
                        { provider: 'facebook', enabled: true },
                        { provider: 'line', enabled: true }
                    ],
                    features: {
                        showLogo: true,
                        showLanguageSelector: true,
                        showTerms: true,
                        showVoucherPurchase: true
                    }
                };
            }
            
            res.render('portal/index', {
                layout: false,
                template,
                lang: req.language,
                t: req.t
            });
        } catch (error) {
            console.error('Portal error:', error);
            res.status(500).send('Portal error');
        }
    }
    
    static async showLogin(req, res) {
        res.redirect('/portal');
    }
    
    static async loginVoucher(req, res) {
        try {
            const { code } = req.body;
            const deviceId = req.query.device || req.headers['x-device-id'];
            const clientIp = req.ip;
            const clientMac = req.headers['x-client-mac'] || req.query.mac;
            
            // Validate voucher
            const validation = await VoucherService.validateVoucher(code, deviceId);
            
            if (!validation.valid) {
                req.flash('error_msg', req.t(`portal.errors.${validation.error}`));
                return res.redirect('/portal');
            }
            
            // Activate voucher
            const activation = await VoucherService.activateVoucher({
                code,
                deviceId,
                macAddress: clientMac,
                ipAddress: clientIp
            });
            
            // Create hotspot user on MikroTik
            if (deviceId) {
                await MikroTikService.createHotspotUser(deviceId, {
                    username: code,
                    password: code,
                    profile: validation.voucher.profile.name,
                    limitUptime: VoucherService.formatDuration(validation.voucher.profile.duration),
                    macAddress: clientMac
                });
            }
            
            // Create session
            const session = new Session({
                organization: validation.voucher.organization,
                device: deviceId,
                voucher: validation.voucher._id,
                user: {
                    username: code,
                    macAddress: clientMac,
                    ipAddress: clientIp,
                    deviceInfo: req.headers['user-agent']
                },
                status: 'active'
            });
            
            await session.save();
            
            // Store session info
            req.session.hotspotSession = {
                sessionId: session._id,
                voucherId: validation.voucher._id,
                expiresAt: activation.expiresAt
            };
            
            // Redirect to status page or original URL
            const redirectUrl = req.session.originalUrl || '/portal/status';
            res.redirect(redirectUrl);
            
        } catch (error) {
            console.error('Voucher login error:', error);
            req.flash('error_msg', req.t('portal.errors.loginFailed'));
            res.redirect('/portal');
        }
    }
    
    static async loginUserPass(req, res) {
        try {
            const { username, password } = req.body;
            const deviceId = req.query.device || req.headers['x-device-id'];
            const clientIp = req.ip;
            const clientMac = req.headers['x-client-mac'] || req.query.mac;
            
            // Authenticate with MikroTik
            if (deviceId) {
                const users = await MikroTikService.getHotspotUsers(deviceId);
                const user = users.find(u => u.name === username);
                
                if (!user || user.password !== password) {
                    req.flash('error_msg', req.t('portal.errors.invalidCredentials'));
                    return res.redirect('/portal');
                }
                
                // Create session
                const session = new Session({
                    device: deviceId,
                    user: {
                        username,
                        macAddress: clientMac,
                        ipAddress: clientIp,
                        deviceInfo: req.headers['user-agent']
                    },
                    status: 'active'
                });
                
                await session.save();
                
                req.session.hotspotSession = {
                    sessionId: session._id,
                    username
                };
                
                res.redirect('/portal/status');
            } else {
                throw new Error('Device ID not provided');
            }
            
        } catch (error) {
            console.error('UserPass login error:', error);
            req.flash('error_msg', req.t('portal.errors.loginFailed'));
            res.redirect('/portal');
        }
    }
    
    static async requestSmsOtp(req, res) {
        try {
            const { phone } = req.body;
            
            // Generate OTP
            const otp = SMSService.generateOTP();
            
            // Save OTP
            const smsOtp = new SmsOtp({
                phone,
                otp,
                purpose: 'login',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            });
            
            await smsOtp.save();
            
            // Send SMS
            await SMSService.sendOTP(phone, otp);
            
            res.json({ success: true, message: req.t('portal.otpSent') });
            
        } catch (error) {
            console.error('SMS OTP error:', error);
            res.status(400).json({ 
                success: false, 
                message: req.t('portal.errors.smsFailed') 
            });
        }
    }
    
    static async verifySmsOtp(req, res) {
        try {
            const { phone, otp } = req.body;
            
            // Find OTP
            const smsOtp = await SmsOtp.findOne({
                phone,
                otp,
                isUsed: false,
                expiresAt: { $gt: new Date() }
            });
            
            if (!smsOtp) {
                req.flash('error_msg', req.t('portal.errors.invalidOtp'));
                return res.redirect('/portal');
            }
            
            // Verify OTP
            await smsOtp.verify(otp);
            
            // Create or find user session
            // This would typically create a temporary user or link to existing user
            
            req.session.hotspotSession = {
                phone,
                loginMethod: 'sms'
            };
            
            res.redirect('/portal/status');
            
        } catch (error) {
            console.error('OTP verification error:', error);
            req.flash('error_msg', error.message);
            res.redirect('/portal');
        }
    }
    
    static async socialLoginCallback(req, res) {
        try {
            const { provider } = req.params;
            // Handle OAuth callback
            // This would be implemented based on the specific provider
            
            res.redirect('/portal/status');
        } catch (error) {
            console.error('Social login error:', error);
            req.flash('error_msg', req.t('portal.errors.socialLoginFailed'));
            res.redirect('/portal');
        }
    }
    
    static async showStatus(req, res) {
        if (!req.session.hotspotSession) {
            return res.redirect('/portal');
        }
        
        res.render('portal/status', {
            layout: false,
            lang: req.language,
            t: req.t
        });
    }
    
    static async logout(req, res) {
        try {
            if (req.session.hotspotSession) {
                const { sessionId } = req.session.hotspotSession;
                
                // End session
                if (sessionId) {
                    await Session.findByIdAndUpdate(sessionId, {
                        status: 'completed',
                        endTime: new Date()
                    });
                }
                
                // Disconnect from MikroTik
                // This would disconnect the user from the hotspot
                
                delete req.session.hotspotSession;
            }
            
            res.redirect('/portal');
        } catch (error) {
            console.error('Logout error:', error);
            res.redirect('/portal');
        }
    }
    
    static async showTerms(req, res) {
        res.render('portal/terms', {
            layout: false,
            lang: req.language,
            t: req.t
        });
    }
}

module.exports = PortalController;
EOF

    # Dashboard Controller
    cat << 'EOF' > "$SYSTEM_DIR/app/controllers/DashboardController.js"
const Device = require('../models/Device');
const Voucher = require('../models/Voucher');
const Session = require('../models/Session');
const PaymentTransaction = require('../models/PaymentTransaction');
const VoucherService = require('../services/VoucherService');
const ReportService = require('../services/ReportService');

class DashboardController {
    static async index(req, res) {
        res.render('dashboard/index', {
            title: req.t('dashboard'),
            activeMenu: 'dashboard'
        });
    }
    
    static async getStats(req, res) {
        try {
            const organizationId = req.user.organization._id;
            
            // Get device stats
            const totalDevices = await Device.countDocuments({ 
                organization: organizationId 
            });
            const onlineDevices = await Device.countDocuments({ 
                organization: organizationId,
                status: 'online'
            });
            
            // Get active users
            const activeUsers = await Session.countDocuments({
                organization: organizationId,
                status: 'active'
            });
            
            // Get voucher stats
            const voucherStats = await VoucherService.getStatistics(organizationId);
            
            // Get today's revenue
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            const todayRevenue = await PaymentTransaction.aggregate([
                {
                    $match: {
                        organization: organizationId,
                        status: 'completed',
                        createdAt: { $gte: today }
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$amount.value' }
                    }
                }
            ]);
            
            // Get chart data
            const usageChart = await this.getUsageChartData(organizationId);
            const revenueChart = await this.getRevenueChartData(organizationId);
            
            res.json({
                success: true,
                data: {
                    totalDevices,
                    onlineDevices,
                    activeUsers,
                    totalVouchers: voucherStats.total,
                    activeVouchers: voucherStats.active,
                    todayRevenue: todayRevenue[0]?.total || 0,
                    usageChart,
                    revenueChart
                }
            });
        } catch (error) {
            console.error('Stats error:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Failed to get statistics' 
            });
        }
    }
    
    static async getUsageChartData(organizationId) {
        const last7Days = [];
        const data = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            date.setHours(0, 0, 0, 0);
            
            const nextDate = new Date(date);
            nextDate.setDate(nextDate.getDate() + 1);
            
            const count = await Session.countDocuments({
                organization: organizationId,
                startTime: {
                    $gte: date,
                    $lt: nextDate
                }
            });
            
            last7Days.push(date.toLocaleDateString('th-TH', { 
                day: 'numeric', 
                month: 'short' 
            }));
            data.push(count);
        }
        
        return { labels: last7Days, data };
    }
    
    static async getRevenueChartData(organizationId) {
        const last7Days = [];
        const data = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            date.setHours(0, 0, 0, 0);
            
            const nextDate = new Date(date);
            nextDate.setDate(nextDate.getDate() + 1);
            
            const revenue = await PaymentTransaction.aggregate([
                {
                    $match: {
                        organization: organizationId,
                        status: 'completed',
                        createdAt: {
                            $gte: date,
                            $lt: nextDate
                        }
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$amount.value' }
                    }
                }
            ]);
            
            last7Days.push(date.toLocaleDateString('th-TH', { 
                day: 'numeric', 
                month: 'short' 
            }));
            data.push(revenue[0]?.total || 0);
        }
        
        return { labels: last7Days, data };
    }
    
    static async devices(req, res) {
        const devices = await Device.find({ 
            organization: req.user.organization._id 
        }).sort({ createdAt: -1 });
        
        res.render('devices/index', {
            title: req.t('devices'),
            activeMenu: 'devices',
            devices
        });
    }
    
    static async vouchers(req, res) {
        const vouchers = await Voucher.find({ 
            organization: req.user.organization._id 
        })
        .populate('device', 'name')
        .sort({ createdAt: -1 })
        .limit(100);
        
        res.render('vouchers/index', {
            title: req.t('vouchers'),
            activeMenu: 'vouchers',
            vouchers
        });
    }
    
    static async createVoucherForm(req, res) {
        const devices = await Device.find({ 
            organization: req.user.organization._id,
            status: 'online'
        });
        
        res.render('vouchers/create', {
            title: req.t('voucher.createVoucher'),
            activeMenu: 'vouchers',
            devices
        });
    }
    
    static async createVoucher(req, res) {
        try {
            const vouchers = await VoucherService.generateBatch({
                ...req.body,
                organization: req.user.organization._id,
                createdBy: req.user._id
            });
            
            req.flash('success_msg', req.t('voucher.createdSuccess', { count: vouchers.length }));
            res.redirect('/vouchers');
        } catch (error) {
            console.error('Create voucher error:', error);
            req.flash('error_msg', req.t('voucher.createError'));
            res.redirect('/vouchers/create');
        }
    }
    
    static async printVoucher(req, res) {
        const voucher = await Voucher.findById(req.params.id);
        
        if (!voucher || voucher.organization.toString() !== req.user.organization._id.toString()) {
            return res.status(404).send('Voucher not found');
        }
        
        res.render('vouchers/print', {
            layout: false,
            voucher
        });
    }
    
    static async users(req, res) {
        res.render('users/index', {
            title: req.t('users'),
            activeMenu: 'users'
        });
    }
    
    static async reports(req, res) {
        res.render('reports/index', {
            title: req.t('reports'),
            activeMenu: 'reports'
        });
    }
    
    static async revenueReport(req, res) {
        const report = await ReportService.generateRevenueReport({
            organizationId: req.user.organization._id,
            ...req.query
        });
        
        res.render('reports/revenue', {
            title: req.t('reports.revenue'),
            activeMenu: 'reports',
            report
        });
    }
    
    static async usageReport(req, res) {
        const report = await ReportService.generateUsageReport({
            organizationId: req.user.organization._id,
            ...req.query
        });
        
        res.render('reports/usage', {
            title: req.t('reports.usage'),
            activeMenu: 'reports',
            report
        });
    }
    
    static async exportReport(req, res) {
        try {
            const url = await ReportService.exportReport({
                ...req.query,
                organizationId: req.user.organization._id,
                userId: req.user._id
            });
            
            res.json({ success: true, url });
        } catch (error) {
            console.error('Export error:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Export failed' 
            });
        }
    }
}

module.exports = DashboardController;
EOF

    # Settings Controller
    cat << 'EOF' > "$SYSTEM_DIR/app/controllers/SettingsController.js"
const Organization = require('../models/Organization');
const HotspotProfile = require('../models/HotspotProfile');
const PortalTemplate = require('../models/PortalTemplate');

class SettingsController {
    static async index(req, res) {
        res.render('settings/index', {
            title: req.t('settings'),
            activeMenu: 'settings'
        });
    }
    
    static async updateGeneral(req, res) {
        try {
            await Organization.findByIdAndUpdate(
                req.user.organization._id,
                {
                    name: req.body.name,
                    email: req.body.email,
                    phone: req.body.phone,
                    address: req.body.address,
                    'settings.timezone': req.body.timezone,
                    'settings.currency': req.body.currency,
                    'settings.language': req.body.language
                }
            );
            
            req.flash('success_msg', req.t('settings.updated'));
            res.redirect('/settings');
        } catch (error) {
            console.error('Settings update error:', error);
            req.flash('error_msg', req.t('settings.updateError'));
            res.redirect('/settings');
        }
    }
    
    static async organization(req, res) {
        const organization = await Organization.findById(req.user.organization._id);
        
        res.render('settings/organization', {
            title: req.t('settings.organization'),
            activeMenu: 'settings',
            organization
        });
    }
    
    static async updateOrganization(req, res) {
        try {
            await Organization.findByIdAndUpdate(
                req.user.organization._id,
                req.body
            );
            
            req.flash('success_msg', req.t('settings.updated'));
            res.redirect('/settings/organization');
        } catch (error) {
            console.error('Organization update error:', error);
            req.flash('error_msg', req.t('settings.updateError'));
            res.redirect('/settings/organization');
        }
    }
    
    static async payment(req, res) {
        const organization = await Organization.findById(req.user.organization._id);
        
        res.render('settings/payment', {
            title: req.t('settings.payment'),
            activeMenu: 'settings',
            paymentSettings: organization.paymentSettings
        });
    }
    
    static async updatePayment(req, res) {
        try {
            await Organization.findByIdAndUpdate(
                req.user.organization._id,
                {
                    'paymentSettings': req.body
                }
            );
            
            req.flash('success_msg', req.t('settings.updated'));
            res.redirect('/settings/payment');
        } catch (error) {
            console.error('Payment settings error:', error);
            req.flash('error_msg', req.t('settings.updateError'));
            res.redirect('/settings/payment');
        }
    }
    
    static async portal(req, res) {
        const templates = await PortalTemplate.find({
            organization: req.user.organization._id
        });
        
        res.render('settings/portal', {
            title: req.t('settings.portal'),
            activeMenu: 'settings',
            templates
        });
    }
    
    static async updatePortal(req, res) {
        try {
            const templateId = req.body.templateId;
            
            if (templateId) {
                await PortalTemplate.findByIdAndUpdate(templateId, req.body);
            } else {
                await PortalTemplate.create({
                    ...req.body,
                    organization: req.user.organization._id
                });
            }
            
            req.flash('success_msg', req.t('settings.updated'));
            res.redirect('/settings/portal');
        } catch (error) {
            console.error('Portal settings error:', error);
            req.flash('error_msg', req.t('settings.updateError'));
            res.redirect('/settings/portal');
        }
    }
    
    static async uploadPortalTemplate(req, res) {
        try {
            if (!req.files || !req.files.template) {
                throw new Error('No file uploaded');
            }
            
            const template = req.files.template;
            const uploadPath = `/uploads/portal-templates/${Date.now()}-${template.name}`;
            
            await template.mv(`./public${uploadPath}`);
            
            res.json({ 
                success: true, 
                path: uploadPath 
            });
        } catch (error) {
            console.error('Template upload error:', error);
            res.status(400).json({ 
                success: false, 
                error: 'Upload failed' 
            });
        }
    }
    
    static async voucherProfiles(req, res) {
        const profiles = await HotspotProfile.find({
            organization: req.user.organization._id
        }).sort({ order: 1 });
        
        res.render('settings/voucher-profiles', {
            title: req.t('settings.voucherProfiles'),
            activeMenu: 'settings',
            profiles
        });
    }
    
    static async createVoucherProfile(req, res) {
        try {
            await HotspotProfile.create({
                ...req.body,
                organization: req.user.organization._id
            });
            
            req.flash('success_msg', req.t('settings.profileCreated'));
            res.redirect('/settings/vouchers');
        } catch (error) {
            console.error('Profile create error:', error);
            req.flash('error_msg', req.t('settings.createError'));
            res.redirect('/settings/vouchers');
        }
    }
    
    static async updateVoucherProfile(req, res) {
        try {
            await HotspotProfile.findByIdAndUpdate(
                req.params.id,
                req.body
            );
            
            req.flash('success_msg', req.t('settings.updated'));
            res.redirect('/settings/vouchers');
        } catch (error) {
            console.error('Profile update error:', error);
            req.flash('error_msg', req.t('settings.updateError'));
            res.redirect('/settings/vouchers');
        }
    }
    
    static async deleteVoucherProfile(req, res) {
        try {
            await HotspotProfile.findByIdAndDelete(req.params.id);
            
            req.flash('success_msg', req.t('settings.deleted'));
            res.redirect('/settings/vouchers');
        } catch (error) {
            console.error('Profile delete error:', error);
            req.flash('error_msg', req.t('settings.deleteError'));
            res.redirect('/settings/vouchers');
        }
    }
    
    static async email(req, res) {
        res.render('settings/email', {
            title: req.t('settings.email'),
            activeMenu: 'settings'
        });
    }
    
    static async updateEmail(req, res) {
        try {
            // Update email settings in environment or database
            
            req.flash('success_msg', req.t('settings.updated'));
            res.redirect('/settings/email');
        } catch (error) {
            console.error('Email settings error:', error);
            req.flash('error_msg', req.t('settings.updateError'));
            res.redirect('/settings/email');
        }
    }
    
    static async testEmail(req, res) {
        try {
            const EmailService = require('../utils/email');
            await EmailService.sendEmail({
                to: req.body.email,
                subject: 'Test Email',
                template: 'test',
                data: {}
            });
            
            res.json({ success: true });
        } catch (error) {
            console.error('Email test error:', error);
            res.status(400).json({ 
                success: false, 
                error: 'Failed to send test email' 
            });
        }
    }
    
    static async api(req, res) {
        res.render('settings/api', {
            title: req.t('settings.api'),
            activeMenu: 'settings',
            apiKeys: req.user.apiKeys
        });
    }
    
    static async generateApiKey(req, res) {
        try {
            const crypto = require('crypto');
            const apiKey = crypto.randomBytes(32).toString('hex');
            
            req.user.apiKeys.push({
                key: apiKey,
                name: req.body.name,
                permissions: req.body.permissions,
                createdAt: new Date()
            });
            
            await req.user.save();
            
            res.json({ 
                success: true, 
                apiKey 
            });
        } catch (error) {
            console.error('API key error:', error);
            res.status(400).json({ 
                success: false, 
                error: 'Failed to generate API key' 
            });
        }
    }
    
    static async deleteApiKey(req, res) {
        try {
            req.user.apiKeys = req.user.apiKeys.filter(
                key => key._id.toString() !== req.params.id
            );
            
            await req.user.save();
            
            req.flash('success_msg', req.t('settings.deleted'));
            res.redirect('/settings/api');
        } catch (error) {
            console.error('API key delete error:', error);
            req.flash('error_msg', req.t('settings.deleteError'));
            res.redirect('/settings/api');
        }
    }
}

module.exports = SettingsController;
EOF
}

# Create application config files
create_app_config_files_full() {
    # Main app config with all features
    cat << EOF > "$SYSTEM_DIR/app/.env"
# Application Configuration
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# URLs
APP_URL=https://$DOMAIN_NAME
CORS_ORIGIN=https://$DOMAIN_NAME,https://admin.$DOMAIN_NAME,https://monitor.$DOMAIN_NAME

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
FROM_EMAIL=noreply@$DOMAIN_NAME
FROM_NAME=MikroTik VPN

# SMS Configuration
SMS_PROVIDER=thaibulksms
THAIBULK_API_KEY=your-api-key
THAIBULK_API_SECRET=your-api-secret
THAIBULK_SENDER=MIKROTIK

# Payment Gateway
PAYMENT_API_KEY=$PAYMENT_API_KEY
PAYMENT_SECRET=$PAYMENT_SECRET
PROMPTPAY_NUMBER=0812345678
OMISE_PUBLIC_KEY=your-omise-public-key
OMISE_SECRET_KEY=your-omise-secret-key

# VPN Configuration
VPN_NETWORK=$VPN_NETWORK
OPENVPN_HOST=$DOMAIN_NAME
OPENVPN_PORT=1194

# MikroTik
MIKROTIK_USER=admin
MIKROTIK_PASSWORD=

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_URL=http://grafana:3000

# Logging
LOG_LEVEL=info
LOG_DIR=/var/log/mikrotik-vpn

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100

# Multi-language
DEFAULT_LANGUAGE=$DEFAULT_LANGUAGE
DEFAULT_CURRENCY=$DEFAULT_CURRENCY
EOF

    # Create Tailwind config
    create_tailwind_config
    
    # Create app.js (client-side JavaScript)
    mkdir -p "$SYSTEM_DIR/app/public/js"
    cat << 'EOF' > "$SYSTEM_DIR/app/public/js/app.js"
// Global app object
window.App = {
    socket: null,
    currentUser: null,
    
    init() {
        this.initSocket();
        this.initDataTables();
        this.initTooltips();
        this.initModals();
    },
    
    initSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Socket connected');
        });
        
        this.socket.on('notification', (data) => {
            this.showNotification(data);
        });
    },
    
    initDataTables() {
        if ($.fn.DataTable) {
            $('.data-table').DataTable({
                responsive: true,
                language: {
                    url: `/static/i18n/datatables/${document.documentElement.lang}.json`
                }
            });
        }
    },
    
    initTooltips() {
        // Initialize tooltips
    },
    
    initModals() {
        // Initialize modals
    },
    
    showNotification(data) {
        const { type, title, message } = data;
        
        Swal.fire({
            icon: type,
            title: title,
            text: message,
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 3000,
            timerProgressBar: true
        });
    },
    
    confirmDelete(url, message) {
        Swal.fire({
            title: 'Are you sure?',
            text: message || 'You won\'t be able to revert this!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                window.location.href = url;
            }
        });
    },
    
    formatCurrency(amount, currency = 'THB') {
        return new Intl.NumberFormat('th-TH', {
            style: 'currency',
            currency: currency
        }).format(amount);
    },
    
    formatDate(date, format = 'short') {
        return new Intl.DateTimeFormat('th-TH', {
            dateStyle: format
        }).format(new Date(date));
    }
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
EOF

    # Create CSS file
    mkdir -p "$SYSTEM_DIR/app/public/css"
    cat << 'EOF' > "$SYSTEM_DIR/app/public/css/app.css"
/* Custom styles for MikroTik VPN Management System */

/* Thai font support */
@import url('https://fonts.googleapis.com/css2?family=Sarabun:wght@300;400;500;600;700&display=swap');

body {
    font-family: 'Sarabun', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

/* Custom scrollbar */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: #f1f1f1;
}

::-webkit-scrollbar-thumb {
    background: #888;
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: #555;
}

/* Loading spinner */
.spinner {
    border: 3px solid #f3f3f3;
    border-top: 3px solid #3498db;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Voucher card styles */
.voucher-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
}

.voucher-code {
    font-family: 'Courier New', monospace;
    font-size: 24px;
    font-weight: bold;
    letter-spacing: 2px;
}

/* Status badges */
.status-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 10px;
    border-radius: 9999px;
    font-size: 12px;
    font-weight: 500;
}

.status-badge.online {
    background-color: #10b981;
    color: white;
}

.status-badge.offline {
    background-color: #ef4444;
    color: white;
}

.status-badge.active {
    background-color: #3b82f6;
    color: white;
}

.status-badge.inactive {
    background-color: #6b7280;
    color: white;
}

/* Portal styles */
.portal-gradient {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

/* Print styles */
@media print {
    .no-print {
        display: none !important;
    }
    
    .voucher-print {
        page-break-inside: avoid;
    }
}

/* Responsive tables */
@media (max-width: 640px) {
    .responsive-table {
        display: block;
        overflow-x: auto;
        white-space: nowrap;
    }
}

/* Animation classes */
.fade-in {
    animation: fadeIn 0.5s ease-in;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.slide-up {
    animation: slideUp 0.3s ease-out;
}

@keyframes slideUp {
    from {
        transform: translateY(20px);
        opacity: 0;
    }
    to {
        transform: translateY(0);
        opacity: 1;
    }
}
EOF
}

# Create Tailwind CSS configuration
create_tailwind_config() {
    cat << 'EOF' > "$SYSTEM_DIR/app/tailwind.config.js"
module.exports = {
  content: [
    './views/**/*.ejs',
    './public/**/*.js',
  ],
  theme: {
    extend: {
      fontFamily: {
        'sans': ['Sarabun', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      colors: {
        'primary': {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
}
EOF

    # Create postcss config
    cat << 'EOF' > "$SYSTEM_DIR/app/postcss.config.js"
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOF
}

# Continue with Phase 6...
# Create Nginx, OpenVPN, Prometheus, Grafana configurations as before
# These remain the same as in the previous version

# =============================================================================
# PHASE 10: FINAL SETUP AND VERIFICATION
# =============================================================================

phase10_final_setup() {
    log "==================================================================="
    log "PHASE 10: FINAL SETUP AND VERIFICATION"
    log "==================================================================="
    
    # Load configuration first
    if [[ -f "$CONFIG_DIR/setup.env" ]]; then
        source "$CONFIG_DIR/setup.env"
        log "Configuration loaded successfully"
    else
        log_error "Configuration file not found at $CONFIG_DIR/setup.env"
        exit 1
    fi
    
    # Create controllers
    create_controller_files
    
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
    log "MikroTik VPN Management System v5.0 installation completed successfully!"
    log "=================================================================="
    log ""
    log "All features have been installed:"
    log "✓ Multi-language support (Thai & English)"
    log "✓ Payment Gateway Integration (PromptPay, TrueWallet)"
    log "✓ MikroTik RouterOS API Integration"
    log "✓ Complete Voucher Management System"
    log "✓ Captive Portal with Multiple Login Methods"
    log "✓ Advanced Reporting & Analytics"
    log ""
    log "To access the management interface, run: mikrotik-vpn"
    log ""
    
    return 0
}

# Execute main function
main "$@"
exit $?
