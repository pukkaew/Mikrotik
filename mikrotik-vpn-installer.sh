# Wait for databases
    print_status "Waiting for databases to be ready..."
    sleep 20
    
    print_status "Starting VPN services..."
    docker compose -f docker-compose-openvpn.yml up -d
    
    print_status "Starting application..."
    docker compose -f docker-compose-app.yml up -d
    
    print_status "Starting web server..."
    docker compose -f docker-compose-nginx.yml up -d
    
    print_status "All services started! Waiting for initialization..."
    sleep 10
    
    # Check if services are running
    if docker ps | grep -q mikrotik-nginx; then
        print_status "✓ All services are running successfully"
    else
        print_warning "Some services may still be starting up"
    fi
}

stop_all_services() {
    print_status "Stopping all MikroTik VPN services..."
    
    cd "$SYSTEM_DIR" || {
        print_error "Cannot access system directory: $SYSTEM_DIR"
        return 1
    }
    
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
            if [ -f "$LOG_DIR/setup.log" ]; then
                tail -f "$LOG_DIR/setup.log"
            else
                print_error "System log not found"
            fi
            ;;
        "all")
            cd "$SYSTEM_DIR" || {
                print_error "Cannot access system directory"
                return 1
            }
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
    
    # Validate client name (only alphanumeric and dash)
    if [[ ! $client_name =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "Client name can only contain letters, numbers, underscore and dash"
        return 1
    fi
    
    print_status "Creating VPN client configuration for: $client_name"
    
    # Load domain from config
    if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
        source "$SYSTEM_DIR/configs/setup.env"
    else
        print_error "Configuration file not found"
        return 1
    fi
    
    # Check if Easy-RSA directory exists
    if [ ! -d "$SYSTEM_DIR/openvpn/easy-rsa" ]; then
        print_error "OpenVPN Easy-RSA not found. Please ensure OpenVPN is properly configured."
        return 1
    fi
    
    cd "$SYSTEM_DIR/openvpn/easy-rsa" || {
        print_error "Cannot access Easy-RSA directory"
        return 1
    }
    
    # Generate client certificate
    ./easyrsa gen-req "$client_name" nopass || {
        print_error "Failed to generate client request"
        return 1
    }
    
    ./easyrsa sign-req client "$client_name" || {
        print_error "Failed to sign client certificate"
        return 1
    }
    
    # Create client configuration directory
    mkdir -p "$SYSTEM_DIR/clients"
    
    # Create client configuration file
    cat << EOC > "$SYSTEM_DIR/clients/$client_name.ovpn"
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
auth SHA256
comp-lzo
verb 3

<ca>
$(cat pki/ca.crt)
</ca>

<cert>
$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' pki/issued/$client_name.crt)
</cert>

<key>
$(cat pki/private/$client_name.key)
</key>

<tls-auth>
$(cat ta.key)
</tls-auth>
key-direction 1
EOC

    chown mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/clients/$client_name.ovpn"
    chmod 600 "$SYSTEM_DIR/clients/$client_name.ovpn"
    
    print_status "✓ Client configuration created: $SYSTEM_DIR/clients/$client_name.ovpn"
    echo
    print_status "To use this configuration:"
    echo "1. Copy the file to your OpenVPN client device"
    echo "2. Import it in your OpenVPN client application"
    echo "3. Connect to the VPN"
}

list_vpn_clients() {
    print_status "VPN Client Configurations:"
    
    if [ -d "$SYSTEM_DIR/clients" ] && [ "$(ls -A $SYSTEM_DIR/clients 2>/dev/null)" ]; then
        echo
        ls -la "$SYSTEM_DIR/clients"/*.ovpn 2>/dev/null | awk '{print "  " $9 " (" $5 " bytes, " $6 " " $7 " " $8 ")"}'
    else
        echo "  No VPN client configurations found"
    fi
    
    echo
    print_status "To generate a new client: $0 vpn <client_name>"
}

# Backup management
run_backup() {
    print_status "Running system backup..."
    
    if [ -f "$SCRIPT_DIR/backup-system.sh" ]; then
        "$SCRIPT_DIR/backup-system.sh"
    else
        print_error "Backup script not found"
        return 1
    fi
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
        echo "7. List VPN Clients"
        echo "8. Run Backup"
        echo "9. Exit"
        echo
        read -p "Select option (1-9): " choice
        
        case $choice in
            1) show_system_status ;;
            2) start_all_services ;;
            3) stop_all_services ;;
            4) restart_all_services ;;
            5) 
                echo
                echo "Available services: app, nginx, mongodb, redis, openvpn, system, all"
                read -p "Enter service name: " service
                view_logs "$service"
                ;;
            6) 
                echo
                read -p "Enter client name: " client_name
                generate_vpn_client "$client_name"
                ;;
            7) list_vpn_clients ;;
            8) run_backup ;;
            9) 
                print_status "Exiting MikroTik VPN Manager"
                exit 0
                ;;
            *) 
                print_error "Invalid option. Please select 1-9."
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
            if [ -n "$2" ]; then
                generate_vpn_client "$2"
            else
                list_vpn_clients
            fi
            ;;
        "backup")
            run_backup
            ;;
        "menu"|"")
            show_main_menu
            ;;
        "help"|"-h"|"--help")
            echo "MikroTik VPN Management System v2.2"
            echo
            echo "Usage: $0 [command] [options]"
            echo
            echo "Commands:"
            echo "  status              - Show system status"
            echo "  start               - Start all services"
            echo "  stop                - Stop all services"
            echo "  restart             - Restart all services"
            echo "  logs <service>      - View service logs"
            echo "  vpn [client_name]   - Generate/list VPN clients"
            echo "  backup              - Run system backup"
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

    chmod +x "$SYSTEM_DIR/mikrotik-vpn-manager.sh"

    # Create service management scripts
    cat << 'EOF' > "$SCRIPT_DIR/start-all-services.sh"
#!/bin/bash
# Start all services script

SYSTEM_DIR="/opt/mikrotik-vpn"

if [ ! -d "$SYSTEM_DIR" ]; then
    echo "ERROR: System directory not found: $SYSTEM_DIR"
    exit 1
fi

cd "$SYSTEM_DIR" || exit 1

echo "Starting MikroTik VPN services..."

# Create network if it doesn't exist
if ! docker network ls | grep -q mikrotik-vpn-net; then
    echo "Creating Docker network..."
    docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 2>/dev/null || true
fi

# Start services in dependency order
echo "Starting databases..."
docker compose -f docker-compose-mongodb.yml up -d
docker compose -f docker-compose-redis.yml up -d

echo "Waiting for databases to initialize..."
sleep 20

echo "Starting VPN services..."
docker compose -f docker-compose-openvpn.yml up -d

echo "Starting application..."
docker compose -f docker-compose-app.yml up -d

echo "Starting web server..."
docker compose -f docker-compose-nginx.yml up -d

echo "All services started successfully!"
EOF

    chmod +x "$SCRIPT_DIR/start-all-services.sh"

    cat << 'EOF' > "$SCRIPT_DIR/stop-all-services.sh"
#!/bin/bash
# Stop all services script

SYSTEM_DIR="/opt/mikrotik-vpn"

if [ ! -d "$SYSTEM_DIR" ]; then
    echo "ERROR: System directory not found: $SYSTEM_DIR"
    exit 1
fi

cd "$SYSTEM_DIR" || exit 1

echo "Stopping MikroTik VPN services..."

# Stop services in reverse order
docker compose -f docker-compose-nginx.yml down 2>/dev/null || true
docker compose -f docker-compose-app.yml down 2>/dev/null || true
docker compose -f docker-compose-openvpn.yml down 2>/dev/null || true
docker compose -f docker-compose-redis.yml down 2>/dev/null || true
docker compose -f docker-compose-mongodb.yml down 2>/dev/null || true

echo "All services stopped!"
EOF

    chmod +x "$SCRIPT_DIR/stop-all-services.sh"

    # Create backup script
    cat << 'EOF' > "$SCRIPT_DIR/backup-system.sh"
#!/bin/bash
# System backup script

BACKUP_DIR="/opt/mikrotik-vpn/backups"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/mikrotik-vpn/backup.log"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Load environment variables
if [ -f "/opt/mikrotik-vpn/configs/setup.env" ]; then
    source "/opt/mikrotik-vpn/configs/setup.env"
else
    echo "Configuration file not found"
    exit 1
fi

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE"
}

BACKUP_PATH="$BACKUP_DIR/daily/backup_$DATE"

log "Starting backup to $BACKUP_PATH"
mkdir -p "$BACKUP_PATH"

# Backup MongoDB
if docker ps | grep -q mikrotik-mongodb; then
    log "Backing up MongoDB..."
    docker exec mikrotik-mongodb mongodump \
        --host localhost \
        --username admin \
        --password "$MONGO_ROOT_PASSWORD" \
        --authenticationDatabase admin \
        --out /tmp/mongodb-backup 2>/dev/null || {
        log "MongoDB backup failed"
    }
    
    docker cp mikrotik-mongodb:/tmp/mongodb-backup "$BACKUP_PATH/" 2>/dev/null || true
    docker exec mikrotik-mongodb rm -rf /tmp/mongodb-backup 2>/dev/null || true
else
    log "MongoDB container not running, skipping database backup"
fi

# Backup Redis
if docker ps | grep -q mikrotik-redis; then
    log "Backing up Redis..."
    docker exec mikrotik-redis redis-cli --no-auth-warning --pass "$REDIS_PASSWORD" BGSAVE 2>/dev/null || {
        log "Redis backup command failed"
    }
    sleep 5
    docker cp mikrotik-redis:/data/dump.rdb "$BACKUP_PATH/redis_dump.rdb" 2>/dev/null || true
else
    log "Redis container not running, skipping Redis backup"
fi

# Backup configurations
log "Backing up configurations..."
tar -czf "$BACKUP_PATH/configs.tar.gz" \
    /opt/mikrotik-vpn/configs \
    /opt/mikrotik-vpn/nginx \
    /opt/mikrotik-vpn/openvpn \
    /opt/mikrotik-vpn/app/.env \
    2>/dev/null || log "Some configuration files could not be backed up"

# Create checksum
if [ -d "$BACKUP_PATH" ]; then
    cd "$BACKUP_PATH" || exit 1
    find . -type f -exec sha256sum {} \; > checksums.sha256 2>/dev/null || true
    
    # Compress backup
    cd "$BACKUP_DIR/daily" || exit 1
    tar -czf "backup_$DATE.tar.gz" "backup_$DATE/" 2>/dev/null || {
        log "Failed to compress backup"
        exit 1
    }
    rm -rf "backup_$DATE/"
    
    # Get backup size
    if [ -f "backup_$DATE.tar.gz" ]; then
        backup_size=$(du -h "backup_$DATE.tar.gz" | cut -f1)
        log "Backup completed successfully: backup_$DATE.tar.gz ($backup_size)"
        
        # Clean old backups (keep last 7 days)
        find "$BACKUP_DIR/daily" -name "backup_*.tar.gz" -mtime +7 -delete 2>/dev/null || true
        log "Old backups cleaned up"
    else
        log "Backup file not created"
        exit 1
    fi
else
    log "Backup directory not created"
    exit 1
fi
EOF

    chmod +x "$SCRIPT_DIR/backup-system.sh"

    # Create health check script
    cat << 'EOF' > "$SCRIPT_DIR/health-check.sh"
#!/bin/bash
# Health check script

LOG_FILE="/var/log/mikrotik-vpn/health-check.log"
FAILED_CHECKS=""

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE"
}

check_service() {
    local service=$1
    local container_name=$2
    
    if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        if docker ps --format "{{.Names}} {{.Status}}" | grep "^${container_name}" | grep -q "Up"; then
            log "✓ $service is running"
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

check_disk_space() {
    local usage
    usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$usage" -gt 80 ]; then
        log "⚠ Disk usage is high: $usage%"
        FAILED_CHECKS="$FAILED_CHECKS disk_space"
        return 1
    else
        log "✓ Disk usage is normal: $usage%"
        return 0
    fi
}

check_memory() {
    local usage
    usage=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
    
    if [ "$usage" -gt 85 ]; then
        log "⚠ Memory usage is high: $usage%"
        FAILED_CHECKS="$FAILED_CHECKS memory"
        return 1
    else
        log "✓ Memory usage is normal: $usage%"
        return 0
    fi
}

check_web_service() {
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80 2>/dev/null || echo "000")
    
    if [[ "$response" =~ ^(200|301|302)$ ]]; then
        log "✓ Web server is responding"
        return 0
    else
        log "✗ Web server not responding (HTTP $response)"
        FAILED_CHECKS="$FAILED_CHECKS web_server"
        return 1
    fi
}

# Main health check
main() {
    log "=== Health Check Started ==="
    
    # Check Docker is available
    if ! command -v docker >/dev/null; then
        log "✗ Docker is not available"
        echo "UNHEALTHY"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log "✗ Docker daemon is not running"
        echo "UNHEALTHY"
        exit 1
    fi
    
    # Check all services
    check_service "MongoDB" "mikrotik-mongodb"
    check_service "Redis" "mikrotik-redis"
    check_service "OpenVPN" "mikrotik-openvpn"
    check_service "Application" "mikrotik-app"
    check_service "Nginx" "mikrotik-nginx"
    
    # Check system resources
    check_disk_space
    check_memory
    check_web_service
    
    # Summary
    if [ -z "$FAILED_CHECKS" ]; then
        log "✓ Overall status: HEALTHY"
        echo "HEALTHY"
        exit 0
    else
        log "✗ Overall status: UNHEALTHY - Failed checks:$FAILED_CHECKS"
        echo "UNHEALTHY"
        exit 1
    fi
}

main "$@"
EOF

    chmod +x "$SCRIPT_DIR/health-check.sh"
}

setup_system_service() {
    # Create systemd service
    cat << EOF > /etc/systemd/system/mikrotik-vpn.service
[Unit]
Description=MikroTik VPN Management System
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
WorkingDirectory=$SYSTEM_DIR
ExecStart=$SCRIPT_DIR/start-all-services.sh
ExecStop=$SCRIPT_DIR/stop-all-services.sh
ExecReload=/bin/bash -c 'cd $SYSTEM_DIR && docker compose -f docker-compose-*.yml restart'
TimeoutStartSec=300
TimeoutStopSec=120
Restart=no

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mikrotik-vpn.service
    
    log "SystemD service created and enabled"
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
    ufw --force reset >/dev/null 2>&1
    
    # Default policies
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    
    # Allow SSH
    ufw allow "$SSH_PORT/tcp" comment 'SSH' >/dev/null 2>&1
    
    # Allow web traffic
    ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1
    
    # Allow VPN
    ufw allow 1194/udp comment 'OpenVPN' >/dev/null 2>&1
    
    # Allow internal Docker network
    ufw allow from 172.20.0.0/16 comment 'Docker network' >/dev/null 2>&1
    
    # Allow VPN network access to local services
    VPN_SUBNET=$(echo "$VPN_NETWORK" | cut -d'/' -f1 | sed 's/\.[0-9]*$/\.0/')
    ufw allow from "$VPN_SUBNET/24" to any port 3000 comment 'VPN to API' >/dev/null 2>&1
    
    # Enable UFW
    ufw --force enable >/dev/null 2>&1
    
    log "Firewall configured and enabled"
}

harden_ssh() {
    # Only harden SSH if not using localhost/IP
    if [[ "$DOMAIN_NAME" != "localhost" ]] && [[ ! "$DOMAIN_NAME" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Backup original config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d) 2>/dev/null || true
        
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

        # Add current user to allowed users if not root
        if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
            echo "AllowUsers mikrotik-vpn $SUDO_USER" > /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
            sed -i '/^AllowUsers mikrotik-vpn$/d' /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
        fi
        
        # Test SSH configuration
        if sshd -t 2>/dev/null; then
            systemctl restart sshd
            log "SSH hardening completed"
        else
            log_warning "SSH configuration test failed, keeping original config"
            rm -f /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
        fi
    else
        log "Skipping SSH hardening for localhost/IP setup"
    fi
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
logpath = $LOG_DIR/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = $LOG_DIR/nginx/error.log
maxretry = 10
EOF

    systemctl restart fail2ban >/dev/null 2>&1 || true
    systemctl enable fail2ban >/dev/null 2>&1 || true
    
    log "Fail2ban configured"
}

# =============================================================================
# PHASE 9: CONFIGURATION SAVE AND FINALIZATION
# =============================================================================

phase9_finalization() {
    log "==================================================================="
    log "PHASE 9: CONFIGURATION SAVE AND FINALIZATION"
    log "==================================================================="
    
    log "Saving configuration..."
    save_configuration
    
    log "Setting up automated tasks..."
    setup_cron_jobs
    
    log "Building and starting services..."
    build_and_start_services
    
    log "Phase 9 completed successfully!"
}

save_configuration() {
    # Save installation configuration
    cat << EOF > "$SYSTEM_DIR/configs/setup.env"
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
INSTALLER_VERSION="2.2"
SYSTEM_STATUS="installed"
EOF

    chmod 600 "$SYSTEM_DIR/configs/setup.env"
    
    # Create passwords file for reference
    cat << EOF > "$SYSTEM_DIR/configs/passwords.txt"
MikroTik VPN System - Password Reference
======================================
Generated: $(date)

MongoDB Admin:
  Username: admin
  Password: $MONGO_ROOT_PASSWORD

MongoDB App:
  Username: mikrotik_app
  Password: $MONGO_APP_PASSWORD

Redis:
  Password: $REDIS_PASSWORD

IMPORTANT: Keep this file secure and change passwords after installation!
EOF

    chmod 600 "$SYSTEM_DIR/configs/passwords.txt"
    
    # Set proper ownership
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR"
    
    log "Configuration saved securely"
}

setup_cron_jobs() {
    # Create cron job for automated tasks
    cat << EOF > /etc/cron.d/mikrotik-vpn
# MikroTik VPN System Scheduled Tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily backup at 2:00 AM
0 2 * * * mikrotik-vpn $SCRIPT_DIR/backup-system.sh >/dev/null 2>&1

# Health check every 5 minutes (only log failures)
*/5 * * * * mikrotik-vpn $SCRIPT_DIR/health-check.sh | grep -q "UNHEALTHY" && echo "Health check failed at \$(date)" >> $LOG_DIR/health-failures.log

# Clean old logs weekly (files older than 30 days)
0 3 * * 0 mikrotik-vpn find $LOG_DIR -name "*.log" -type f -mtime +30 -delete 2>/dev/null

# Restart containers if they become unhealthy (weekly check)
0 4 * * 0 root docker ps --filter health=unhealthy --format "{{.Names}}" | xargs -r docker restart 2>/dev/null
EOF

    # Set proper permissions
    chmod 644 /etc/cron.d/mikrotik-vpn
    
    # Restart cron service
    systemctl restart cron >/dev/null 2>&1 || true
    
    log "Automated tasks configured"
}

build_and_start_services() {
    cd "$SYSTEM_DIR" || {
        log_error "Cannot access system directory"
        exit 1
    }
    
    # Install Node.js dependencies
    log "Installing application dependencies..."
    cd "$SYSTEM_DIR/app" || exit 1
    
    if command -v npm >/dev/null 2>&1; then
        npm install --production --silent || {
            log_warning "npm install failed, but continuing..."
        }
    else
        log_warning "npm not available, dependencies will be installed in container"
    fi
    
    cd "$SYSTEM_DIR" || exit 1
    
    # Create Docker network
    if ! docker network ls | grep -q mikrotik-vpn-net; then
        log "Creating Docker network..."
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 || {
            log_error "Failed to create Docker network"
            exit 1
        }
    fi
    
    # Start services in order
    log "Starting database services..."
    docker compose -f docker-compose-mongodb.yml up -d || {
        log_error "Failed to start MongoDB"
        exit 1
    }
    
    docker compose -f docker-compose-redis.yml up -d || {
        log_error "Failed to start Redis"
        exit 1
    }
    
    # Wait for databases to be ready
    log "Waiting for databases to initialize..."
    sleep 30
    
    # Check database health
    local mongo_ready=false
    local redis_ready=false
    
    for i in {1..12}; do
        if docker exec mikrotik-mongodb mongosh --eval "db.runCommand('ping').ok" --quiet >/dev/null 2>&1; then
            mongo_ready=true
            break
        fi
        log "Waiting for MongoDB... (attempt $i/12)"
        sleep 5
    done
    
    for i in {1..12}; do
        if docker exec mikrotik-redis redis-cli --no-auth-warning ping >/dev/null 2>&1; then
            redis_ready=true
            break
        fi
        log "Waiting for Redis... (attempt $i/12)"
        sleep 5
    done
    
    if [ "$mongo_ready" = false ]; then
        log_warning "MongoDB may not be fully ready, but continuing..."
    fi
    
    if [ "$redis_ready" = false ]; then
        log_warning "Redis may not be fully ready, but continuing..."
    fi
    
    # Start VPN service
    log "Starting VPN service..."
    docker compose -f docker-compose-openvpn.yml up -d || {
        log_warning "OpenVPN failed to start, but continuing..."
    }
    
    # Start application
    log "Starting application..."
    docker compose -f docker-compose-app.yml up -d || {
        log_error "Failed to start application"
        exit 1
    }
    
    # Wait for application
    log "Waiting for application to start..."
    sleep 20
    
    # Start web server
    log "Starting web server..."
    docker compose -f docker-compose-nginx.yml up -d || {
        log_error "Failed to start web server"
        exit 1
    }
    
    # Wait for all services
    log "Waiting for all services to be ready..."
    sleep 15
    
    # Final health check
    if "$SCRIPT_DIR/health-check.sh" >/dev/null 2>&1; then
        log "✓ All services are running and healthy"
    else
        log_warning "Some services may need more time to start up"
    fi
}

# =============================================================================
# MAIN INSTALLATION PROCESS
# =============================================================================

main_installation() {
    log "==================================================================="
    log "Starting MikroTik VPN Management System Installation v2.2"
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
    phase9_finalization
    
    # Show completion message
    show_installation_complete
}

show_installation_complete() {
    clear
    
    # Get system info
    local system_ip
    system_ip=$(hostname -I | awk '{print $1}')
    
    echo -e "${GREEN}======================================================================${NC}"
    echo -e "${GREEN}    🎉 MikroTik VPN Management System Installation Complete! 🎉${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    echo
    echo -e "${CYAN}Installation Summary:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${YELLOW}Domain:${NC}           $DOMAIN_NAME"
    echo -e "${YELLOW}Server IP:${NC}        $system_ip"
    echo -e "${YELLOW}Admin Email:${NC}      $ADMIN_EMAIL"
    echo -e "${YELLOW}SSH Port:${NC}         $SSH_PORT"
    echo -e "${YELLOW}VPN Network:${NC}      $VPN_NETWORK"
    echo -e "${YELLOW}Install Date:${NC}     $(date)"
    echo
    echo -e "${CYAN}Access Points:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [[ "$DOMAIN_NAME" != "localhost" ]] && [[ ! "$DOMAIN_NAME" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${GREEN}Web Interface:${NC}    https://$DOMAIN_NAME"
        echo -e "${GREEN}HTTP Redirect:${NC}    http://$DOMAIN_NAME → https://$DOMAIN_NAME"
    else
        echo -e "${GREEN}Web Interface:${NC}    https://$system_ip"
        echo -e "${GREEN}Local Access:${NC}     http://localhost"
    fi
    echo -e "${GREEN}API Endpoint:${NC}     http://$system_ip/api"
    echo -e "${GREEN}Health Check:${NC}     http://$system_ip/health"
    echo -e "${GREEN}SSH Access:${NC}       Port $SSH_PORT"
    echo -e "${GREEN}OpenVPN:${NC}          $DOMAIN_NAME:1194 (UDP)"
    echo
    echo -e "${CYAN}Management Commands:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}System Manager:${NC}   sudo $SYSTEM_DIR/mikrotik-vpn-manager.sh"
    echo -e "${GREEN}System Status:${NC}    sudo systemctl status mikrotik-vpn"
    echo -e "${GREEN}Start Services:${NC}   sudo systemctl start mikrotik-vpn"
    echo -e "${GREEN}Stop Services:${NC}    sudo systemctl stop mikrotik-vpn"
    echo -e "${GREEN}View Logs:${NC}        sudo journalctl -u mikrotik-vpn -f"
    echo -e "${GREEN}Health Check:${NC}     sudo $SCRIPT_DIR/health-check.sh"
    echo
    echo -e "${CYAN}Database Access:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}MongoDB:${NC}          localhost:27017"
    echo -e "${GREEN}  Admin User:${NC}     admin"
    echo -e "${GREEN}  Admin Pass:${NC}     $MONGO_ROOT_PASSWORD"
    echo -e "${GREEN}Redis:${NC}            localhost:6379"
    echo -e "${GREEN}  Password:${NC}       $REDIS_PASSWORD"
    echo
    echo -e "${CYAN}Important Files:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}System Directory:${NC} $SYSTEM_DIR"
    echo -e "${GREEN}Configuration:${NC}    $SYSTEM_DIR/configs/"
    echo -e "${GREEN}VPN Clients:${NC}      $SYSTEM_DIR/clients/"
    echo -e "${GREEN}Backups:${NC}          $SYSTEM_DIR/backups/"
    echo -e "${GREEN}Logs:${NC}             $LOG_DIR"
    echo -e "${GREEN}Passwords:${NC}        $SYSTEM_DIR/configs/passwords.txt"
    echo
    echo -e "${RED}⚠️  IMPORTANT SECURITY NOTES:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${YELLOW}1.${NC} Passwords are saved in: $SYSTEM_DIR/configs/passwords.txt"
    echo -e "${YELLOW}2.${NC} Configure your domain's DNS to point to this server: $system_ip"
    echo -e "${YELLOW}3.${NC} Replace self-signed SSL certificate with Let's Encrypt"
    echo -e "${YELLOW}4.${NC} Review and customize firewall rules for your environment"
    echo -e "${YELLOW}5.${NC} Set up SSH key authentication and disable password auth"
    echo -e "${YELLOW}6.${NC} Change default database passwords"
    echo
    echo -e "${CYAN}Next Steps:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}1.${NC} Test the web interface: curl -k https://$system_ip"
    echo -e "${GREEN}2.${NC} Generate VPN client: sudo $SYSTEM_DIR/mikrotik-vpn-manager.sh vpn client1"
    echo -e "${GREEN}3.${NC} Configure DNS A record: $DOMAIN_NAME → $system_ip"
    echo -e "${GREEN}4.${NC} Set up Let's Encrypt: certbot --nginx -d $DOMAIN_NAME"
    echo -e "${GREEN}5.${NC} Review logs: sudo $SYSTEM_DIR/mikrotik-vpn-manager.sh logs all"
    echo
    echo -e "${BLUE}Quick Test Commands:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}System Status:${NC}    sudo $SYSTEM_DIR/mikrotik-vpn-manager.sh status"
    echo -e "${GREEN}Health Check:${NC}     sudo $SCRIPT_DIR/health-check.sh"
    echo -e "${GREEN}Web Test:${NC}         curl -k http://localhost/health"
    echo -e "${GREEN}Container Status:${NC} docker ps"
    echo
    echo -e "${GREEN}Installation log: $LOG_DIR/setup.log${NC}"
    echo
    echo -e "${GREEN}======================================================================${NC}"
    echo -e "${GREEN}         System is ready! Run the system manager to get started:${NC}"
    echo -e "${GREEN}              sudo $SYSTEM_DIR/mikrotik-vpn-manager.sh${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    echo
}

# =============================================================================
# SCRIPT MAIN LOGIC
# =============================================================================

print_banner() {
    clear
    echo -e "${CYAN}===================================================================${NC}"
    echo -e "${CYAN}       MikroTik VPN Management System - Installer v2.2${NC}"
    echo -e "${CYAN}       Complete VPN-based Hotspot Management Solution${NC}"
    echo -e "${CYAN}===================================================================${NC}"
    echo -e "${BLUE}       Automated Installation for Ubuntu 22.04 LTS${NC}"
    echo -e "${BLUE}       Created by: AI Assistant | Version: 2.2${NC}"
    echo -e "${CYAN}===================================================================${NC}"
    echo
}

check_system_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [ ! -f /etc/lsb-release ] || ! grep -q "Ubuntu" /etc/lsb-release; then
        log_error "This installer is designed for Ubuntu. Current OS may not be supported."
        read -p "Continue anyway? (y/n): " continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check available disk space (minimum 10GB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    required_space=$((10 * 1024 * 1024)) # 10GB in KB
    
    if [ "$available_space" -lt "$required_space" ]; then
        log_error "Insufficient disk space. Required: 10GB, Available: $(($available_space / 1024 / 1024))GB"
        exit 1
    fi
    
    # Check available memory (minimum 2GB)
    total_mem=$(free | awk '/^Mem:/ {print $2}')
    required_mem=$((2 * 1024 * 1024)) # 2GB in KB
    
    if [ "$total_mem" -lt "$required_mem" ]; then
        log_warning "Low memory detected. Recommended: 4GB+, Available: $(($total_mem / 1024 / 1024))GB"
        read -p "Continue with low memory? (y/n): " continue_low_mem
        if [[ ! $continue_low_mem =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    log "✓ System requirements check passed"
}

# Error handling
handle_error() {
    local line_number=$1
    local error_code=$2
    log_error "Installation failed at line $line_number with exit code $error_code"
    log_error "Check the log file for details: $LOG_DIR/setup.log"
    
    echo
    echo -e "${RED}======================================================================${NC}"
    echo -e "${RED}                    INSTALLATION FAILED${NC}"
    echo -e "${RED}======================================================================${NC}"
    echo
    echo -e "${YELLOW}Error occurred at line: $line_number${NC}"
    echo -e "${YELLOW}Error code: $error_code${NC}"
    echo
    echo -e "${CYAN}Troubleshooting steps:${NC}"
    echo "1. Check the log file: $LOG_DIR/setup.log"
    echo "2. Ensure you have a stable internet connection"
    echo "3. Make sure you have sufficient disk space and memory"
    echo "4. Try running the installer again"
    echo "5. Check if any services are conflicting (port 80, 443, etc.)"
    echo
    echo -e "${CYAN}To retry installation:${NC}"
    echo "sudo ./$(basename "$0")"
    echo
    exit $error_code
}

# Set up error handling
trap 'handle_error $LINENO $?' ERR

# Main script execution
main() {
    # Check if running as root
    check_root
    
    print_banner
    
    # Check system requirements
    check_system_requirements
    
    # Create initial directories early
    create_initial_directories
    
    # Check if system is already installed
    if [ -d "$SYSTEM_DIR" ] && [ "$(ls -A "$SYSTEM_DIR" 2>/dev/null)" ]; then
        echo -e "${YELLOW}Existing installation detected!${NC}"
        echo
        echo "Options:"
        echo "1. Run system manager (if installation is complete)"
        echo "2. Force complete reinstallation"
        echo "3. Exit"
        echo
        read -p "Select option (1-3): " existing_choice
        
        case $existing_choice in
            1)
                if check_installation; then
                    echo -e "${GREEN}Starting system manager...${NC}"
                    exec "$SYSTEM_DIR/mikrotik-vpn-manager.sh"
                else
                    log_warning "Installation appears incomplete. Proceeding with cleanup and reinstall..."
                    BACKUP_CONFIG_EXISTS=false
                    cleanup_incomplete_installation
                    main_installation
                fi
                ;;
            2)
                echo
                echo -e "${RED}⚠️  WARNING: This will completely reinstall the system!${NC}"
                echo -e "${RED}   All data, configurations, and VPN clients will be lost!${NC}"
                echo
                read -p "Are you absolutely sure? (type 'yes' to confirm): " confirm
                if [ "$confirm" = "yes" ]; then
                    cleanup_incomplete_installation
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
                log_error "Invalid option"
                exit 1
                ;;
        esac
    else
        # Fresh installation
        echo -e "${GREEN}Starting fresh installation...${NC}"
        echo
        main_installation
    fi
}

# Handle command line arguments
case "${1:-}" in
    "--help"|"-h")
        echo "MikroTik VPN Management System Installer v2.2"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help              Show this help message"
        echo "  --force-reinstall   Force complete reinstallation"
        echo "  --version           Show version information"
        echo "  --check             Check system requirements only"
        echo
        echo "For system management after installation:"
        echo "  /opt/mikrotik-vpn/mikrotik-vpn-manager.sh"
        echo
        echo "Examples:"
        echo "  sudo $0                    # Interactive installation"
        echo "  sudo $0 --force-reinstall  # Force reinstall"
        echo "  sudo $0 --check            # Check requirements"
        exit 0
        ;;
    "--version"|"-v")
        echo "MikroTik VPN Management System Installer"
        echo "Version: 2.2"
        echo "Compatible: Ubuntu 22.04 LTS"
        echo "Build date: $(date)"
        echo "Features: Docker, OpenVPN, MongoDB, Redis, Nginx, Node.js"
        exit 0
        ;;
    "--check")
        check_root
        check_system_requirements
        echo -e "${GREEN}✓ System requirements check passed${NC}"
        exit 0
        ;;
    "--force-reinstall")
        check_root
        create_initial_directories
        cleanup_incomplete_installation
        main_installation
        ;;
    "")
        main
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script (Fixed)
# Version: 2.2
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

# Basic utility functions (defined first)
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Logging functions
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${msg}${NC}"
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log"
    fi
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}${msg}${NC}" >&2
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log"
    fi
}

log_warning() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1"
    echo -e "${YELLOW}${msg}${NC}"
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log"
    fi
}

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1"
    echo -e "${BLUE}${msg}${NC}"
    
    # Only write to log file if directory exists
    if [ -d "$(dirname "$LOG_DIR/setup.log")" ]; then
        echo "$msg" >> "$LOG_DIR/setup.log"
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run this script as root (use sudo)"
        exit 1
    fi
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
    touch "$LOG_DIR/setup.log"
    chmod 644 "$LOG_DIR/setup.log"
    
    # Set proper permissions
    chown -R root:root "$SYSTEM_DIR" "$LOG_DIR"
    chmod -R 755 "$SYSTEM_DIR" "$LOG_DIR"
    chmod 700 "$SYSTEM_DIR/configs"
    
    echo "✓ System directories created successfully"
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
        echo "❌ Installation appears incomplete. Missing: ${missing_files[*]}"
        return 1
    fi
    
    return 0
}

# Function to clean up incomplete installation
cleanup_incomplete_installation() {
    log "Cleaning up incomplete installation..."
    
    # Stop any running containers if Docker is available
    if command -v docker >/dev/null 2>&1; then
        docker stop $(docker ps -q --filter name=mikrotik) 2>/dev/null || true
        docker rm $(docker ps -aq --filter name=mikrotik) 2>/dev/null || true
        docker network rm mikrotik-vpn-net 2>/dev/null || true
    else
        log_warning "Docker not installed yet, skipping container cleanup"
    fi
    
    # Remove systemd service if exists
    if [ -f "/etc/systemd/system/mikrotik-vpn.service" ]; then
        systemctl stop mikrotik-vpn 2>/dev/null || true
        systemctl disable mikrotik-vpn 2>/dev/null || true
        rm -f /etc/systemd/system/mikrotik-vpn.service
        systemctl daemon-reload
    fi
    
    # Backup existing config if present
    if [ -f "$SYSTEM_DIR/configs/setup.env" ]; then
        log "Backing up existing configuration..."
        cp "$SYSTEM_DIR/configs/setup.env" "/tmp/mikrotik-vpn-backup.env" 2>/dev/null || true
        BACKUP_CONFIG_EXISTS=true
    fi
    
    # Remove incomplete installation but keep logs for debugging
    if [ -d "$SYSTEM_DIR" ]; then
        rm -rf "$SYSTEM_DIR" 2>/dev/null || true
    fi
    
    log "Cleanup completed"
}

# Function to restore previous configuration
restore_previous_config() {
    if [ "$BACKUP_CONFIG_EXISTS" = "true" ] && [ -f "/tmp/mikrotik-vpn-backup.env" ]; then
        log "Restoring previous configuration..."
        mkdir -p "$SYSTEM_DIR/configs"
        cp "/tmp/mikrotik-vpn-backup.env" "$SYSTEM_DIR/configs/setup.env"
        chmod 600 "$SYSTEM_DIR/configs/setup.env"
        
        # Source the configuration
        source "/tmp/mikrotik-vpn-backup.env"
        
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
        
        # Basic domain validation - allow localhost and IP for testing
        if [[ $DOMAIN_NAME == "localhost" ]] || \
           [[ $DOMAIN_NAME =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || \
           [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
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
        ADMIN_EMAIL=$(echo "$ADMIN_EMAIL" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
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
    
    # Database passwords
    echo
    echo "Database Configuration:"
    echo "Setting default passwords (you can change them later)"
    
    # Generate secure random passwords
    MONGO_ROOT_PASSWORD="MongoRoot$(openssl rand -base64 12 | tr -d '/')"
    MONGO_APP_PASSWORD="MongoApp$(openssl rand -base64 12 | tr -d '/')"
    REDIS_PASSWORD="Redis$(openssl rand -base64 12 | tr -d '/')"
    
    echo "Generated secure passwords for databases"
    
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
    export DEBIAN_FRONTEND=noninteractive
    apt update && apt upgrade -y
    
    log "Setting timezone to $TIMEZONE..."
    timedatectl set-timezone "$TIMEZONE" || log_warning "Failed to set timezone"
    
    log "Installing essential packages..."
    apt install -y \
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
        openssl || {
            log_error "Failed to install essential packages"
            exit 1
        }
    
    # Create system user for application
    if ! id "mikrotik-vpn" &>/dev/null; then
        log "Creating mikrotik-vpn system user..."
        useradd -r -m -s /bin/bash -d /home/mikrotik-vpn mikrotik-vpn || {
            log_error "Failed to create system user"
            exit 1
        }
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
        log "Docker is already installed"
        docker --version
    else
        log "Installing Docker..."
        
        # Remove old versions
        apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Add Docker's official GPG key
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg || {
            log_error "Failed to add Docker GPG key"
            exit 1
        }
        
        # Add Docker repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker Engine
        apt update
        apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || {
            log_error "Failed to install Docker"
            exit 1
        }
    fi
    
    # Configure Docker daemon
    create_docker_config
    
    log "Adding users to docker group..."
    if [ -n "${SUDO_USER:-}" ]; then
        usermod -aG docker "$SUDO_USER" || log_warning "Failed to add $SUDO_USER to docker group"
    fi
    usermod -aG docker mikrotik-vpn || log_warning "Failed to add mikrotik-vpn to docker group"
    
    log "Starting and enabling Docker..."
    systemctl enable docker
    systemctl start docker || {
        log_error "Failed to start Docker"
        exit 1
    }
    
    # Wait for Docker to be ready
    sleep 5
    
    log "Creating Docker network..."
    if ! docker network ls | grep -q mikrotik-vpn-net; then
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 || {
            log_warning "Failed to create Docker network, will retry later"
        }
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
    
    log "Downloading and setting up Easy-RSA..."
    cd "$SYSTEM_DIR/openvpn"
    
    # Download Easy-RSA
    if [ ! -f "EasyRSA-3.1.0.tgz" ]; then
        wget -q https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz || {
            log_error "Failed to download Easy-RSA"
            exit 1
        }
    fi
    
    tar xzf EasyRSA-3.1.0.tgz
    rm -rf easy-rsa 2>/dev/null || true
    mv EasyRSA-3.1.0 easy-rsa
    rm -f EasyRSA-3.1.0.tgz
    
    # Setup Easy-RSA configuration
    cd easy-rsa
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
    if command -v openvpn >/dev/null 2>&1; then
        openvpn --genkey secret ta.key
    else
        # Install OpenVPN for key generation
        apt install -y openvpn
        openvpn --genkey secret ta.key
    fi
    
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
    cat << EOF > "$SYSTEM_DIR/docker-compose-openvpn.yml"
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
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/openvpn"
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
    cat << EOF > "$SYSTEM_DIR/docker-compose-mongodb.yml"
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
    cat << EOF > "$SYSTEM_DIR/redis/redis.conf"
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
    cat << EOF > "$SYSTEM_DIR/docker-compose-redis.yml"
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
    cat << EOF > "$SYSTEM_DIR/nginx/nginx.conf"
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

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
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
    
    # Redirect to HTTPS if domain matches
    location / {
        if (\$host = $DOMAIN_NAME) {
            return 301 https://\$server_name\$request_uri;
        }
        return 200 "MikroTik VPN Management System - HTTP";
        add_header Content-Type text/plain;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME localhost;

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
    cat << EOF > "$SYSTEM_DIR/docker-compose-nginx.yml"
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
    cat << EOF > "$SYSTEM_DIR/nginx/html/index.html"
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
            <p><strong>Version:</strong> 2.2</p>
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
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SYSTEM_DIR/nginx/ssl/privkey.pem" \
        -out "$SYSTEM_DIR/nginx/ssl/fullchain.pem" \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
        -addext "subjectAltName=DNS:$DOMAIN_NAME,DNS:localhost" 2>/dev/null || {
        
        # Fallback for older OpenSSL versions
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SYSTEM_DIR/nginx/ssl/privkey.pem" \
            -out "$SYSTEM_DIR/nginx/ssl/fullchain.pem" \
            -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME"
    }
    
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
        if node -e "process.exit(parseInt(process.version.slice(1)) >= 16 ? 0 : 1)"; then
            log "Node.js version is suitable"
            return
        else
            log "Node.js version is too old, installing newer version..."
        fi
    fi
    
    # Install Node.js 20 LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - || {
        log_error "Failed to add NodeSource repository"
        exit 1
    }
    
    apt-get install -y nodejs || {
        log_error "Failed to install Node.js"
        exit 1
    }
    
    # Verify installation
    node --version
    npm --version
}

create_application_structure() {
    # Create application directory structure
    mkdir -p "$SYSTEM_DIR/app"/{src,config,public,views,routes,models,controllers,middleware,utils}
    
    # Create package.json
    cat << EOF > "$SYSTEM_DIR/app/package.json"
{
  "name": "mikrotik-vpn-management",
  "version": "2.2.0",
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

    # Create main server file
    cat << 'EOF' > "$SYSTEM_DIR/app/server.js"
const express = require('express');
const mongoose = require('mongoose');
const redis = require('redis');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
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
        origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : "*",
        methods: ["GET", "POST"]
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
            filename: '/var/log/mikrotik-vpn/app.log',
            maxsize: 10485760, // 10MB
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

// Database connections
let mongoClient = null;
let redisClient = null;

const connectMongoDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        mongoClient = mongoose.connection;
        logger.info('Connected to MongoDB');
    } catch (error) {
        logger.error('MongoDB connection error:', error);
        throw error;
    }
};

const connectRedis = async () => {
    try {
        redisClient = redis.createClient({
            url: `redis://default:${process.env.REDIS_PASSWORD}@redis:6379`,
            socket: {
                connectTimeout: 5000,
                commandTimeout: 5000,
            },
            retry_strategy: function (options) {
                if (options.error && options.error.code === 'ECONNREFUSED') {
                    return new Error('The Redis server refused the connection');
                }
                if (options.total_retry_time > 1000 * 60 * 60) {
                    return new Error('Retry time exhausted');
                }
                if (options.attempt > 10) {
                    return undefined;
                }
                return Math.min(options.attempt * 100, 3000);
            }
        });
        
        await redisClient.connect();
        logger.info('Connected to Redis');
        return redisClient;
    } catch (error) {
        logger.error('Redis connection error:', error);
        throw error;
    }
};

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware setup
app.use(helmet({
    contentSecurityPolicy: false, // Disable for development
}));
app.use(cors());
app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use('/static', express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/health', (req, res) => {
    const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        version: '2.2.0'
    };
    
    // Check database connections
    health.mongodb = mongoClient && mongoClient.readyState === 1 ? 'connected' : 'disconnected';
    health.redis = redisClient && redisClient.isOpen ? 'connected' : 'disconnected';
    
    res.status(200).json(health);
});

// Basic API routes
app.get('/', (req, res) => {
    res.json({ 
        message: 'MikroTik VPN Management System API',
        version: '2.2.0',
        status: 'running',
        timestamp: new Date().toISOString()
    });
});

app.get('/api', (req, res) => {
    res.json({
        name: 'MikroTik VPN Management API',
        version: '2.2.0',
        endpoints: {
            health: '/health',
            status: '/api/status',
            docs: '/api/docs'
        }
    });
});

app.get('/api/status', (req, res) => {
    res.json({
        system: 'MikroTik VPN Management System',
        status: 'operational',
        version: '2.2.0',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        connections: {
            mongodb: mongoClient ? mongoClient.readyState : 0,
            redis: redisClient ? redisClient.isOpen : false
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!',
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: 'The requested resource was not found',
        path: req.path,
        timestamp: new Date().toISOString()
    });
});

// Socket.IO for real-time features
io.on('connection', (socket) => {
    logger.info(`Client connected: ${socket.id}`);
    
    socket.emit('welcome', {
        message: 'Connected to MikroTik VPN Management System',
        timestamp: new Date().toISOString()
    });
    
    socket.on('disconnect', (reason) => {
        logger.info(`Client disconnected: ${socket.id}, reason: ${reason}`);
    });
    
    socket.on('error', (error) => {
        logger.error(`Socket error for ${socket.id}:`, error);
    });
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received, shutting down gracefully`);
    
    server.close(async () => {
        logger.info('HTTP server closed');
        
        try {
            if (mongoClient) {
                await mongoose.connection.close();
                logger.info('MongoDB connection closed');
            }
            
            if (redisClient) {
                await redisClient.quit();
                logger.info('Redis connection closed');
            }
        } catch (error) {
            logger.error('Error during graceful shutdown:', error);
        }
        
        process.exit(0);
    });
    
    // Force close after 10 seconds
    setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
});

// Start server
const startServer = async () => {
    try {
        // Connect to databases
        await connectMongoDB();
        await connectRedis();
        
        const PORT = process.env.PORT || 3000;
        server.listen(PORT, '0.0.0.0', () => {
            logger.info(`🚀 MikroTik VPN Management System started on port ${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
            logger.info(`Health check: http://localhost:${PORT}/health`);
        });
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
};

startServer();
EOF

    # Create environment configuration
    cat << EOF > "$SYSTEM_DIR/app/.env"
# Application Configuration
NODE_ENV=production
PORT=3000

# Database Configuration
MONGODB_URI=mongodb://mikrotik_app:$MONGO_APP_PASSWORD@mongodb:27017/mikrotik_vpn?authSource=mikrotik_vpn
REDIS_PASSWORD=$REDIS_PASSWORD

# Session Configuration
SESSION_SECRET=$(openssl rand -base64 32)

# JWT Configuration
JWT_SECRET=$(openssl rand -base64 64)

# Security
ALLOWED_ORIGINS=https://$DOMAIN_NAME,http://localhost:3000

# Email Configuration (configure later)
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
    cat << EOF > "$SYSTEM_DIR/docker-compose-app.yml"
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
      - /usr/src/app/node_modules
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
      start_period: 60s

networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create Dockerfile
    cat << EOF > "$SYSTEM_DIR/app/Dockerfile"
FROM node:20-alpine

# Install system dependencies
RUN apk add --no-cache curl bash

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application files
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mikrotik -u 1001 -G nodejs

# Create necessary directories and set permissions
RUN mkdir -p logs public && \
    chown -R mikrotik:nodejs /usr/src/app && \
    chmod -R 755 /usr/src/app

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

    # Set proper ownership
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/app"
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
    cat << 'EOF' > "$SYSTEM_DIR/mikrotik-vpn-manager.sh"
#!/bin/bash
# MikroTik VPN System Master Management Script v2.2

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
    clear
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}              MikroTik VPN Management System v2.2${NC}"
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
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}' | xargs)"
    
    # Memory usage
    if command -v free >/dev/null; then
        echo "Memory Usage: $(free -h | awk '/^Mem:/ {printf "Used: %s / Total: %s (%.1f%%)", $3, $2, $3/$2*100}')"
    fi
    
    # Disk usage
    echo "Disk Usage: $(df -h / | awk 'NR==2 {printf "Used: %s / Total: %s (%s)", $3, $2, $5}')"
    echo
    
    # Docker services status
    echo -e "${PURPLE}Docker Services:${NC}"
    if command -v docker >/dev/null; then
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep mikrotik || echo "No MikroTik services running"
    else
        echo "Docker not available"
    fi
    echo
    
    # VPN status
    echo -e "${PURPLE}VPN Status:${NC}"
    if docker ps | grep -q mikrotik-openvpn; then
        echo "OpenVPN: Running"
        if docker exec mikrotik-openvpn test -f /var/log/openvpn/status.log 2>/dev/null; then
            clients=$(docker exec mikrotik-openvpn cat /var/log/openvpn/status.log 2>/dev/null | grep -c "CLIENT_LIST" || echo "0")
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
    
    # Web status
    echo -e "${PURPLE}Web Server Status:${NC}"
    if docker ps | grep -q mikrotik-nginx; then
        echo "Nginx: Running"
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
    
    cd "$SYSTEM_DIR" || {
        print_error "Cannot access system directory: $SYSTEM_DIR"
        return 1
    }
    
    # Create Docker network if not exists
    if ! docker network ls | grep -q mikrotik-vpn-net; then
        print_status "Creating Docker network..."
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16 2>/dev/null || true
    fi
    
    # Start services in dependency order
    print_status "Starting databases..."
    docker compose -f docker-compose-mongodb.yml up -d
    docker compose -f docker-compose-redis.yml up -d
    
    # Wait for databases
    print_status "Waiting for databases to be ready..."
