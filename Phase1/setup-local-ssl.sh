#!/bin/bash
# =============================================================================
# Local SSL Certificate Setup Script for MikroTik VPN Test Environment
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║       Local SSL Certificate Setup for MikroTik VPN           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Check if mkcert is already installed
if command -v mkcert &> /dev/null; then
    log "mkcert is already installed"
    mkcert_version=$(mkcert -version 2>/dev/null || echo "unknown")
    log_info "Current version: $mkcert_version"
else
    log "Installing mkcert..."
    
    # Download mkcert
    wget -q --show-progress https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64 \
        -O /tmp/mkcert || {
        log_error "Failed to download mkcert"
        exit 1
    }
    
    # Make executable and move to bin
    chmod +x /tmp/mkcert
    sudo mv /tmp/mkcert /usr/local/bin/mkcert
    
    log "mkcert installed successfully"
fi

# Install mkcert root CA
log "Installing mkcert root CA..."
export CAROOT="$HOME/.local/share/mkcert"
mkcert -install || {
    log_warning "Failed to install CA, continuing anyway..."
}

# Backup existing certificates if they exist
if [[ -f "/opt/mikrotik-vpn/nginx/ssl/fullchain.pem" ]]; then
    log "Backing up existing certificates..."
    timestamp=$(date +%Y%m%d_%H%M%S)
    mkdir -p /opt/mikrotik-vpn/nginx/ssl/backup
    cp /opt/mikrotik-vpn/nginx/ssl/*.pem /opt/mikrotik-vpn/nginx/ssl/backup/ 2>/dev/null || true
    log_info "Backup saved to: /opt/mikrotik-vpn/nginx/ssl/backup/"
fi

# Get system information
HOSTNAME=$(hostname)
PRIMARY_IP=$(hostname -I | awk '{print $1}')
ALL_IPS=$(hostname -I)

log "System Information:"
log_info "  Hostname: $HOSTNAME"
log_info "  Primary IP: $PRIMARY_IP"
log_info "  All IPs: $ALL_IPS"

# Change to SSL directory
cd /opt/mikrotik-vpn/nginx/ssl || {
    log_error "SSL directory not found: /opt/mikrotik-vpn/nginx/ssl"
    exit 1
}

# Generate certificate with all possible names
log "Generating SSL certificate..."
log_info "This certificate will be valid for:"
log_info "  - localhost"
log_info "  - 127.0.0.1"
log_info "  - ::1"
log_info "  - $HOSTNAME"
log_info "  - $PRIMARY_IP"
log_info "  - netkarn.local"
log_info "  - *.netkarn.local"

# Create certificate
mkcert -cert-file fullchain.pem -key-file privkey.pem \
    localhost 127.0.0.1 ::1 \
    "$HOSTNAME" "$HOSTNAME.local" \
    $PRIMARY_IP \
    netkarn.local "*.netkarn.local" \
    admin.netkarn.local monitor.netkarn.local || {
    log_error "Failed to generate certificate"
    exit 1
}

# Set proper permissions
log "Setting certificate permissions..."
chmod 644 fullchain.pem
chmod 600 privkey.pem
chown root:root *.pem

# Verify certificate
log "Verifying certificate..."
if openssl x509 -in fullchain.pem -noout -text &>/dev/null; then
    log "Certificate is valid"
    
    # Show certificate details
    echo
    log_info "Certificate Details:"
    openssl x509 -in fullchain.pem -noout -subject -issuer -dates | sed 's/^/  /'
    
    echo
    log_info "Alternative Names:"
    openssl x509 -in fullchain.pem -noout -text | \
        grep -A1 "Subject Alternative Name" | tail -1 | \
        sed 's/DNS://g' | sed 's/,/\n  /g' | sed 's/^/  /'
else
    log_error "Certificate verification failed"
    exit 1
fi

# Restart nginx
log "Restarting nginx..."
if docker ps | grep -q mikrotik-nginx; then
    docker restart mikrotik-nginx || {
        log_error "Failed to restart nginx"
        log_info "Try manually: docker restart mikrotik-nginx"
    }
    
    # Wait for nginx to be ready
    sleep 3
    
    # Check if nginx is running
    if docker ps | grep -q mikrotik-nginx; then
        log "Nginx restarted successfully"
    else
        log_error "Nginx is not running"
    fi
else
    log_warning "Nginx container not found or not running"
fi

# Create hosts file entries
echo
log "Adding local domain entries to /etc/hosts..."
cp /etc/hosts /etc/hosts.bak

# Remove old entries
sed -i '/netkarn.local/d' /etc/hosts

# Add new entries
cat >> /etc/hosts << EOF

# MikroTik VPN Local Development
$PRIMARY_IP    netkarn.local
$PRIMARY_IP    admin.netkarn.local
$PRIMARY_IP    monitor.netkarn.local
EOF

log "Hosts file updated"

# Show access information
echo
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Completed!                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo
log_info "You can now access the system using:"
echo
echo "  Local Domain Access:"
echo "    Main:     https://netkarn.local:9443"
echo "    Admin:    https://admin.netkarn.local:9443"
echo "    Monitor:  https://monitor.netkarn.local:9443"
echo
echo "  IP Address Access:"
echo "    Main:     https://$PRIMARY_IP:9443"
echo "    HTTP:     http://$PRIMARY_IP:9080"
echo
echo "  Localhost Access:"
echo "    Main:     https://localhost:9443"
echo "    HTTP:     http://localhost:9080"
echo
log_info "Note: The certificate is trusted locally. No browser warnings!"
echo

# Create test script
cat > /opt/mikrotik-vpn/test-ssl.sh << 'EOF'
#!/bin/bash
echo "Testing SSL connections..."
echo

# Test URLs
urls=(
    "https://localhost:9443/health"
    "https://netkarn.local:9443/health"
    "https://admin.netkarn.local:9443/health"
)

for url in "${urls[@]}"; do
    echo -n "Testing $url ... "
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|301\|302"; then
        echo "✓ OK"
    else
        echo "✗ Failed"
    fi
done
EOF

chmod +x /opt/mikrotik-vpn/test-ssl.sh

log_info "Run '/opt/mikrotik-vpn/test-ssl.sh' to test SSL connections"

# Completion
echo
log "SSL setup completed successfully! 🎉"
