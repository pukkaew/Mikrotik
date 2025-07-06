#!/bin/bash
# =============================================================================
# Local SSL Certificate Setup Script for MikroTik VPN Test Environment
# Version: 2.0 - Enhanced with validation, browser instructions, and testing
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SSL_DIR="/opt/mikrotik-vpn/nginx/ssl"
BACKUP_DIR="$SSL_DIR/backup"
CAROOT="${CAROOT:-$HOME/.local/share/mkcert}"
MKCERT_VERSION="v1.4.4"

# Functions
log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Print header
print_header() {
    clear
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     Enhanced Local SSL Certificate Setup for MikroTik VPN     ║"
    echo "║                        Version 2.0                            ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check for required commands
    local required_commands=("wget" "openssl" "docker")
    for cmd in "${required_commands[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            log_error "Required command '$cmd' not found. Please install it first."
            exit 1
        fi
    done
    
    # Check if Docker is running
    if ! docker ps &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Check if nginx container exists
    if ! docker ps -a --format '{{.Names}}' | grep -q mikrotik-nginx; then
        log_warning "Nginx container 'mikrotik-nginx' not found"
        log_info "Make sure the MikroTik VPN system is installed"
    fi
    
    log_success "All requirements met"
}

# Install or update mkcert
install_mkcert() {
    if command -v mkcert &> /dev/null; then
        local current_version=$(mkcert -version 2>/dev/null || echo "unknown")
        log "mkcert is already installed (version: $current_version)"
        
        read -p "Do you want to update mkcert? (y/n): " update_choice
        if [[ ! $update_choice =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    log "Installing mkcert..."
    
    # Detect architecture
    local arch=""
    case $(uname -m) in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        *) log_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    
    # Download mkcert
    local download_url="https://github.com/FiloSottile/mkcert/releases/download/${MKCERT_VERSION}/mkcert-${MKCERT_VERSION}-linux-${arch}"
    
    if ! wget -q --show-progress "$download_url" -O /tmp/mkcert; then
        log_error "Failed to download mkcert"
        exit 1
    fi
    
    # Install mkcert
    chmod +x /tmp/mkcert
    sudo mv /tmp/mkcert /usr/local/bin/mkcert
    
    # Verify installation
    if mkcert -version &> /dev/null; then
        log_success "mkcert installed successfully ($(mkcert -version))"
    else
        log_error "mkcert installation verification failed"
        exit 1
    fi
}

# Setup mkcert CA with enhanced error handling
setup_mkcert_ca() {
    log "Setting up mkcert Certificate Authority..."
    
    # Set CAROOT
    export CAROOT="$HOME/.local/share/mkcert"
    mkdir -p "$CAROOT"
    
    # Install CA
    if ! mkcert -install; then
        log_warning "Failed to install CA automatically, trying manual approach..."
        
        # Generate CA if not exists
        if [[ ! -f "$CAROOT/rootCA.pem" ]]; then
            mkcert -CAROOT || {
                log_error "Failed to generate CA"
                exit 1
            }
        fi
    fi
    
    # Verify CA installation
    if [[ -f "$CAROOT/rootCA.pem" ]]; then
        log_success "mkcert CA is installed"
        log_info "CA location: $CAROOT/rootCA.pem"
        
        # Display CA info
        log_info "CA Certificate Info:"
        openssl x509 -in "$CAROOT/rootCA.pem" -noout -subject -issuer | sed 's/^/  /'
    else
        log_error "CA installation failed"
        exit 1
    fi
}

# Backup existing certificates with versioning
backup_certificates() {
    if [[ ! -f "$SSL_DIR/fullchain.pem" ]]; then
        log_info "No existing certificates to backup"
        return 0
    fi
    
    log "Backing up existing certificates..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$BACKUP_DIR/ssl_backup_$timestamp"
    
    # Create versioned backup directory
    mkdir -p "$backup_path"
    
    # Copy certificates with metadata
    cp "$SSL_DIR/fullchain.pem" "$backup_path/" 2>/dev/null || true
    cp "$SSL_DIR/privkey.pem" "$backup_path/" 2>/dev/null || true
    
    # Save certificate information
    if [[ -f "$SSL_DIR/fullchain.pem" ]]; then
        openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -text > "$backup_path/cert_info.txt" 2>/dev/null || true
        openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -subject -issuer -dates > "$backup_path/cert_summary.txt" 2>/dev/null || true
    fi
    
    # Create backup manifest
    cat > "$backup_path/manifest.txt" << EOF
Backup Date: $(date)
Backup Type: SSL Certificate
Original Location: $SSL_DIR
Certificate Subject: $(openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -subject 2>/dev/null || echo "Unknown")
Certificate Issuer: $(openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -issuer 2>/dev/null || echo "Unknown")
Certificate Expiry: $(openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -enddate 2>/dev/null || echo "Unknown")
EOF
    
    # Keep only last 5 backups
    if [[ -d "$BACKUP_DIR" ]]; then
        local backup_count=$(ls -d "$BACKUP_DIR"/ssl_backup_* 2>/dev/null | wc -l)
        if [[ $backup_count -gt 5 ]]; then
            ls -dt "$BACKUP_DIR"/ssl_backup_* | tail -n +6 | xargs -r rm -rf
            log_info "Cleaned old backups (kept last 5)"
        fi
    fi
    
    log_success "Backup saved to: $backup_path"
}

# Get system information with enhanced detection
get_system_info() {
    log "Gathering system information..."
    
    # Hostname
    HOSTNAME=$(hostname)
    
    # Get all IP addresses
    PRIMARY_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}')
    ALL_IPS=$(hostname -I 2>/dev/null || ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
    
    # Get Docker network IPs
    DOCKER_IPS=""
    if command -v docker &> /dev/null; then
        DOCKER_IPS=$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || true)
    fi
    
    log_info "System Information:"
    log_info "  Hostname: $HOSTNAME"
    log_info "  Primary IP: $PRIMARY_IP"
    log_info "  All IPs: $(echo $ALL_IPS | tr '\n' ' ')"
    [[ -n "$DOCKER_IPS" ]] && log_info "  Docker Gateway: $DOCKER_IPS"
}

# Generate SSL certificate with enhanced options
generate_certificate() {
    log "Generating SSL certificate..."
    
    # Ensure SSL directory exists
    mkdir -p "$SSL_DIR"
    cd "$SSL_DIR"
    
    # Build certificate parameters
    local cert_params=(
        "-cert-file" "fullchain.pem"
        "-key-file" "privkey.pem"
        "localhost"
        "127.0.0.1"
        "::1"
        "$HOSTNAME"
        "$HOSTNAME.local"
        "$PRIMARY_IP"
    )
    
    # Add all system IPs
    for ip in $ALL_IPS; do
        if [[ ! " ${cert_params[@]} " =~ " ${ip} " ]]; then
            cert_params+=("$ip")
        fi
    done
    
    # Add Docker IPs if available
    if [[ -n "$DOCKER_IPS" ]]; then
        cert_params+=("$DOCKER_IPS")
    fi
    
    # Add custom domains
    cert_params+=(
        "netkarn.local"
        "*.netkarn.local"
        "admin.netkarn.local"
        "monitor.netkarn.local"
        "api.netkarn.local"
    )
    
    log_info "Certificate will be valid for:"
    for name in "${cert_params[@]:2}"; do
        echo "  - $name"
    done
    
    # Generate certificate
    if ! mkcert "${cert_params[@]}"; then
        log_error "Failed to generate certificate"
        exit 1
    fi
    
    # Set proper permissions
    chmod 644 fullchain.pem
    chmod 600 privkey.pem
    chown root:root *.pem
    
    log_success "Certificate generated successfully"
}

# Validate SSL certificate with detailed checks
validate_certificate() {
    log "Validating SSL certificate..."
    
    if [[ ! -f "$SSL_DIR/fullchain.pem" ]]; then
        log_error "Certificate file not found: $SSL_DIR/fullchain.pem"
        return 1
    fi
    
    # Basic validation
    if ! openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -text &>/dev/null; then
        log_error "Certificate validation failed - invalid format"
        return 1
    fi
    
    # Check expiry
    local expiry_date=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -enddate | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    if [[ $days_left -lt 0 ]]; then
        log_error "Certificate has expired!"
        return 1
    elif [[ $days_left -lt 30 ]]; then
        log_warning "Certificate expires in $days_left days"
    else
        log_info "Certificate valid for $days_left more days"
    fi
    
    # Display certificate details
    echo
    log_info "Certificate Details:"
    openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -subject -issuer -dates | sed 's/^/  /'
    
    echo
    log_info "Subject Alternative Names:"
    openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -text | \
        grep -A1 "Subject Alternative Name" | tail -1 | \
        sed 's/DNS://g' | sed 's/IP Address://g' | sed 's/,/\n  /g' | sed 's/^/  /'
    
    # Verify private key matches certificate
    local cert_modulus=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -noout -modulus | md5sum)
    local key_modulus=$(openssl rsa -in "$SSL_DIR/privkey.pem" -noout -modulus 2>/dev/null | md5sum)
    
    if [[ "$cert_modulus" != "$key_modulus" ]]; then
        log_error "Certificate and private key do not match!"
        return 1
    fi
    
    log_success "Certificate validation passed"
    return 0
}

# Restart nginx with health check
restart_nginx() {
    log "Restarting nginx..."
    
    if ! docker ps --format "{{.Names}}" | grep -q mikrotik-nginx; then
        log_warning "Nginx container not running"
        
        # Try to start it
        if docker ps -a --format "{{.Names}}" | grep -q mikrotik-nginx; then
            log_info "Starting nginx container..."
            docker start mikrotik-nginx || {
                log_error "Failed to start nginx container"
                return 1
            }
        else
            log_error "Nginx container not found"
            return 1
        fi
    else
        # Restart running container
        docker restart mikrotik-nginx || {
            log_error "Failed to restart nginx"
            return 1
        }
    fi
    
    # Wait for nginx to be ready
    log_info "Waiting for nginx to be ready..."
    local count=0
    while [[ $count -lt 30 ]]; do
        if docker exec mikrotik-nginx nginx -t &>/dev/null; then
            log_success "Nginx is ready"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    log_error "Nginx failed to start properly"
    return 1
}

# Update hosts file with validation
update_hosts_file() {
    log "Updating /etc/hosts file..."
    
    # Backup hosts file
    cp /etc/hosts /etc/hosts.bak.$(date +%Y%m%d_%H%M%S)
    
    # Remove old entries
    sed -i '/# MikroTik VPN Local Development/,/# End MikroTik VPN/d' /etc/hosts
    sed -i '/netkarn.local/d' /etc/hosts
    
    # Add new entries
    cat >> /etc/hosts << EOF

# MikroTik VPN Local Development
$PRIMARY_IP    netkarn.local
$PRIMARY_IP    admin.netkarn.local
$PRIMARY_IP    monitor.netkarn.local
$PRIMARY_IP    api.netkarn.local
127.0.0.1      netkarn.local
127.0.0.1      admin.netkarn.local
127.0.0.1      monitor.netkarn.local
127.0.0.1      api.netkarn.local
# End MikroTik VPN
EOF
    
    log_success "Hosts file updated"
}

# Check DNS resolution
check_dns_resolution() {
    log "Checking DNS resolution..."
    
    local domains=(
        "netkarn.local"
        "admin.netkarn.local"
        "monitor.netkarn.local"
        "api.netkarn.local"
    )
    
    local all_resolved=true
    
    for domain in "${domains[@]}"; do
        printf "  %-30s" "$domain"
        
        if host "$domain" >/dev/null 2>&1; then
            local resolved_ip=$(getent hosts "$domain" | awk '{print $1}' | head -1)
            if [[ "$resolved_ip" == "$PRIMARY_IP" ]] || [[ "$resolved_ip" == "127.0.0.1" ]]; then
                echo -e "${GREEN}✓ Resolves to $resolved_ip${NC}"
            else
                echo -e "${YELLOW}⚠ Resolves to $resolved_ip (expected $PRIMARY_IP)${NC}"
                all_resolved=false
            fi
        else
            echo -e "${RED}✗ Not resolving${NC}"
            all_resolved=false
        fi
    done
    
    if [[ "$all_resolved" == "true" ]]; then
        log_success "All domains resolving correctly"
    else
        log_warning "Some domains not resolving correctly"
    fi
}

# Test SSL connections with detailed output
test_ssl_connections() {
    log "Testing SSL connections..."
    echo
    
    local test_urls=(
        "https://localhost:9443/health"
        "https://127.0.0.1:9443/health"
        "https://$PRIMARY_IP:9443/health"
        "https://netkarn.local:9443/health"
        "https://admin.netkarn.local:9443/health"
        "https://monitor.netkarn.local:9443/health"
    )
    
    local all_passed=true
    
    for url in "${test_urls[@]}"; do
        printf "  %-50s" "$url"
        
        # Test with curl
        local response=$(curl -s -o /dev/null -w "%{http_code}:%{ssl_verify_result}" \
            --connect-timeout 5 \
            --max-time 10 \
            --cacert "$CAROOT/rootCA.pem" \
            "$url" 2>/dev/null || echo "000:1")
        
        local http_code=$(echo "$response" | cut -d: -f1)
        local ssl_result=$(echo "$response" | cut -d: -f2)
        
        if [[ "$http_code" =~ ^(200|301|302|404)$ ]] && [[ "$ssl_result" == "0" ]]; then
            echo -e "${GREEN}✓ OK${NC} (HTTP $http_code, SSL verified)"
        elif [[ "$http_code" =~ ^(200|301|302|404)$ ]]; then
            echo -e "${YELLOW}⚠ Warning${NC} (HTTP $http_code, SSL not verified)"
            all_passed=false
        else
            echo -e "${RED}✗ Failed${NC} (HTTP $http_code)"
            all_passed=false
        fi
    done
    
    echo
    if [[ "$all_passed" == "true" ]]; then
        log_success "All SSL connections tested successfully"
    else
        log_warning "Some SSL connections failed"
        log_info "This might be normal if the application is not fully started"
    fi
}

# Show browser import instructions with OS-specific guidance
show_browser_import_instructions() {
    echo
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║         Browser Certificate Import Instructions               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo
    
    log_info "The mkcert CA certificate location:"
    echo "  $CAROOT/rootCA.pem"
    echo
    
    echo "${CYAN}Chrome/Edge (Windows/Mac/Linux):${NC}"
    echo "  1. Navigate to: chrome://settings/certificates (or edge://settings/privacy)"
    echo "  2. Click 'Manage certificates'"
    echo "  3. Go to 'Authorities' tab"
    echo "  4. Click 'Import' and select: $CAROOT/rootCA.pem"
    echo "  5. Check 'Trust this certificate for identifying websites'"
    echo
    
    echo "${CYAN}Firefox:${NC}"
    echo "  1. Navigate to: about:preferences#privacy"
    echo "  2. Scroll down to 'Certificates' → 'View Certificates'"
    echo "  3. Go to 'Authorities' tab"
    echo "  4. Click 'Import' and select: $CAROOT/rootCA.pem"
    echo "  5. Check 'Trust this CA to identify websites'"
    echo
    
    echo "${CYAN}Safari (macOS):${NC}"
    echo "  1. Double-click: $CAROOT/rootCA.pem"
    echo "  2. Add to 'System' keychain"
    echo "  3. Open Keychain Access"
    echo "  4. Find 'mkcert' certificate"
    echo "  5. Double-click and set 'Always Trust' for SSL"
    echo
    
    echo "${CYAN}System-wide Trust (Linux):${NC}"
    echo "  Ubuntu/Debian:"
    echo "    sudo cp $CAROOT/rootCA.pem /usr/local/share/ca-certificates/mkcert-ca.crt"
    echo "    sudo update-ca-certificates"
    echo
    echo "  RHEL/CentOS:"
    echo "    sudo cp $CAROOT/rootCA.pem /etc/pki/ca-trust/source/anchors/"
    echo "    sudo update-ca-trust"
    echo
    
    echo "${CYAN}System-wide Trust (Windows):${NC}"
    echo "  1. Run as Administrator:"
    echo "    certutil -addstore -f \"ROOT\" \"$CAROOT/rootCA.pem\""
    echo
    
    log_warning "Note: You may need to restart your browser after importing the certificate"
}

# Create test script with enhanced testing
create_test_script() {
    log "Creating test script..."
    
    cat > /opt/mikrotik-vpn/test-ssl.sh << 'EOF'
#!/bin/bash
# SSL Connection Test Script

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    SSL Connection Tests                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Function to test URL
test_url() {
    local url=$1
    local name=$2
    
    printf "%-30s: " "$name"
    
    # Full test with timing
    local start=$(date +%s%N)
    local response=$(curl -s -o /dev/null -w "%{http_code}:%{ssl_verify_result}:%{time_total}" \
        --connect-timeout 5 \
        --max-time 10 \
        "$url" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        local http_code=$(echo "$response" | cut -d: -f1)
        local ssl_result=$(echo "$response" | cut -d: -f2)
        local time_total=$(echo "$response" | cut -d: -f3)
        
        if [[ "$http_code" =~ ^(200|301|302|404)$ ]]; then
            echo -e "${GREEN}✓ OK${NC} (HTTP $http_code, ${time_total}s)"
        else
            echo -e "${RED}✗ Failed${NC} (HTTP $http_code)"
        fi
    else
        echo -e "${RED}✗ Connection failed${NC}"
    fi
}

# Test basic connectivity
echo "Basic Connectivity Tests:"
echo "========================"
test_url "http://localhost:9080" "HTTP Localhost"
test_url "https://localhost:9443" "HTTPS Localhost"
test_url "https://127.0.0.1:9443" "HTTPS 127.0.0.1"

echo
echo "Domain Tests:"
echo "============"
test_url "https://netkarn.local:9443" "Main Domain"
test_url "https://admin.netkarn.local:9443" "Admin Domain"
test_url "https://monitor.netkarn.local:9443" "Monitor Domain"
test_url "https://api.netkarn.local:9443" "API Domain"

echo
echo "Health Check Endpoints:"
echo "====================="
test_url "https://netkarn.local:9443/health" "Main Health"
test_url "https://netkarn.local:9443/api" "API Info"
test_url "https://netkarn.local:9443/metrics" "Metrics"

echo
echo "Certificate Information:"
echo "======================="
if command -v openssl &>/dev/null; then
    echo "Main certificate (netkarn.local:9443):"
    echo | openssl s_client -connect netkarn.local:9443 -servername netkarn.local 2>/dev/null | \
        openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'
else
    echo "  OpenSSL not available for certificate inspection"
fi

echo
echo "DNS Resolution:"
echo "=============="
for domain in netkarn.local admin.netkarn.local monitor.netkarn.local api.netkarn.local; do
    printf "  %-30s: " "$domain"
    if host "$domain" &>/dev/null; then
        echo -e "${GREEN}✓ Resolving${NC}"
    else
        echo -e "${RED}✗ Not resolving${NC}"
    fi
done

echo
echo -e "${BLUE}Test completed!${NC}"
EOF
    
    chmod +x /opt/mikrotik-vpn/test-ssl.sh
    log_success "Test script created: /opt/mikrotik-vpn/test-ssl.sh"
}

# Create uninstall script
create_uninstall_script() {
    cat > /opt/mikrotik-vpn/uninstall-ssl.sh << 'EOF'
#!/bin/bash
# SSL Certificate Uninstall Script

echo "This will remove the local SSL certificates and mkcert CA."
read -p "Are you sure? (y/n): " confirm

if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Remove certificates
rm -f /opt/mikrotik-vpn/nginx/ssl/*.pem

# Remove mkcert CA
mkcert -uninstall 2>/dev/null || true

# Remove hosts entries
sed -i '/# MikroTik VPN Local Development/,/# End MikroTik VPN/d' /etc/hosts

echo "SSL certificates and CA removed."
echo "You may need to manually remove the CA from your browsers."
EOF
    
    chmod +x /opt/mikrotik-vpn/uninstall-ssl.sh
}

# Show completion summary
show_completion_summary() {
    echo
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    Setup Completed!                           ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo
    log_success "SSL certificates have been generated and installed successfully!"
    echo
    echo "${CYAN}You can now access the system using:${NC}"
    echo
    echo "  ${GREEN}Local Domain Access (Recommended):${NC}"
    echo "    Main:     https://netkarn.local:9443"
    echo "    Admin:    https://admin.netkarn.local:9443"
    echo "    Monitor:  https://monitor.netkarn.local:9443"
    echo "    API:      https://api.netkarn.local:9443"
    echo
    echo "  ${GREEN}IP Address Access:${NC}"
    echo "    Main:     https://$PRIMARY_IP:9443"
    echo "    HTTP:     http://$PRIMARY_IP:9080"
    echo
    echo "  ${GREEN}Localhost Access:${NC}"
    echo "    Main:     https://localhost:9443"
    echo "    HTTP:     http://localhost:9080"
    echo
    echo "${CYAN}Useful Commands:${NC}"
    echo "  Test connections:  /opt/mikrotik-vpn/test-ssl.sh"
    echo "  Uninstall SSL:     /opt/mikrotik-vpn/uninstall-ssl.sh"
    echo "  View nginx logs:   docker logs mikrotik-nginx"
    echo
    log_info "Note: The certificate is trusted locally. No browser warnings!"
    log_warning "Remember to import the CA certificate in your browser if needed."
    echo
}

# Main execution flow
main() {
    print_header
    check_root
    check_requirements
    install_mkcert
    setup_mkcert_ca
    backup_certificates
    get_system_info
    generate_certificate
    
    if validate_certificate; then
        update_hosts_file
        restart_nginx
        check_dns_resolution
        echo
        test_ssl_connections
        show_browser_import_instructions
        create_test_script
        create_uninstall_script
        show_completion_summary
    else
        log_error "Certificate validation failed. Please check the errors above."
        exit 1
    fi
    
    log_success "SSL setup completed successfully! 🎉"
}

# Execute main function
main "$@"
