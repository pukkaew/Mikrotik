#!/bin/bash
# =============================================================================
# Fix Docker Configuration and Start MikroTik VPN System
# Description: แก้ไขปัญหา Docker daemon configuration และเริ่มระบบ MikroTik VPN
# Version: 1.0
# =============================================================================

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_header() {
    echo
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       Fix Docker & Start MikroTik VPN System Script          ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Main execution
main() {
    print_header
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
    
    # Step 1: Stop Docker services
    print_info "Step 1: Stopping Docker services..."
    systemctl stop docker.socket 2>/dev/null || true
    systemctl stop docker 2>/dev/null || true
    systemctl stop containerd 2>/dev/null || true
    print_success "Docker services stopped"
    
    # Step 2: Backup existing configuration
    print_info "Step 2: Backing up existing Docker configuration..."
    if [[ -f /etc/docker/daemon.json ]]; then
        cp /etc/docker/daemon.json /etc/docker/daemon.json.backup.$(date +%Y%m%d_%H%M%S)
        print_success "Configuration backed up"
    else
        print_warning "No existing configuration found"
    fi
    
    # Step 3: Clean up Docker artifacts
    print_info "Step 3: Cleaning up Docker artifacts..."
    rm -rf /var/run/docker.sock 2>/dev/null || true
    rm -rf /var/run/docker.pid 2>/dev/null || true
    rm -rf /var/run/docker/ 2>/dev/null || true
    print_success "Docker artifacts cleaned"
    
    # Step 4: Create new Docker configuration
    print_info "Step 4: Creating new Docker daemon configuration..."
    mkdir -p /etc/docker
    
    cat > /etc/docker/daemon.json <<'EOF'
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
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
  "ipv6": false
}
EOF
    
    print_success "Docker configuration created"
    
    # Step 5: Reload systemd daemon
    print_info "Step 5: Reloading systemd daemon..."
    systemctl daemon-reload
    print_success "Systemd daemon reloaded"
    
    # Step 6: Start Docker services
    print_info "Step 6: Starting Docker services..."
    
    # Start containerd first
    systemctl start containerd
    sleep 2
    
    # Start Docker socket
    systemctl start docker.socket
    sleep 2
    
    # Start Docker daemon
    if systemctl start docker; then
        print_success "Docker started successfully"
    else
        print_error "Failed to start Docker"
        print_info "Checking Docker status..."
        systemctl status docker --no-pager | tail -20
        exit 1
    fi
    
    # Step 7: Verify Docker is working
    print_info "Step 7: Verifying Docker installation..."
    if docker ps >/dev/null 2>&1; then
        print_success "Docker is working correctly"
        docker version | grep "Version:" | head -2
    else
        print_error "Docker is not responding"
        exit 1
    fi
    
    # Step 8: Enable Docker to start on boot
    print_info "Step 8: Enabling Docker to start on boot..."
    systemctl enable docker
    systemctl enable containerd
    print_success "Docker enabled for automatic startup"
    
    # Step 9: Check if MikroTik VPN is installed
    print_info "Step 9: Checking MikroTik VPN installation..."
    if [[ ! -d /opt/mikrotik-vpn ]]; then
        print_error "MikroTik VPN system not found at /opt/mikrotik-vpn"
        exit 1
    fi
    print_success "MikroTik VPN installation found"
    
    # Step 10: Create Docker network if needed
    print_info "Step 10: Checking Docker network..."
    if ! docker network ls --format '{{.Name}}' | grep -q "^mikrotik-vpn-net$"; then
        print_info "Creating Docker network..."
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
        print_success "Docker network created"
    else
        print_success "Docker network already exists"
    fi
    
    # Step 11: Start MikroTik VPN services
    print_info "Step 11: Starting MikroTik VPN services..."
    
    # Check if systemd service exists
    if systemctl list-unit-files | grep -q "mikrotik-vpn.service"; then
        print_info "Using systemd service..."
        if systemctl start mikrotik-vpn; then
            print_success "MikroTik VPN started via systemd"
        else
            print_warning "Systemd service failed, trying direct method..."
            cd /opt/mikrotik-vpn && docker compose up -d
        fi
    else
        print_info "Using Docker Compose directly..."
        cd /opt/mikrotik-vpn || exit 1
        
        # Load environment variables if available
        if [[ -f /opt/mikrotik-vpn/configs/setup.env ]]; then
            print_info "Loading configuration..."
            source /opt/mikrotik-vpn/configs/setup.env
        fi
        
        # Start services with Docker Compose
        if docker compose up -d; then
            print_success "MikroTik VPN services started"
        else
            print_error "Failed to start MikroTik VPN services"
            docker compose logs --tail=50
            exit 1
        fi
    fi
    
    # Step 12: Wait for services to be ready
    print_info "Step 12: Waiting for services to be ready..."
    sleep 20
    
    # Step 13: Check service status
    print_info "Step 13: Checking service status..."
    echo
    echo "Service Status:"
    echo "═══════════════"
    
    # Check each service
    services=("mongodb" "redis" "app" "nginx" "openvpn" "prometheus" "grafana")
    all_running=true
    
    for service in "${services[@]}"; do
        if docker ps --format "{{.Names}}" | grep -q "mikrotik-$service"; then
            print_success "$service is running"
        else
            print_error "$service is not running"
            all_running=false
        fi
    done
    
    echo
    
    # Step 14: Show access information
    if $all_running; then
        print_success "All services are running!"
        echo
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo -e "${GREEN}MikroTik VPN System is ready!${NC}"
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo
        echo "Access Information:"
        echo "══════════════════"
        
        # Get domain from config if available
        if [[ -f /opt/mikrotik-vpn/configs/setup.env ]]; then
            source /opt/mikrotik-vpn/configs/setup.env
            echo "Main URL: https://${DOMAIN_NAME}:9443"
            echo "Admin URL: https://admin.${DOMAIN_NAME}:9443"
            echo "Monitor URL: https://monitor.${DOMAIN_NAME}:9443"
        else
            echo "Main URL: https://localhost:9443"
        fi
        
        echo
        echo "Management Commands:"
        echo "═══════════════════"
        echo "• View status: sudo mikrotik-vpn status"
        echo "• Open management: sudo mikrotik-vpn"
        echo "• View logs: cd /opt/mikrotik-vpn && docker compose logs -f"
        echo
    else
        print_warning "Some services failed to start"
        echo
        echo "Troubleshooting:"
        echo "══════════════"
        echo "1. Check logs: cd /opt/mikrotik-vpn && docker compose logs"
        echo "2. Check individual service: docker logs mikrotik-<service-name>"
        echo "3. Restart specific service: docker restart mikrotik-<service-name>"
        echo "4. Check Docker: docker ps -a | grep mikrotik"
    fi
    
    # Final message
    echo
    print_info "Script execution completed!"
}

# Run main function
main "$@"
