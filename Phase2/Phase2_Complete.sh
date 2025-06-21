#!/bin/bash
# =============================================================================
# Phase 2: MikroTik Integration - Complete Installation Script
# Version: 2.0
# Description: Runs all Phase 2 parts in sequence
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Script directory
PHASE2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/mikrotik-vpn/phase2-complete.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

show_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║        MikroTik VPN Management System - Phase 2              ║"
    echo "║              Complete MikroTik Integration                   ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# =============================================================================
# PRE-REQUISITE CHECKS
# =============================================================================

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Phase 1 is completed
    if [[ ! -d "/opt/mikrotik-vpn" ]]; then
        log_error "Phase 1 not completed. Please run Phase 1 installation first."
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker ps &>/dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Check if MongoDB is accessible
    if ! docker ps | grep -q "mikrotik-mongodb"; then
        log_error "MongoDB container is not running. Please ensure Phase 1 services are running."
        exit 1
    fi
    
    # Check if configuration file exists
    if [[ ! -f "/opt/mikrotik-vpn/configs/setup.env" ]]; then
        log_error "Configuration file not found. Please ensure Phase 1 was completed successfully."
        exit 1
    fi
    
    # Load configuration
    source /opt/mikrotik-vpn/configs/setup.env
    
    # Verify required passwords are loaded
    if [[ -z "${MONGO_APP_PASSWORD:-}" ]] || [[ -z "${REDIS_PASSWORD:-}" ]]; then
        log_error "Required passwords not found in configuration."
        exit 1
    fi
    
    # Check JWT_SECRET and SESSION_SECRET
    if [[ -z "${JWT_SECRET:-}" ]] || [[ -z "${SESSION_SECRET:-}" ]]; then
        log_error "Required secrets (JWT_SECRET/SESSION_SECRET) not found in configuration."
        exit 1
    fi
    
    log "Prerequisites check passed!"
}

# =============================================================================
# PHASE 2 PARTS EXECUTION
# =============================================================================

run_phase2_part1() {
    log ""
    log "════════════════════════════════════════════════════════════"
    log "Running Phase 2 Part 1: Core Setup and Device Management"
    log "════════════════════════════════════════════════════════════"
    
    if [[ -f "$PHASE2_DIR/Phase2_Part1.sh" ]]; then
        bash "$PHASE2_DIR/Phase2_Part1.sh" || {
            log_error "Phase 2 Part 1 failed!"
            return 1
        }
    else
        log_error "Phase 2 Part 1 script not found!"
        return 1
    fi
    
    log "Phase 2 Part 1 completed successfully!"
    return 0
}

run_phase2_part2() {
    log ""
    log "════════════════════════════════════════════════════════════"
    log "Running Phase 2 Part 2: Hotspot and User Management"
    log "════════════════════════════════════════════════════════════"
    
    if [[ -f "$PHASE2_DIR/Phase2_Part2.sh" ]]; then
        bash "$PHASE2_DIR/Phase2_Part2.sh" || {
            log_error "Phase 2 Part 2 failed!"
            return 1
        }
    else
        log_error "Phase 2 Part 2 script not found!"
        return 1
    fi
    
    log "Phase 2 Part 2 completed successfully!"
    return 0
}

run_phase2_part3() {
    log ""
    log "════════════════════════════════════════════════════════════"
    log "Running Phase 2 Part 3: Voucher System"
    log "════════════════════════════════════════════════════════════"
    
    if [[ -f "$PHASE2_DIR/Phase2_Part3.sh" ]]; then
        bash "$PHASE2_DIR/Phase2_Part3.sh" || {
            log_error "Phase 2 Part 3 failed!"
            return 1
        }
    else
        log_error "Phase 2 Part 3 script not found!"
        return 1
    fi
    
    log "Phase 2 Part 3 completed successfully!"
    return 0
}

run_phase2_part4() {
    log ""
    log "════════════════════════════════════════════════════════════"
    log "Running Phase 2 Part 4: Reporting and Integration"
    log "════════════════════════════════════════════════════════════"
    
    if [[ -f "$PHASE2_DIR/Phase2_Part4.sh" ]]; then
        bash "$PHASE2_DIR/Phase2_Part4.sh" || {
            log_error "Phase 2 Part 4 failed!"
            return 1
        }
    else
        log_error "Phase 2 Part 4 script not found!"
        return 1
    fi
    
    log "Phase 2 Part 4 completed successfully!"
    return 0
}

# =============================================================================
# POST-INSTALLATION TASKS
# =============================================================================

post_installation_tasks() {
    log ""
    log "════════════════════════════════════════════════════════════"
    log "Running Post-Installation Tasks"
    log "════════════════════════════════════════════════════════════"
    
    # Initialize database with default data
    log_info "Initializing database with default data..."
    docker exec mikrotik-app node -e "
    const mongoose = require('mongoose');
    const Organization = require('./models/Organization');
    const HotspotProfile = require('./models/HotspotProfile');
    
    async function initializeDefaults() {
        try {
            await mongoose.connect(process.env.MONGODB_URI);
            
            // Check if organization exists
            let organization = await Organization.findOne();
            if (!organization) {
                organization = await Organization.create({
                    name: 'Default Organization',
                    email: 'admin@mikrotik-vpn.local',
                    isActive: true,
                    settings: {
                        features: {
                            hotspot: true,
                            vouchers: true
                        }
                    }
                });
                console.log('Created default organization');
            }
            
            // Create default hotspot profiles
            const profiles = [
                {
                    name: 'Trial (30 minutes)',
                    mikrotikName: 'trial',
                    type: 'time-based',
                    limits: {
                        uptime: '30m',
                        rateLimit: '1M/1M'
                    },
                    pricing: {
                        price: 0
                    }
                },
                {
                    name: 'Basic (1 hour)',
                    mikrotikName: 'basic-1h',
                    type: 'time-based',
                    limits: {
                        uptime: '1h',
                        rateLimit: '2M/2M'
                    },
                    pricing: {
                        price: 20
                    }
                },
                {
                    name: 'Standard (1 day)',
                    mikrotikName: 'standard-1d',
                    type: 'time-based',
                    limits: {
                        uptime: '1d',
                        rateLimit: '5M/5M'
                    },
                    pricing: {
                        price: 50
                    }
                },
                {
                    name: 'Premium (7 days)',
                    mikrotikName: 'premium-7d',
                    type: 'time-based',
                    limits: {
                        uptime: '7d',
                        rateLimit: '10M/10M',
                        concurrentSessions: 2
                    },
                    pricing: {
                        price: 200
                    }
                }
            ];
            
            for (const profileData of profiles) {
                const existing = await HotspotProfile.findOne({
                    organization: organization._id,
                    mikrotikName: profileData.mikrotikName
                });
                
                if (!existing) {
                    await HotspotProfile.create({
                        ...profileData,
                        organization: organization._id,
                        createdBy: organization.createdBy || organization._id
                    });
                    console.log(\`Created profile: \${profileData.name}\`);
                }
            }
            
            // Set the first profile as default
            const firstProfile = await HotspotProfile.findOne({ organization: organization._id });
            if (firstProfile && !firstProfile.isDefault) {
                firstProfile.isDefault = true;
                await firstProfile.save();
                console.log('Set default profile');
            }
            
            console.log('Default data initialization completed');
            mongoose.disconnect();
        } catch (error) {
            console.error('Initialization failed:', error);
            mongoose.disconnect();
            process.exit(1);
        }
    }
    
    initializeDefaults();
    " || log_warning "Failed to initialize default data"
    
    # Create sample device setup script
    log_info "Creating sample device setup script..."
    cat << 'EOF' > /opt/mikrotik-vpn/scripts/sample-device-setup.rsc
# Sample MikroTik Device Setup Script
# This script configures basic settings for VPN management

# Set system identity
/system identity set name="MikroTik-Managed"

# Configure API service
/ip service
set api disabled=no port=8728
set api-ssl disabled=no port=8729

# Create API user for management
/user add name=api-user password=YourSecurePassword group=full comment="VPN Management API User"

# Configure L2TP client for management VPN
/interface l2tp-client
add connect-to=YOUR_VPN_SERVER_IP name=vpn-mgmt user=YOUR_VPN_USER \
    password=YOUR_VPN_PASSWORD profile=default-encryption \
    add-default-route=no disabled=no comment="Management VPN"

# Add route to management network
/ip route
add dst-address=10.8.0.0/24 gateway=vpn-mgmt

# Configure firewall to allow management access
/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=8728,8729 \
    src-address=10.8.0.0/24 comment="Allow API from management network"

# Configure hotspot (example)
/interface bridge add name=bridge-hotspot
/ip address add address=192.168.88.1/24 interface=bridge-hotspot
/ip pool add name=hotspot-pool ranges=192.168.88.10-192.168.88.254
/ip dhcp-server add address-pool=hotspot-pool disabled=no interface=bridge-hotspot name=hotspot-dhcp
/ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=8.8.8.8,8.8.4.4

print "Basic setup completed! Configure VPN settings with your actual server details."
EOF
    
    # Test API connectivity
    log_info "Testing API connectivity..."
    if curl -s http://localhost:3000/health | grep -q "ok"; then
        log "✓ API is responding"
    else
        log_warning "✗ API health check failed - this may be normal during startup"
    fi
    
    log "Post-installation tasks completed!"
}

# =============================================================================
# SUMMARY AND NEXT STEPS
# =============================================================================

show_summary() {
    source /opt/mikrotik-vpn/configs/setup.env
    
    echo
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}       Phase 2 Installation Completed Successfully!          ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${CYAN}Installed Components:${NC}"
    echo "  ✓ MikroTik Device Management"
    echo "  ✓ Device Discovery and Monitoring"
    echo "  ✓ Hotspot User Management"
    echo "  ✓ Hotspot Profile Management"
    echo "  ✓ Session Tracking and Analytics"
    echo "  ✓ Voucher Generation System"
    echo "  ✓ Voucher Sales Management"
    echo "  ✓ Comprehensive Reporting System"
    echo "  ✓ Real-time Dashboard Metrics"
    echo "  ✓ Integration with Phase 1 Infrastructure"
    echo
    echo -e "${CYAN}Access Information:${NC}"
    echo "  Web Interface: https://$DOMAIN_NAME"
    echo "  API Endpoint: https://$DOMAIN_NAME/api/v1"
    echo "  Management CLI: mikrotik-vpn"
    echo
    echo -e "${CYAN}Default Credentials:${NC}"
    echo "  Username: admin"
    echo "  Email: admin@mikrotik-vpn.local"
    echo "  Password: admin123"
    echo -e "${RED}  IMPORTANT: Change the default password immediately!${NC}"
    echo
    echo -e "${CYAN}Quick Start Guide:${NC}"
    echo "  1. Access the web interface and change default password"
    echo "  2. Register your first MikroTik device:"
    echo "     - Run: /opt/mikrotik-vpn/scripts/setup-mikrotik-device.sh"
    echo "     - Configure VPN on your MikroTik device"
    echo "     - Register device in web interface"
    echo "  3. Create hotspot profiles"
    echo "  4. Generate vouchers for sale"
    echo "  5. Monitor devices and sessions in real-time"
    echo
    echo -e "${CYAN}Sample Files:${NC}"
    echo "  MikroTik Setup: /opt/mikrotik-vpn/scripts/sample-device-setup.rsc"
    echo "  VPN Templates: /opt/mikrotik-vpn/src/mikrotik/templates/"
    echo
    echo -e "${CYAN}Logs:${NC}"
    echo "  Application: docker logs mikrotik-app"
    echo "  Installation: $LOG_FILE"
    echo
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "  Phase 3: Business Features"
    echo "  - Payment Gateway Integration"
    echo "  - Custom Captive Portal"
    echo "  - Multi-language Support"
    echo "  - Advanced Analytics"
    echo "  - Mobile App API"
    echo
    echo -e "${GREEN}Thank you for installing MikroTik VPN Management System!${NC}"
    echo
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Show banner
    show_banner
    
    # Start installation
    log "Starting Phase 2 Complete Installation..."
    log "Installation log: $LOG_FILE"
    
    # Check prerequisites
    check_prerequisites
    
    # Ask for confirmation
    echo
    echo -e "${YELLOW}This will install all Phase 2 components:${NC}"
    echo "  - Device Management"
    echo "  - Hotspot Management"
    echo "  - Voucher System"
    echo "  - Reporting System"
    echo
    read -p "Do you want to continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Installation cancelled by user"
        exit 0
    fi
    
    # Record start time
    START_TIME=$(date +%s)
    
    # Run all parts in sequence
    run_phase2_part1 || {
        log_error "Installation failed at Part 1"
        exit 1
    }
    
    run_phase2_part2 || {
        log_error "Installation failed at Part 2"
        exit 1
    }
    
    run_phase2_part3 || {
        log_error "Installation failed at Part 3"
        exit 1
    }
    
    run_phase2_part4 || {
        log_error "Installation failed at Part 4"
        exit 1
    }
    
    # Run post-installation tasks
    post_installation_tasks
    
    # Calculate installation time
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    MINUTES=$((DURATION / 60))
    SECONDS=$((DURATION % 60))
    
    log ""
    log "Total installation time: ${MINUTES} minutes ${SECONDS} seconds"
    
    # Show summary
    show_summary
}

# Execute main
main "$@"
