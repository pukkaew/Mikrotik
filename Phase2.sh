#!/bin/bash
# =============================================================================
# Phase 2: MikroTik Integration - Complete Implementation
# Version: 2.0
# Description: Full implementation of MikroTik device management and integration
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

# Directories
SYSTEM_DIR="/opt/mikrotik-vpn"
APP_DIR="$SYSTEM_DIR/app"
CONFIG_DIR="$SYSTEM_DIR/configs"
LOG_DIR="/var/log/mikrotik-vpn"
SCRIPT_DIR="$SYSTEM_DIR/scripts"

# Create log directory if not exists
mkdir -p "$LOG_DIR"

# Load environment - IMPORTANT: This loads all passwords from Phase 1
if [[ -f "$CONFIG_DIR/setup.env" ]]; then
    source "$CONFIG_DIR/setup.env"
else
    echo -e "${RED}ERROR: Configuration file not found. Please run Phase 1 first.${NC}"
    exit 1
fi

# Verify required passwords are loaded
if [[ -z "${MONGO_APP_PASSWORD:-}" ]] || [[ -z "${REDIS_PASSWORD:-}" ]]; then
    echo -e "${RED}ERROR: Required passwords not found in configuration.${NC}"
    echo "Please ensure Phase 1 was completed successfully."
    exit 1
fi

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_DIR/phase2.log"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_DIR/phase2.log"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_DIR/phase2.log"
}

# =============================================================================
# PHASE 2.1: MIKROTIK DEVICE MANAGEMENT
# =============================================================================

phase2_1_device_management() {
    log "=== Phase 2.1: Setting up MikroTik Device Management ==="
    
    # Create device management directories
    mkdir -p "$APP_DIR/src/mikrotik"
    mkdir -p "$APP_DIR/src/mikrotik/lib"
    mkdir -p "$APP_DIR/src/mikrotik/templates"
    mkdir -p "$APP_DIR/src/mikrotik/scripts"
    mkdir -p "$APP_DIR/controllers"
    mkdir -p "$APP_DIR/routes"
    
    # Install MikroTik specific dependencies
    cd "$APP_DIR"
    log "Installing MikroTik dependencies..."
    npm install --save \
        node-routeros \
        mikrotik \
        ssh2 \
        node-schedule \
        ip \
        netmask \
        ping \
        snmp-native \
        @slack/webhook \
        @sendgrid/mail \
        pdfkit \
        exceljs \
        qrcode \
        handlebars \
        puppeteer \
        node-thermal-printer || {
        log_error "Failed to install npm dependencies"
        return 1
    }
    
    # Create MikroTik API wrapper
    create_mikrotik_api_wrapper
    
    # Create device discovery service
    create_device_discovery_service
    
    # Create device management controller
    create_device_management_controller
    
    # Create device monitoring service
    create_device_monitoring_service
    
    # Create MikroTik script templates
    create_mikrotik_templates
    
    log "Phase 2.1 completed!"
}

# Create MikroTik API wrapper
create_mikrotik_api_wrapper() {
    cat << 'EOF' > "$APP_DIR/src/mikrotik/lib/mikrotik-api.js"
const { RouterOSAPI } = require('node-routeros');
const EventEmitter = require('events');
const logger = require('../../utils/logger');

class MikroTikAPI extends EventEmitter {
    constructor(config) {
        super();
        this.config = {
            host: config.host || config.vpnIpAddress,
            user: config.user || 'admin',
            password: config.password,
            port: config.port || 8728,
            timeout: config.timeout || 10000,
            tls: config.tls || false
        };
        this.connection = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 5000;
    }

    async connect() {
        try {
            this.connection = new RouterOSAPI(this.config);
            await this.connection.connect();
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.emit('connected');
            logger.info(`Connected to MikroTik device at ${this.config.host}`);
            return true;
        } catch (error) {
            logger.error(`Failed to connect to MikroTik device: ${error.message}`);
            this.emit('error', error);
            throw error;
        }
    }

    async disconnect() {
        if (this.connection) {
            await this.connection.close();
            this.isConnected = false;
            this.emit('disconnected');
            logger.info(`Disconnected from MikroTik device at ${this.config.host}`);
        }
    }

    async reconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            logger.error('Max reconnection attempts reached');
            this.emit('reconnectFailed');
            return false;
        }

        this.reconnectAttempts++;
        logger.info(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
        
        await new Promise(resolve => setTimeout(resolve, this.reconnectDelay));
        
        try {
            await this.connect();
            return true;
        } catch (error) {
            return this.reconnect();
        }
    }

    async execute(command, params = {}) {
        if (!this.isConnected) {
            throw new Error('Not connected to MikroTik device');
        }

        try {
            const result = await this.connection.write(command, params);
            return result;
        } catch (error) {
            logger.error(`Command execution failed: ${error.message}`);
            
            if (error.message.includes('Connection') || error.message.includes('timeout')) {
                this.isConnected = false;
                this.emit('connectionLost');
                
                // Try to reconnect
                const reconnected = await this.reconnect();
                if (reconnected) {
                    // Retry the command
                    return this.execute(command, params);
                }
            }
            
            throw error;
        }
    }

    // System Information
    async getSystemInfo() {
        const [identity, resource, routerboard, health] = await Promise.all([
            this.execute('/system/identity/print'),
            this.execute('/system/resource/print'),
            this.execute('/system/routerboard/print').catch(() => null),
            this.execute('/system/health/print').catch(() => null)
        ]);

        return {
            identity: identity[0].name,
            version: resource[0].version,
            buildTime: resource[0]['build-time'],
            factorySoftware: resource[0]['factory-software'],
            freeMemory: resource[0]['free-memory'],
            totalMemory: resource[0]['total-memory'],
            freeHddSpace: resource[0]['free-hdd-space'],
            totalHddSpace: resource[0]['total-hdd-space'],
            cpuCount: resource[0]['cpu-count'],
            cpuFrequency: resource[0]['cpu-frequency'],
            cpuLoad: resource[0]['cpu-load'],
            uptime: resource[0].uptime,
            platform: resource[0].platform,
            boardName: resource[0]['board-name'],
            architecture: resource[0]['architecture-name'],
            routerboard: routerboard ? routerboard[0] : null,
            health: health || []
        };
    }

    // Interface Management
    async getInterfaces() {
        const interfaces = await this.execute('/interface/print');
        const stats = await this.execute('/interface/ethernet/print', { stats: true });
        
        return interfaces.map(iface => {
            const stat = stats.find(s => s.name === iface.name) || {};
            return {
                ...iface,
                stats: {
                    rxBytes: stat['rx-bytes'] || 0,
                    txBytes: stat['tx-bytes'] || 0,
                    rxPackets: stat['rx-packets'] || 0,
                    txPackets: stat['tx-packets'] || 0,
                    rxErrors: stat['rx-errors'] || 0,
                    txErrors: stat['tx-errors'] || 0
                }
            };
        });
    }

    // IP Address Management
    async getIPAddresses() {
        return this.execute('/ip/address/print');
    }

    async addIPAddress(address, interfaceName) {
        return this.execute('/ip/address/add', {
            address: address,
            interface: interfaceName
        });
    }

    // Hotspot Management
    async getHotspotServers() {
        return this.execute('/ip/hotspot/print');
    }

    async getHotspotProfiles() {
        return this.execute('/ip/hotspot/profile/print');
    }

    async getHotspotUsers() {
        return this.execute('/ip/hotspot/user/print');
    }

    async addHotspotUser(userData) {
        return this.execute('/ip/hotspot/user/add', {
            name: userData.username,
            password: userData.password,
            profile: userData.profile || 'default',
            'limit-uptime': userData.limitUptime,
            'limit-bytes-total': userData.limitBytesTotal,
            'mac-address': userData.macAddress,
            comment: userData.comment
        });
    }

    async removeHotspotUser(username) {
        const users = await this.getHotspotUsers();
        const user = users.find(u => u.name === username);
        
        if (user) {
            return this.execute('/ip/hotspot/user/remove', { '.id': user['.id'] });
        }
        
        throw new Error('User not found');
    }

    async updateHotspotUser(username, updates) {
        const users = await this.getHotspotUsers();
        const user = users.find(u => u.name === username);
        
        if (user) {
            return this.execute('/ip/hotspot/user/set', {
                '.id': user['.id'],
                ...updates
            });
        }
        
        throw new Error('User not found');
    }

    // Active Sessions
    async getHotspotActive() {
        return this.execute('/ip/hotspot/active/print');
    }

    async disconnectHotspotUser(sessionId) {
        return this.execute('/ip/hotspot/active/remove', { '.id': sessionId });
    }

    // Firewall Management
    async getFirewallRules() {
        const [filter, nat, mangle] = await Promise.all([
            this.execute('/ip/firewall/filter/print'),
            this.execute('/ip/firewall/nat/print'),
            this.execute('/ip/firewall/mangle/print')
        ]);

        return { filter, nat, mangle };
    }

    async addFirewallRule(chain, rule) {
        return this.execute(`/ip/firewall/${chain}/add`, rule);
    }

    // VPN Configuration
    async getVPNServers() {
        const [pptp, l2tp, sstp, ovpn] = await Promise.all([
            this.execute('/interface/pptp-server/print').catch(() => []),
            this.execute('/interface/l2tp-server/print').catch(() => []),
            this.execute('/interface/sstp-server/print').catch(() => []),
            this.execute('/interface/ovpn-server/print').catch(() => [])
        ]);

        return { pptp, l2tp, sstp, ovpn };
    }

    async getPPPSecrets() {
        return this.execute('/ppp/secret/print');
    }

    async addPPPSecret(secret) {
        return this.execute('/ppp/secret/add', {
            name: secret.name,
            password: secret.password,
            service: secret.service || 'any',
            profile: secret.profile || 'default',
            'local-address': secret.localAddress,
            'remote-address': secret.remoteAddress,
            comment: secret.comment
        });
    }

    // DHCP Management
    async getDHCPServers() {
        return this.execute('/ip/dhcp-server/print');
    }

    async getDHCPLeases() {
        return this.execute('/ip/dhcp-server/lease/print');
    }

    async addStaticDHCPLease(lease) {
        return this.execute('/ip/dhcp-server/lease/add', {
            address: lease.address,
            'mac-address': lease.macAddress,
            server: lease.server,
            comment: lease.comment
        });
    }

    // Queue Management (Bandwidth Control)
    async getQueues() {
        const [simple, tree] = await Promise.all([
            this.execute('/queue/simple/print'),
            this.execute('/queue/tree/print')
        ]);

        return { simple, tree };
    }

    async addSimpleQueue(queue) {
        return this.execute('/queue/simple/add', {
            name: queue.name,
            target: queue.target,
            'max-limit': queue.maxLimit,
            'burst-limit': queue.burstLimit,
            'burst-threshold': queue.burstThreshold,
            'burst-time': queue.burstTime,
            comment: queue.comment
        });
    }

    // DNS Management
    async getDNSSettings() {
        return this.execute('/ip/dns/print');
    }

    async getDNSStaticEntries() {
        return this.execute('/ip/dns/static/print');
    }

    async addDNSStaticEntry(entry) {
        return this.execute('/ip/dns/static/add', {
            name: entry.name,
            address: entry.address,
            ttl: entry.ttl || '1d',
            comment: entry.comment
        });
    }

    // Logging and Monitoring
    async getSystemLogs(limit = 100) {
        return this.execute('/log/print', {
            limit: limit.toString()
        });
    }

    async getTrafficStats(interfaceName) {
        const stats = await this.execute('/interface/monitor-traffic', {
            interface: interfaceName,
            once: true
        });

        return stats[0];
    }

    // Backup and Configuration
    async createBackup(filename) {
        await this.execute('/system/backup/save', {
            name: filename,
            'dont-encrypt': 'yes'
        });

        // Wait for backup to complete
        await new Promise(resolve => setTimeout(resolve, 2000));

        return filename;
    }

    async exportConfiguration() {
        const config = await this.execute('/export');
        return config.join('\n');
    }

    // Script Execution
    async runScript(script) {
        // Create temporary script
        const scriptName = `temp-script-${Date.now()}`;
        await this.execute('/system/script/add', {
            name: scriptName,
            source: script
        });

        try {
            // Run the script
            const result = await this.execute('/system/script/run', {
                number: scriptName
            });

            return result;
        } finally {
            // Clean up
            await this.execute('/system/script/remove', {
                numbers: scriptName
            }).catch(() => {});
        }
    }

    // Scheduled Tasks
    async getScheduledTasks() {
        return this.execute('/system/scheduler/print');
    }

    async addScheduledTask(task) {
        return this.execute('/system/scheduler/add', {
            name: task.name,
            'start-time': task.startTime || 'startup',
            interval: task.interval,
            'on-event': task.onEvent,
            comment: task.comment
        });
    }

    // Reboot and Shutdown
    async reboot() {
        return this.execute('/system/reboot');
    }

    async shutdown() {
        return this.execute('/system/shutdown');
    }
}

module.exports = MikroTikAPI;
EOF
}

# Create device discovery service
create_device_discovery_service() {
    cat << 'EOF' > "$APP_DIR/src/mikrotik/lib/device-discovery.js"
const dgram = require('dgram');
const { EventEmitter } = require('events');
const logger = require('../../utils/logger');

class DeviceDiscovery extends EventEmitter {
    constructor(options = {}) {
        super();
        this.port = options.port || 5678;
        this.broadcastAddress = options.broadcastAddress || '255.255.255.255';
        this.timeout = options.timeout || 5000;
        this.socket = null;
        this.discovered = new Map();
    }

    async discover() {
        return new Promise((resolve, reject) => {
            this.socket = dgram.createSocket('udp4');
            const devices = [];
            const startTime = Date.now();

            this.socket.on('message', (msg, rinfo) => {
                try {
                    const device = this.parseDiscoveryMessage(msg, rinfo);
                    if (device && !this.discovered.has(device.macAddress)) {
                        this.discovered.set(device.macAddress, device);
                        devices.push(device);
                        this.emit('deviceFound', device);
                        logger.info(`Discovered MikroTik device: ${device.identity} at ${device.ipAddress}`);
                    }
                } catch (error) {
                    logger.error(`Failed to parse discovery message: ${error.message}`);
                }
            });

            this.socket.on('error', (error) => {
                logger.error(`Discovery error: ${error.message}`);
                this.socket.close();
                reject(error);
            });

            this.socket.bind(() => {
                this.socket.setBroadcast(true);
                
                // Send discovery packet
                const discoveryPacket = this.createDiscoveryPacket();
                this.socket.send(discoveryPacket, this.port, this.broadcastAddress, (error) => {
                    if (error) {
                        logger.error(`Failed to send discovery packet: ${error.message}`);
                    }
                });

                // Set timeout
                setTimeout(() => {
                    this.socket.close();
                    resolve(devices);
                }, this.timeout);
            });
        });
    }

    createDiscoveryPacket() {
        // MikroTik discovery protocol packet
        const packet = Buffer.alloc(4);
        packet.writeUInt32BE(0x00000000, 0);
        return packet;
    }

    parseDiscoveryMessage(msg, rinfo) {
        if (msg.length < 20) return null;

        try {
            // Parse MikroTik discovery response
            const device = {
                ipAddress: rinfo.address,
                port: rinfo.port,
                discoveredAt: new Date()
            };

            let offset = 0;
            while (offset < msg.length) {
                const type = msg.readUInt16BE(offset);
                const length = msg.readUInt16BE(offset + 2);
                const value = msg.slice(offset + 4, offset + 4 + length);

                switch (type) {
                    case 0x0001: // MAC address
                        device.macAddress = value.toString('hex').match(/.{2}/g).join(':');
                        break;
                    case 0x0005: // Identity
                        device.identity = value.toString('utf8');
                        break;
                    case 0x0007: // Platform
                        device.platform = value.toString('utf8');
                        break;
                    case 0x0008: // Version
                        device.version = value.toString('utf8');
                        break;
                    case 0x000A: // Uptime
                        device.uptime = value.readUInt32BE(0);
                        break;
                    case 0x000B: // Software ID
                        device.softwareId = value.toString('utf8');
                        break;
                    case 0x000C: // Board name
                        device.boardName = value.toString('utf8');
                        break;
                    case 0x0010: // Unpack
                        device.unpack = value.toString('utf8');
                        break;
                    case 0x0011: // IPv6
                        device.ipv6Address = this.parseIPv6(value);
                        break;
                    case 0x0014: // Interface name
                        device.interfaceName = value.toString('utf8');
                        break;
                    case 0x0015: // IPv4
                        device.ipv4Address = value.join('.');
                        break;
                }

                offset += 4 + length;
            }

            return device;
        } catch (error) {
            logger.error(`Failed to parse discovery data: ${error.message}`);
            return null;
        }
    }

    parseIPv6(buffer) {
        const parts = [];
        for (let i = 0; i < buffer.length; i += 2) {
            parts.push(buffer.readUInt16BE(i).toString(16));
        }
        return parts.join(':');
    }

    async scanNetwork(network) {
        const net = require('netmask').Netmask;
        const block = new net(network);
        const devices = [];

        logger.info(`Scanning network ${network} for MikroTik devices...`);

        // Scan each IP in the network
        block.forEach(async (ip) => {
            try {
                const device = await this.probeDevice(ip);
                if (device) {
                    devices.push(device);
                    this.emit('deviceFound', device);
                }
            } catch (error) {
                // Device not responding or not a MikroTik device
            }
        });

        return devices;
    }

    async probeDevice(ipAddress) {
        // Try to connect to MikroTik API port
        const net = require('net');
        
        return new Promise((resolve, reject) => {
            const socket = new net.Socket();
            socket.setTimeout(2000);

            socket.on('connect', () => {
                socket.destroy();
                resolve({
                    ipAddress,
                    port: 8728,
                    discoveredAt: new Date(),
                    probeMethod: 'api'
                });
            });

            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error('Connection timeout'));
            });

            socket.on('error', (error) => {
                reject(error);
            });

            socket.connect(8728, ipAddress);
        });
    }
}

module.exports = DeviceDiscovery;
EOF
}

# Create device management controller
create_device_management_controller() {
    cat << 'EOF' > "$APP_DIR/controllers/deviceController.js"
const Device = require('../models/Device');
const MikroTikAPI = require('../src/mikrotik/lib/mikrotik-api');
const DeviceDiscovery = require('../src/mikrotik/lib/device-discovery');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');

class DeviceController {
    constructor() {
        this.connections = new Map();
        this.discovery = new DeviceDiscovery();
    }

    // Get all devices for organization
    async getDevices(req, res, next) {
        try {
            const devices = await Device.find({ 
                organization: req.user.organization 
            })
            .populate('organization')
            .sort({ name: 1 });

            // Check online status for each device
            const devicesWithStatus = await Promise.all(
                devices.map(async (device) => {
                    const isOnline = await this.checkDeviceStatus(device.vpnIpAddress);
                    return {
                        ...device.toObject(),
                        status: isOnline ? 'online' : 'offline'
                    };
                })
            );

            res.json({
                success: true,
                count: devicesWithStatus.length,
                data: devicesWithStatus
            });
        } catch (error) {
            next(error);
        }
    }

    // Get single device
    async getDevice(req, res, next) {
        try {
            const device = await Device.findOne({
                _id: req.params.id,
                organization: req.user.organization
            }).populate('organization');

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            // Get real-time info if device is online
            let realtimeInfo = null;
            if (await this.checkDeviceStatus(device.vpnIpAddress)) {
                try {
                    const api = await this.getDeviceConnection(device);
                    realtimeInfo = await api.getSystemInfo();
                } catch (error) {
                    logger.error(`Failed to get real-time info: ${error.message}`);
                }
            }

            res.json({
                success: true,
                data: {
                    ...device.toObject(),
                    realtimeInfo
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Register new device
    async registerDevice(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const {
                name,
                serialNumber,
                macAddress,
                model,
                location,
                vpnIpAddress,
                apiUsername,
                apiPassword
            } = req.body;

            // Check if device already exists
            const existingDevice = await Device.findOne({
                $or: [
                    { serialNumber },
                    { macAddress: macAddress.toUpperCase() }
                ]
            });

            if (existingDevice) {
                return res.status(400).json({
                    success: false,
                    error: 'Device already registered'
                });
            }

            // Test connection before saving
            const testApi = new MikroTikAPI({
                host: vpnIpAddress,
                user: apiUsername,
                password: apiPassword
            });

            try {
                await testApi.connect();
                const systemInfo = await testApi.getSystemInfo();
                await testApi.disconnect();

                // Create device
                const device = await Device.create({
                    organization: req.user.organization,
                    name,
                    serialNumber,
                    macAddress: macAddress.toUpperCase(),
                    model: model || systemInfo.platform,
                    firmwareVersion: systemInfo.version,
                    location,
                    vpnIpAddress,
                    configuration: {
                        apiUsername,
                        apiPassword: this.encryptPassword(apiPassword)
                    },
                    status: 'online',
                    lastSeen: new Date()
                });

                // Store connection
                this.connections.set(device._id.toString(), testApi);

                res.status(201).json({
                    success: true,
                    data: device
                });

                // Emit device registered event
                req.app.get('io').to(`org:${req.user.organization}`).emit('device:registered', {
                    device: device.toObject()
                });

            } catch (error) {
                return res.status(400).json({
                    success: false,
                    error: `Failed to connect to device: ${error.message}`
                });
            }
        } catch (error) {
            next(error);
        }
    }

    // Update device
    async updateDevice(req, res, next) {
        try {
            const device = await Device.findOneAndUpdate(
                {
                    _id: req.params.id,
                    organization: req.user.organization
                },
                req.body,
                {
                    new: true,
                    runValidators: true
                }
            );

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            res.json({
                success: true,
                data: device
            });

            // Emit device updated event
            req.app.get('io').to(`org:${req.user.organization}`).emit('device:updated', {
                device: device.toObject()
            });
        } catch (error) {
            next(error);
        }
    }

    // Delete device
    async deleteDevice(req, res, next) {
        try {
            const device = await Device.findOneAndDelete({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            // Close connection if exists
            const connectionKey = device._id.toString();
            if (this.connections.has(connectionKey)) {
                const api = this.connections.get(connectionKey);
                await api.disconnect();
                this.connections.delete(connectionKey);
            }

            res.json({
                success: true,
                data: {}
            });

            // Emit device deleted event
            req.app.get('io').to(`org:${req.user.organization}`).emit('device:deleted', {
                deviceId: device._id
            });
        } catch (error) {
            next(error);
        }
    }

    // Discover devices on network
    async discoverDevices(req, res, next) {
        try {
            const { network } = req.body;

            let devices = [];
            
            if (network) {
                // Scan specific network
                devices = await this.discovery.scanNetwork(network);
            } else {
                // Broadcast discovery
                devices = await this.discovery.discover();
            }

            // Filter out already registered devices
            const registeredDevices = await Device.find({
                organization: req.user.organization,
                macAddress: { $in: devices.map(d => d.macAddress?.toUpperCase()).filter(Boolean) }
            });

            const registeredMacs = new Set(registeredDevices.map(d => d.macAddress));
            const newDevices = devices.filter(d => 
                d.macAddress && !registeredMacs.has(d.macAddress.toUpperCase())
            );

            res.json({
                success: true,
                data: {
                    discovered: devices.length,
                    new: newDevices.length,
                    devices: newDevices
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Execute command on device
    async executeCommand(req, res, next) {
        try {
            const { command, params } = req.body;

            const device = await Device.findOne({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            const api = await this.getDeviceConnection(device);
            const result = await api.execute(command, params);

            res.json({
                success: true,
                data: result
            });

            // Log command execution
            logger.info(`Command executed on device ${device.name}: ${command}`, {
                deviceId: device._id,
                command,
                params,
                user: req.user._id
            });
        } catch (error) {
            next(error);
        }
    }

    // Get device statistics
    async getDeviceStats(req, res, next) {
        try {
            const device = await Device.findOne({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            const api = await this.getDeviceConnection(device);
            
            const [systemInfo, interfaces, hotspotActive, queues] = await Promise.all([
                api.getSystemInfo(),
                api.getInterfaces(),
                api.getHotspotActive(),
                api.getQueues()
            ]);

            res.json({
                success: true,
                data: {
                    system: systemInfo,
                    interfaces,
                    hotspot: {
                        activeUsers: hotspotActive.length,
                        sessions: hotspotActive
                    },
                    queues
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Backup device configuration
    async backupDevice(req, res, next) {
        try {
            const device = await Device.findOne({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            const api = await this.getDeviceConnection(device);
            
            // Create backup
            const backupName = `backup-${device.name}-${Date.now()}`;
            await api.createBackup(backupName);

            // Export configuration
            const configuration = await api.exportConfiguration();

            // Store backup info in database
            device.backups = device.backups || [];
            device.backups.push({
                filename: backupName,
                createdAt: new Date(),
                createdBy: req.user._id,
                size: Buffer.byteLength(configuration),
                configuration
            });

            // Keep only last 10 backups
            if (device.backups.length > 10) {
                device.backups = device.backups.slice(-10);
            }

            await device.save();

            res.json({
                success: true,
                data: {
                    filename: backupName,
                    size: Buffer.byteLength(configuration),
                    createdAt: new Date()
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Reboot device
    async rebootDevice(req, res, next) {
        try {
            const device = await Device.findOne({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            const api = await this.getDeviceConnection(device);
            await api.reboot();

            // Update device status
            device.status = 'maintenance';
            device.alerts.push({
                type: 'warning',
                message: 'Device is rebooting',
                timestamp: new Date()
            });
            await device.save();

            res.json({
                success: true,
                message: 'Device reboot initiated'
            });

            // Emit reboot event
            req.app.get('io').to(`org:${req.user.organization}`).emit('device:rebooting', {
                deviceId: device._id,
                deviceName: device.name
            });

            // Schedule status check in 2 minutes
            setTimeout(async () => {
                const isOnline = await this.checkDeviceStatus(device.vpnIpAddress);
                
                device.status = isOnline ? 'online' : 'offline';
                await device.save();

                req.app.get('io').to(`org:${req.user.organization}`).emit('device:status:update', {
                    deviceId: device._id,
                    status: device.status
                });
            }, 120000);

        } catch (error) {
            next(error);
        }
    }

    // Apply configuration template
    async applyTemplate(req, res, next) {
        try {
            const { templateId } = req.body;

            const device = await Device.findOne({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            // Get template
            const template = await ConfigTemplate.findOne({
                _id: templateId,
                organization: req.user.organization
            });

            if (!template) {
                return res.status(404).json({
                    success: false,
                    error: 'Template not found'
                });
            }

            const api = await this.getDeviceConnection(device);

            // Apply template commands
            const results = [];
            for (const command of template.commands) {
                try {
                    const result = await api.execute(command.command, command.params);
                    results.push({
                        command: command.command,
                        success: true,
                        result
                    });
                } catch (error) {
                    results.push({
                        command: command.command,
                        success: false,
                        error: error.message
                    });
                }
            }

            // Update device configuration
            device.configuration.lastTemplate = templateId;
            device.configuration.lastTemplateApplied = new Date();
            await device.save();

            res.json({
                success: true,
                data: {
                    template: template.name,
                    results
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Helper methods
    async getDeviceConnection(device) {
        const connectionKey = device._id.toString();
        
        if (this.connections.has(connectionKey)) {
            const api = this.connections.get(connectionKey);
            if (api.isConnected) {
                return api;
            }
        }

        // Create new connection
        const api = new MikroTikAPI({
            host: device.vpnIpAddress,
            user: device.configuration.apiUsername,
            password: this.decryptPassword(device.configuration.apiPassword)
        });

        await api.connect();
        this.connections.set(connectionKey, api);

        // Set up event handlers
        api.on('disconnected', () => {
            this.connections.delete(connectionKey);
        });

        api.on('error', (error) => {
            logger.error(`Device connection error for ${device.name}: ${error.message}`);
        });

        return api;
    }

    async checkDeviceStatus(ipAddress) {
        const ping = require('ping');
        
        try {
            const result = await ping.promise.probe(ipAddress, {
                timeout: 2,
                min_reply: 1
            });
            
            return result.alive;
        } catch (error) {
            return false;
        }
    }

    encryptPassword(password) {
        // TODO: Implement proper encryption
        const crypto = require('crypto');
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
        const iv = crypto.randomBytes(16);
        
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(password, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return iv.toString('hex') + ':' + encrypted;
    }

    decryptPassword(encryptedPassword) {
        // Implement proper decryption
        const crypto = require('crypto');
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
        
        try {
            const [ivHex, encrypted] = encryptedPassword.split(':');
            const iv = Buffer.from(ivHex, 'hex');
            
            const decipher = crypto.createDecipheriv(algorithm, key, iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            logger.error('Failed to decrypt password:', error);
            throw new Error('Decryption failed');
        }
    }
}

module.exports = new DeviceController();
EOF
}

# Create device monitoring service
create_device_monitoring_service() {
    cat << 'EOF' > "$APP_DIR/src/mikrotik/lib/device-monitor.js"
const EventEmitter = require('events');
const schedule = require('node-schedule');
const Device = require('../../../models/Device');
const MikroTikAPI = require('./mikrotik-api');
const logger = require('../../../utils/logger');
const { sendAlert } = require('../../../utils/alerts');

class DeviceMonitor extends EventEmitter {
    constructor(io) {
        super();
        this.io = io;
        this.monitors = new Map();
        this.alerts = new Map();
        this.checkInterval = 60000; // 1 minute
        this.isRunning = false;
    }

    async start() {
        if (this.isRunning) {
            logger.warn('Device monitor is already running');
            return;
        }

        this.isRunning = true;
        logger.info('Starting device monitor...');

        // Initial check
        await this.checkAllDevices();

        // Schedule regular checks
        this.scheduleJob = schedule.scheduleJob('*/1 * * * *', async () => {
            await this.checkAllDevices();
        });

        // Schedule hourly statistics collection
        this.statsJob = schedule.scheduleJob('0 * * * *', async () => {
            await this.collectStatistics();
        });

        // Schedule daily health report
        this.reportJob = schedule.scheduleJob('0 8 * * *', async () => {
            await this.generateHealthReport();
        });

        this.emit('started');
    }

    async stop() {
        if (!this.isRunning) {
            return;
        }

        this.isRunning = false;
        logger.info('Stopping device monitor...');

        // Cancel scheduled jobs
        if (this.scheduleJob) {
            this.scheduleJob.cancel();
        }
        if (this.statsJob) {
            this.statsJob.cancel();
        }
        if (this.reportJob) {
            this.reportJob.cancel();
        }

        // Disconnect all monitors
        for (const [deviceId, monitor] of this.monitors) {
            if (monitor.api) {
                await monitor.api.disconnect();
            }
        }

        this.monitors.clear();
        this.alerts.clear();

        this.emit('stopped');
    }

    async checkAllDevices() {
        try {
            const devices = await Device.find({ isActive: true });
            
            for (const device of devices) {
                await this.checkDevice(device);
            }
        } catch (error) {
            logger.error(`Failed to check devices: ${error.message}`);
        }
    }

    async checkDevice(device) {
        const deviceId = device._id.toString();
        
        try {
            // Check if device is reachable
            const ping = require('ping');
            const pingResult = await ping.promise.probe(device.vpnIpAddress, {
                timeout: 5,
                min_reply: 1
            });

            if (pingResult.alive) {
                // Device is online
                await this.handleDeviceOnline(device);
            } else {
                // Device is offline
                await this.handleDeviceOffline(device);
            }
        } catch (error) {
            logger.error(`Failed to check device ${device.name}: ${error.message}`);
            await this.handleDeviceError(device, error);
        }
    }

    async handleDeviceOnline(device) {
        const deviceId = device._id.toString();
        const wasOffline = device.status === 'offline';

        // Update device status
        device.status = 'online';
        device.lastSeen = new Date();

        // Clear offline alert if exists
        if (this.alerts.has(deviceId)) {
            const alert = this.alerts.get(deviceId);
            if (alert.type === 'offline') {
                this.alerts.delete(deviceId);
                
                // Send recovery notification
                if (wasOffline) {
                    await sendAlert({
                        type: 'recovery',
                        device: device.name,
                        message: `Device ${device.name} is back online`,
                        timestamp: new Date()
                    });
                }
            }
        }

        // Get device metrics
        try {
            const monitor = await this.getDeviceMonitor(device);
            const metrics = await this.collectDeviceMetrics(monitor.api);
            
            // Update device health
            device.health = {
                cpuUsage: metrics.system.cpuLoad,
                memoryUsage: Math.round((1 - metrics.system.freeMemory / metrics.system.totalMemory) * 100),
                diskUsage: Math.round((1 - metrics.system.freeHddSpace / metrics.system.totalHddSpace) * 100),
                temperature: metrics.system.temperature,
                uptime: metrics.system.uptime
            };

            // Check for health alerts
            await this.checkHealthAlerts(device, metrics);

            // Update VPN status
            device.vpnStatus = {
                connected: true,
                connectedAt: device.vpnStatus.connectedAt || new Date(),
                bytesIn: metrics.traffic.bytesIn,
                bytesOut: metrics.traffic.bytesOut
            };

            // Emit real-time update
            this.io.to(`org:${device.organization}`).emit('device:metrics', {
                deviceId: device._id,
                metrics,
                timestamp: new Date()
            });

        } catch (error) {
            logger.error(`Failed to collect metrics for ${device.name}: ${error.message}`);
        }

        await device.save();
    }

    async handleDeviceOffline(device) {
        const deviceId = device._id.toString();
        const wasOnline = device.status === 'online';

        // Update device status
        device.status = 'offline';
        device.vpnStatus.connected = false;
        device.vpnStatus.disconnectedAt = new Date();

        // Create offline alert
        if (!this.alerts.has(deviceId) && wasOnline) {
            const alert = {
                type: 'offline',
                device: device.name,
                message: `Device ${device.name} is offline`,
                timestamp: new Date(),
                notificationSent: false
            };

            this.alerts.set(deviceId, alert);

            // Send immediate notification for critical devices
            if (device.tags.includes('critical')) {
                await sendAlert(alert);
                alert.notificationSent = true;
            } else {
                // Schedule notification after 5 minutes
                setTimeout(async () => {
                    if (this.alerts.has(deviceId) && !alert.notificationSent) {
                        await sendAlert(alert);
                        alert.notificationSent = true;
                    }
                }, 300000);
            }
        }

        // Add alert to device
        device.alerts.push({
            type: 'error',
            message: 'Device is offline',
            timestamp: new Date()
        });

        // Keep only last 50 alerts
        if (device.alerts.length > 50) {
            device.alerts = device.alerts.slice(-50);
        }

        await device.save();

        // Emit offline event
        this.io.to(`org:${device.organization}`).emit('device:offline', {
            deviceId: device._id,
            deviceName: device.name,
            timestamp: new Date()
        });
    }

    async handleDeviceError(device, error) {
        device.status = 'error';
        device.alerts.push({
            type: 'critical',
            message: `Connection error: ${error.message}`,
            timestamp: new Date()
        });

        await device.save();

        // Send critical alert
        await sendAlert({
            type: 'critical',
            device: device.name,
            message: `Critical error on device ${device.name}: ${error.message}`,
            timestamp: new Date()
        });
    }

    async getDeviceMonitor(device) {
        const deviceId = device._id.toString();

        if (this.monitors.has(deviceId)) {
            const monitor = this.monitors.get(deviceId);
            if (monitor.api && monitor.api.isConnected) {
                return monitor;
            }
        }

        // Create new monitor
        const api = new MikroTikAPI({
            host: device.vpnIpAddress,
            user: device.configuration.apiUsername,
            password: this.decryptPassword(device.configuration.apiPassword)
        });

        await api.connect();

        const monitor = {
            device,
            api,
            lastCheck: new Date()
        };

        this.monitors.set(deviceId, monitor);

        // Set up API event handlers
        api.on('disconnected', () => {
            this.monitors.delete(deviceId);
        });

        api.on('error', (error) => {
            logger.error(`Monitor API error for ${device.name}: ${error.message}`);
        });

        return monitor;
    }

    async collectDeviceMetrics(api) {
        const [system, interfaces, hotspotActive, queues, logs] = await Promise.all([
            api.getSystemInfo(),
            api.getInterfaces(),
            api.getHotspotActive(),
            api.getQueues(),
            api.getSystemLogs(50)
        ]);

        // Calculate interface traffic
        const traffic = interfaces.reduce((acc, iface) => {
            acc.bytesIn += iface.stats.rxBytes || 0;
            acc.bytesOut += iface.stats.txBytes || 0;
            acc.packetsIn += iface.stats.rxPackets || 0;
            acc.packetsOut += iface.stats.txPackets || 0;
            acc.errors += (iface.stats.rxErrors || 0) + (iface.stats.txErrors || 0);
            return acc;
        }, {
            bytesIn: 0,
            bytesOut: 0,
            packetsIn: 0,
            packetsOut: 0,
            errors: 0
        });

        // Parse temperature if available
        let temperature = null;
        if (system.health && system.health.length > 0) {
            const tempReading = system.health.find(h => h.name === 'temperature');
            if (tempReading) {
                temperature = parseFloat(tempReading.value);
            }
        }

        return {
            system: {
                ...system,
                temperature
            },
            interfaces,
            hotspot: {
                activeUsers: hotspotActive.length,
                sessions: hotspotActive
            },
            queues,
            traffic,
            logs: logs.slice(0, 10) // Last 10 log entries
        };
    }

    async checkHealthAlerts(device, metrics) {
        const alerts = [];

        // CPU usage alert
        if (metrics.system.cpuLoad > 80) {
            alerts.push({
                type: 'warning',
                message: `High CPU usage: ${metrics.system.cpuLoad}%`,
                metric: 'cpu',
                value: metrics.system.cpuLoad
            });
        }

        // Memory usage alert
        const memoryUsage = Math.round((1 - metrics.system.freeMemory / metrics.system.totalMemory) * 100);
        if (memoryUsage > 85) {
            alerts.push({
                type: 'warning',
                message: `High memory usage: ${memoryUsage}%`,
                metric: 'memory',
                value: memoryUsage
            });
        }

        // Disk usage alert
        const diskUsage = Math.round((1 - metrics.system.freeHddSpace / metrics.system.totalHddSpace) * 100);
        if (diskUsage > 90) {
            alerts.push({
                type: 'critical',
                message: `Critical disk usage: ${diskUsage}%`,
                metric: 'disk',
                value: diskUsage
            });
        }

        // Temperature alert
        if (metrics.system.temperature && metrics.system.temperature > 70) {
            alerts.push({
                type: 'warning',
                message: `High temperature: ${metrics.system.temperature}°C`,
                metric: 'temperature',
                value: metrics.system.temperature
            });
        }

        // Interface errors alert
        if (metrics.traffic.errors > 100) {
            alerts.push({
                type: 'warning',
                message: `High interface errors: ${metrics.traffic.errors}`,
                metric: 'errors',
                value: metrics.traffic.errors
            });
        }

        // Process alerts
        for (const alert of alerts) {
            const alertKey = `${device._id}-${alert.metric}`;
            
            if (!this.alerts.has(alertKey)) {
                // New alert
                this.alerts.set(alertKey, {
                    ...alert,
                    device: device.name,
                    deviceId: device._id,
                    timestamp: new Date(),
                    notificationSent: false
                });

                // Add to device alerts
                device.alerts.push({
                    type: alert.type,
                    message: alert.message,
                    timestamp: new Date()
                });

                // Send notification for critical alerts
                if (alert.type === 'critical') {
                    await sendAlert({
                        ...alert,
                        device: device.name
                    });
                }
            }
        }

        // Clear resolved alerts
        for (const [alertKey, alert] of this.alerts) {
            if (alertKey.startsWith(device._id.toString())) {
                const metric = alertKey.split('-')[1];
                const currentAlert = alerts.find(a => a.metric === metric);
                
                if (!currentAlert) {
                    // Alert resolved
                    this.alerts.delete(alertKey);
                    
                    // Mark device alert as resolved
                    const deviceAlert = device.alerts.find(a => 
                        a.message.includes(metric) && !a.resolved
                    );
                    if (deviceAlert) {
                        deviceAlert.resolved = true;
                    }
                }
            }
        }
    }

    async collectStatistics() {
        logger.info('Collecting hourly statistics...');

        try {
            const devices = await Device.find({ isActive: true });

            for (const device of devices) {
                try {
                    const monitor = await this.getDeviceMonitor(device);
                    const metrics = await this.collectDeviceMetrics(monitor.api);

                    // Store statistics
                    await DeviceStatistics.create({
                        device: device._id,
                        timestamp: new Date(),
                        system: {
                            cpuLoad: metrics.system.cpuLoad,
                            memoryUsage: Math.round((1 - metrics.system.freeMemory / metrics.system.totalMemory) * 100),
                            diskUsage: Math.round((1 - metrics.system.freeHddSpace / metrics.system.totalHddSpace) * 100),
                            temperature: metrics.system.temperature,
                            uptime: metrics.system.uptime
                        },
                        traffic: metrics.traffic,
                        hotspot: {
                            activeUsers: metrics.hotspot.activeUsers
                        }
                    });

                    logger.info(`Statistics collected for device ${device.name}`);
                } catch (error) {
                    logger.error(`Failed to collect statistics for ${device.name}: ${error.message}`);
                }
            }
        } catch (error) {
            logger.error(`Failed to collect statistics: ${error.message}`);
        }
    }

    async generateHealthReport() {
        logger.info('Generating daily health report...');

        try {
            const organizations = await Organization.find({ isActive: true });

            for (const org of organizations) {
                const devices = await Device.find({ 
                    organization: org._id,
                    isActive: true 
                });

                const report = {
                    organization: org.name,
                    date: new Date(),
                    totalDevices: devices.length,
                    onlineDevices: devices.filter(d => d.status === 'online').length,
                    offlineDevices: devices.filter(d => d.status === 'offline').length,
                    alerts: [],
                    deviceHealth: []
                };

                // Collect device health
                for (const device of devices) {
                    const health = {
                        name: device.name,
                        status: device.status,
                        uptime: device.health?.uptime,
                        cpuAvg: 0,
                        memoryAvg: 0,
                        diskUsage: device.health?.diskUsage,
                        activeAlerts: device.alerts.filter(a => !a.resolved).length
                    };

                    // Get average metrics from last 24 hours
                    const stats = await DeviceStatistics.find({
                        device: device._id,
                        timestamp: { $gte: new Date(Date.now() - 86400000) }
                    });

                    if (stats.length > 0) {
                        health.cpuAvg = Math.round(
                            stats.reduce((sum, s) => sum + s.system.cpuLoad, 0) / stats.length
                        );
                        health.memoryAvg = Math.round(
                            stats.reduce((sum, s) => sum + s.system.memoryUsage, 0) / stats.length
                        );
                    }

                    report.deviceHealth.push(health);

                    // Collect active alerts
                    const activeAlerts = device.alerts.filter(a => !a.resolved);
                    report.alerts.push(...activeAlerts.map(a => ({
                        device: device.name,
                        ...a
                    })));
                }

                // Send report
                await this.sendHealthReport(org, report);
            }
        } catch (error) {
            logger.error(`Failed to generate health report: ${error.message}`);
        }
    }

    async sendHealthReport(organization, report) {
        // TODO: Implement email sending
        logger.info(`Health report generated for ${organization.name}`);
        
        // For now, just emit via socket
        this.io.to(`org:${organization._id}`).emit('health:report', report);
    }

    decryptPassword(encryptedPassword) {
        // Implement proper decryption
        const crypto = require('crypto');
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
        
        try {
            const [ivHex, encrypted] = encryptedPassword.split(':');
            const iv = Buffer.from(ivHex, 'hex');
            
            const decipher = crypto.createDecipheriv(algorithm, key, iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            logger.error('Failed to decrypt password:', error);
            throw new Error('Decryption failed');
        }
    }
}

module.exports = DeviceMonitor;
EOF
}

# Create MikroTik script templates
create_mikrotik_templates() {
    # Hotspot setup template
    cat << 'EOF' > "$APP_DIR/src/mikrotik/templates/hotspot-setup.rsc"
# MikroTik Hotspot Setup Template
# Generated by MikroTik VPN Management System

# Set identity
/system identity set name="{{DEVICE_NAME}}"

# Configure hotspot interface
/interface bridge
add name=bridge-hotspot comment="Hotspot Bridge"

# Add hotspot interfaces to bridge
/interface bridge port
add bridge=bridge-hotspot interface={{HOTSPOT_INTERFACE}}

# Configure IP address for hotspot
/ip address
add address={{HOTSPOT_IP}}/24 interface=bridge-hotspot

# Configure DHCP server
/ip pool
add name=hotspot-pool ranges={{DHCP_RANGE}}

/ip dhcp-server
add address-pool=hotspot-pool disabled=no interface=bridge-hotspot name=hotspot-dhcp

/ip dhcp-server network
add address={{HOTSPOT_NETWORK}}/24 gateway={{HOTSPOT_IP}} dns-server=8.8.8.8,8.8.4.4

# Configure hotspot
/ip hotspot profile
add dns-name={{HOTSPOT_DNS_NAME}} hotspot-address={{HOTSPOT_IP}} name={{PROFILE_NAME}} \
    login-by=cookie,http-chap,trial use-radius=no

/ip hotspot
add address-pool=hotspot-pool disabled=no interface=bridge-hotspot name={{HOTSPOT_NAME}} \
    profile={{PROFILE_NAME}}

# Configure hotspot user profile
/ip hotspot user profile
add name="default" shared-users=1 rate-limit="2M/2M"
add name="premium" shared-users=1 rate-limit="5M/5M"
add name="vip" shared-users=2 rate-limit="10M/10M"

# Configure firewall for hotspot
/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=80,443,8291 src-address={{HOTSPOT_NETWORK}}/24 \
    comment="Allow hotspot management"
add chain=forward action=accept src-address={{HOTSPOT_NETWORK}}/24 out-interface={{WAN_INTERFACE}} \
    comment="Allow hotspot to internet"

# Configure NAT
/ip firewall nat
add chain=srcnat action=masquerade src-address={{HOTSPOT_NETWORK}}/24 out-interface={{WAN_INTERFACE}} \
    comment="Hotspot NAT"

# Configure walled garden (optional)
/ip hotspot walled-garden
add dst-host="*.google.com" comment="Allow Google"
add dst-host="*.facebook.com" comment="Allow Facebook"

# Configure hotspot pages
/ip hotspot profile
set [find name={{PROFILE_NAME}}] \
    html-directory=flash/hotspot \
    login-by=cookie,http-chap,trial

# Create default trial user
/ip hotspot user
add name="trial" profile="default" limit-uptime=30m comment="30-minute trial"

# Configure logging
/system logging
add topics=hotspot,info action=memory
add topics=hotspot,error action=memory

print "Hotspot setup completed successfully!"
EOF

    # VPN client setup template
    cat << 'EOF' > "$APP_DIR/src/mikrotik/templates/vpn-client-setup.rsc"
# MikroTik VPN Client Setup Template
# Connect to Management VPN Server

# Configure L2TP client
/interface l2tp-client
add connect-to={{VPN_SERVER}} name=vpn-mgmt user={{VPN_USER}} \
    password={{VPN_PASSWORD}} profile=default-encryption \
    add-default-route=no disabled=no comment="Management VPN"

# Wait for connection
:delay 5s

# Add route to management network
/ip route
add dst-address={{MGMT_NETWORK}}/24 gateway=vpn-mgmt

# Configure firewall to allow management access
/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=8728,8729,80,443,22 \
    src-address={{MGMT_NETWORK}}/24 comment="Allow management access"

# Enable API service
/ip service
set api disabled=no port=8728
set api-ssl disabled=no port=8729 certificate=api-ssl

# Configure API user
/user
add name={{API_USER}} password={{API_PASSWORD}} group=full \
    comment="API user for management system"

# Configure scheduled keepalive
/system scheduler
add name=vpn-keepalive interval=1m on-event="/ping {{VPN_SERVER}} count=3" \
    comment="Keep VPN connection alive"

print "VPN client setup completed successfully!"
EOF

    # Bandwidth management template
    cat << 'EOF' > "$APP_DIR/src/mikrotik/templates/bandwidth-management.rsc"
# MikroTik Bandwidth Management Template
# Configure QoS and bandwidth limits

# Create mangle rules for traffic marking
/ip firewall mangle
add chain=forward action=mark-connection new-connection-mark=hotspot-conn \
    src-address={{HOTSPOT_NETWORK}}/24 passthrough=yes comment="Mark hotspot connections"
add chain=forward action=mark-packet new-packet-mark=hotspot-packet \
    connection-mark=hotspot-conn passthrough=no comment="Mark hotspot packets"

# Create PCQ types for fair bandwidth distribution
/queue type
add name=pcq-download kind=pcq pcq-classifier=dst-address pcq-rate={{DOWNLOAD_RATE}}
add name=pcq-upload kind=pcq pcq-classifier=src-address pcq-rate={{UPLOAD_RATE}}

# Create queue tree for bandwidth management
/queue tree
add name=download parent=global packet-mark=hotspot-packet queue=pcq-download \
    max-limit={{TOTAL_DOWNLOAD}} comment="Total download bandwidth"
add name=upload parent=global packet-mark=hotspot-packet queue=pcq-upload \
    max-limit={{TOTAL_UPLOAD}} comment="Total upload bandwidth"

# Create simple queues for user profiles
/queue simple
add name="default-profile" target={{HOTSPOT_NETWORK}}/24 \
    max-limit={{DEFAULT_UP}}/{{DEFAULT_DOWN}} burst-limit={{DEFAULT_BURST_UP}}/{{DEFAULT_BURST_DOWN}} \
    burst-time=10s/10s burst-threshold={{DEFAULT_THRESHOLD_UP}}/{{DEFAULT_THRESHOLD_DOWN}} \
    comment="Default user profile limits"

# Configure queue priorities
/queue tree
add name=priority-high parent=download packet-mark=priority-high priority=1 queue=default
add name=priority-normal parent=download packet-mark=priority-normal priority=4 queue=default
add name=priority-low parent=download packet-mark=priority-low priority=8 queue=default

print "Bandwidth management configured successfully!"
EOF

    # Security hardening template
    cat << 'EOF' > "$APP_DIR/src/mikrotik/templates/security-hardening.rsc"
# MikroTik Security Hardening Template
# Implement security best practices

# Disable unnecessary services
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh port=22222 disabled=no
set api disabled=no address={{MGMT_NETWORK}}/24
set api-ssl disabled=no address={{MGMT_NETWORK}}/24 certificate=api-ssl
set winbox disabled=no address={{MGMT_NETWORK}}/24

# Configure strong passwords policy
/user
set [find name=admin] password={{ADMIN_PASSWORD}}

# Remove default user if exists
/user remove [find name=admin !default]

# Configure firewall - Input chain
/ip firewall filter
add chain=input action=accept connection-state=established,related \
    comment="Accept established/related"
add chain=input action=accept protocol=icmp comment="Accept ICMP"
add chain=input action=accept dst-port=8728,8729,22222 protocol=tcp \
    src-address={{MGMT_NETWORK}}/24 comment="Accept management"
add chain=input action=accept in-interface=bridge-hotspot dst-port=53 protocol=udp \
    comment="Accept DNS from hotspot"
add chain=input action=drop comment="Drop everything else"

# Configure firewall - Forward chain
/ip firewall filter
add chain=forward action=accept connection-state=established,related \
    comment="Accept established/related"
add chain=forward action=accept src-address={{HOTSPOT_NETWORK}}/24 \
    out-interface={{WAN_INTERFACE}} comment="Allow hotspot to internet"
add chain=forward action=drop connection-state=invalid comment="Drop invalid"
add chain=forward action=drop comment="Drop everything else"

# Configure port knocking (optional)
/ip firewall filter
add chain=input action=add-src-to-address-list address-list=knock-step1 \
    address-list-timeout=10s dst-port=1111 protocol=tcp comment="Port knock step 1"
add chain=input action=add-src-to-address-list address-list=knock-step2 \
    address-list-timeout=10s dst-port=2222 protocol=tcp src-address-list=knock-step1
add chain=input action=add-src-to-address-list address-list=secure-access \
    address-list-timeout=1h dst-port=3333 protocol=tcp src-address-list=knock-step2
add chain=input action=accept dst-port=8291 protocol=tcp src-address-list=secure-access \
    comment="Allow WinBox after port knocking"

# Configure DDoS protection
/ip firewall filter
add chain=input action=drop connection-limit=50,32 protocol=tcp comment="Limit connections"
add chain=input action=drop src-address-list=blacklist comment="Drop blacklisted"
add chain=input action=add-src-to-address-list address-list=blacklist \
    address-list-timeout=1d connection-state=new connection-limit=100,32 protocol=tcp \
    comment="Blacklist excessive connections"

# Enable secure neighbor discovery
/ip neighbor discovery-settings
set discover-interface-list=none

# Configure NTP
/system ntp client
set enabled=yes server-dns-names=pool.ntp.org

# Configure logging
/system logging
add topics=firewall,warning action=memory
add topics=system,error,critical action=memory

print "Security hardening completed successfully!"
EOF

    log "MikroTik templates created"
}

# =============================================================================
# PHASE 2.2: HOTSPOT USER MANAGEMENT
# =============================================================================

phase2_2_hotspot_management() {
    log "=== Phase 2.2: Setting up Hotspot User Management ==="
    
    # Create hotspot management controllers
    create_hotspot_controller
    
    # Create hotspot user model
    create_hotspot_user_model
    
    # Create hotspot profile model
    create_hotspot_profile_model
    
    # Create hotspot session tracking
    create_session_tracking
    
    log "Phase 2.2 completed!"
}

# Create hotspot controller
create_hotspot_controller() {
    cat << 'EOF' > "$APP_DIR/controllers/hotspotController.js"
const HotspotUser = require('../models/HotspotUser');
const HotspotProfile = require('../models/HotspotProfile');
const Device = require('../models/Device');
const MikroTikAPI = require('../src/mikrotik/lib/mikrotik-api');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');

class HotspotController {
    // Get all hotspot users
    async getUsers(req, res, next) {
        try {
            const { deviceId, status, profile } = req.query;
            
            const query = { organization: req.user.organization };
            
            if (deviceId) query.device = deviceId;
            if (status) query.status = status;
            if (profile) query.profile = profile;
            
            const users = await HotspotUser.find(query)
                .populate('device')
                .populate('profile')
                .sort({ createdAt: -1 });
            
            res.json({
                success: true,
                count: users.length,
                data: users
            });
        } catch (error) {
            next(error);
        }
    }

    // Get single hotspot user
    async getUser(req, res, next) {
        try {
            const user = await HotspotUser.findOne({
                _id: req.params.id,
                organization: req.user.organization
            })
            .populate('device')
            .populate('profile')
            .populate('sessions');
            
            if (!user) {
                return res.status(404).json({
                    success: false,
                    error: 'User not found'
                });
            }
            
            res.json({
                success: true,
                data: user
            });
        } catch (error) {
            next(error);
        }
    }

    // Create hotspot user
    async createUser(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const {
                deviceId,
                username,
                password,
                profileId,
                macAddress,
                limitUptime,
                limitBytesTotal,
                validFrom,
                validTo,
                comment
            } = req.body;

            // Get device
            const device = await Device.findOne({
                _id: deviceId,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            // Get profile
            const profile = await HotspotProfile.findOne({
                _id: profileId,
                organization: req.user.organization
            });

            if (!profile) {
                return res.status(404).json({
                    success: false,
                    error: 'Profile not found'
                });
            }

            // Create user in MikroTik
            const api = await this.getDeviceConnection(device);
            
            const mikrotikUser = await api.addHotspotUser({
                username,
                password,
                profile: profile.mikrotikName,
                macAddress,
                limitUptime,
                limitBytesTotal,
                comment: comment || `Created by ${req.user.name}`
            });

            // Create user in database
            const user = await HotspotUser.create({
                organization: req.user.organization,
                device: device._id,
                username,
                password: this.hashPassword(password),
                profile: profile._id,
                macAddress: macAddress?.toUpperCase(),
                limits: {
                    uptime: limitUptime,
                    bytesTotal: limitBytesTotal,
                    rateLimit: profile.rateLimit
                },
                validity: {
                    from: validFrom || new Date(),
                    to: validTo
                },
                mikrotikId: mikrotikUser['.id'],
                status: 'active',
                createdBy: req.user._id,
                comment
            });

            await user.populate('device profile');

            res.status(201).json({
                success: true,
                data: user
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'hotspot_user_create',
                target: user._id,
                details: {
                    username: user.username,
                    device: device.name,
                    profile: profile.name
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Update hotspot user
    async updateUser(req, res, next) {
        try {
            const user = await HotspotUser.findOne({
                _id: req.params.id,
                organization: req.user.organization
            }).populate('device');

            if (!user) {
                return res.status(404).json({
                    success: false,
                    error: 'User not found'
                });
            }

            const updates = req.body;

            // Update in MikroTik
            if (user.mikrotikId && user.device) {
                const api = await this.getDeviceConnection(user.device);
                
                const mikrotikUpdates = {};
                if (updates.password) mikrotikUpdates.password = updates.password;
                if (updates.limitUptime) mikrotikUpdates['limit-uptime'] = updates.limitUptime;
                if (updates.limitBytesTotal) mikrotikUpdates['limit-bytes-total'] = updates.limitBytesTotal;
                if (updates.macAddress) mikrotikUpdates['mac-address'] = updates.macAddress;
                if (updates.comment) mikrotikUpdates.comment = updates.comment;
                
                await api.updateHotspotUser(user.username, mikrotikUpdates);
            }

            // Update in database
            if (updates.password) {
                updates.password = this.hashPassword(updates.password);
            }

            Object.assign(user, updates);
            await user.save();

            res.json({
                success: true,
                data: user
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'hotspot_user_update',
                target: user._id,
                details: {
                    username: user.username,
                    updates: Object.keys(updates)
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Delete hotspot user
    async deleteUser(req, res, next) {
        try {
            const user = await HotspotUser.findOne({
                _id: req.params.id,
                organization: req.user.organization
            }).populate('device');

            if (!user) {
                return res.status(404).json({
                    success: false,
                    error: 'User not found'
                });
            }

            // Delete from MikroTik
            if (user.mikrotikId && user.device) {
                try {
                    const api = await this.getDeviceConnection(user.device);
                    await api.removeHotspotUser(user.username);
                } catch (error) {
                    logger.error(`Failed to delete user from MikroTik: ${error.message}`);
                }
            }

            // Delete from database
            await user.remove();

            res.json({
                success: true,
                data: {}
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'hotspot_user_delete',
                target: user._id,
                details: {
                    username: user.username
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Bulk create users
    async bulkCreateUsers(req, res, next) {
        try {
            const {
                deviceId,
                profileId,
                prefix,
                count,
                passwordLength,
                validityDays,
                limitUptime,
                limitBytesTotal
            } = req.body;

            // Validate count
            if (count > 1000) {
                return res.status(400).json({
                    success: false,
                    error: 'Cannot create more than 1000 users at once'
                });
            }

            // Get device and profile
            const [device, profile] = await Promise.all([
                Device.findOne({ _id: deviceId, organization: req.user.organization }),
                HotspotProfile.findOne({ _id: profileId, organization: req.user.organization })
            ]);

            if (!device || !profile) {
                return res.status(404).json({
                    success: false,
                    error: 'Device or profile not found'
                });
            }

            const api = await this.getDeviceConnection(device);
            const users = [];
            const errors = [];
            
            const validFrom = new Date();
            const validTo = validityDays ? 
                new Date(Date.now() + validityDays * 86400000) : null;

            // Generate users
            for (let i = 0; i < count; i++) {
                const username = `${prefix}${String(i + 1).padStart(4, '0')}`;
                const password = this.generatePassword(passwordLength || 8);

                try {
                    // Create in MikroTik
                    const mikrotikUser = await api.addHotspotUser({
                        username,
                        password,
                        profile: profile.mikrotikName,
                        limitUptime: limitUptime || profile.limits?.uptime,
                        limitBytesTotal: limitBytesTotal || profile.limits?.bytesTotal,
                        comment: `Bulk created by ${req.user.name}`
                    });

                    // Create in database
                    const user = await HotspotUser.create({
                        organization: req.user.organization,
                        device: device._id,
                        username,
                        password: this.hashPassword(password),
                        plainPassword: password, // Store temporarily for export
                        profile: profile._id,
                        limits: {
                            uptime: limitUptime || profile.limits?.uptime,
                            bytesTotal: limitBytesTotal || profile.limits?.bytesTotal,
                            rateLimit: profile.rateLimit
                        },
                        validity: { from: validFrom, to: validTo },
                        mikrotikId: mikrotikUser['.id'],
                        status: 'active',
                        createdBy: req.user._id,
                        isBulkCreated: true
                    });

                    users.push(user);
                } catch (error) {
                    errors.push({
                        username,
                        error: error.message
                    });
                }
            }

            res.json({
                success: true,
                data: {
                    created: users.length,
                    failed: errors.length,
                    users: users.map(u => ({
                        _id: u._id,
                        username: u.username,
                        password: u.plainPassword
                    })),
                    errors
                }
            });

            // Clean up plainPassword after response
            setTimeout(async () => {
                await HotspotUser.updateMany(
                    { _id: { $in: users.map(u => u._id) } },
                    { $unset: { plainPassword: 1 } }
                );
            }, 60000); // 1 minute

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'hotspot_user_bulk_create',
                details: {
                    count: users.length,
                    prefix,
                    device: device.name,
                    profile: profile.name
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Get active sessions
    async getActiveSessions(req, res, next) {
        try {
            const { deviceId } = req.query;

            let devices;
            if (deviceId) {
                devices = await Device.find({
                    _id: deviceId,
                    organization: req.user.organization
                });
            } else {
                devices = await Device.find({
                    organization: req.user.organization,
                    status: 'online'
                });
            }

            const allSessions = [];

            for (const device of devices) {
                try {
                    const api = await this.getDeviceConnection(device);
                    const sessions = await api.getHotspotActive();
                    
                    // Enhance session data
                    const enhancedSessions = sessions.map(session => ({
                        ...session,
                        device: {
                            _id: device._id,
                            name: device.name
                        },
                        startTime: new Date(Date.now() - this.parseUptime(session.uptime)),
                        bytesIn: parseInt(session['bytes-in'] || 0),
                        bytesOut: parseInt(session['bytes-out'] || 0),
                        packetsIn: parseInt(session['packets-in'] || 0),
                        packetsOut: parseInt(session['packets-out'] || 0)
                    }));

                    allSessions.push(...enhancedSessions);
                } catch (error) {
                    logger.error(`Failed to get sessions from ${device.name}: ${error.message}`);
                }
            }

            res.json({
                success: true,
                count: allSessions.length,
                data: allSessions
            });
        } catch (error) {
            next(error);
        }
    }

    // Disconnect user session
    async disconnectSession(req, res, next) {
        try {
            const { deviceId, sessionId } = req.params;

            const device = await Device.findOne({
                _id: deviceId,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            const api = await this.getDeviceConnection(device);
            await api.disconnectHotspotUser(sessionId);

            res.json({
                success: true,
                message: 'Session disconnected successfully'
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'hotspot_session_disconnect',
                details: {
                    device: device.name,
                    sessionId
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Get hotspot profiles
    async getProfiles(req, res, next) {
        try {
            const profiles = await HotspotProfile.find({
                organization: req.user.organization
            }).sort({ name: 1 });

            res.json({
                success: true,
                count: profiles.length,
                data: profiles
            });
        } catch (error) {
            next(error);
        }
    }

    // Create hotspot profile
    async createProfile(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const profile = await HotspotProfile.create({
                ...req.body,
                organization: req.user.organization,
                createdBy: req.user._id
            });

            res.status(201).json({
                success: true,
                data: profile
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'hotspot_profile_create',
                details: {
                    name: profile.name
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Update hotspot profile
    async updateProfile(req, res, next) {
        try {
            const profile = await HotspotProfile.findOneAndUpdate(
                {
                    _id: req.params.id,
                    organization: req.user.organization
                },
                req.body,
                {
                    new: true,
                    runValidators: true
                }
            );

            if (!profile) {
                return res.status(404).json({
                    success: false,
                    error: 'Profile not found'
                });
            }

            res.json({
                success: true,
                data: profile
            });

            // Update users with this profile in MikroTik devices
            // This is done asynchronously in the background
            this.updateProfileInDevices(profile);

        } catch (error) {
            next(error);
        }
    }

    // Delete hotspot profile
    async deleteProfile(req, res, next) {
        try {
            // Check if profile is in use
            const usersCount = await HotspotUser.countDocuments({
                profile: req.params.id,
                organization: req.user.organization
            });

            if (usersCount > 0) {
                return res.status(400).json({
                    success: false,
                    error: `Profile is in use by ${usersCount} users`
                });
            }

            const profile = await HotspotProfile.findOneAndDelete({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!profile) {
                return res.status(404).json({
                    success: false,
                    error: 'Profile not found'
                });
            }

            res.json({
                success: true,
                data: {}
            });

        } catch (error) {
            next(error);
        }
    }

    // Export users to CSV
    async exportUsers(req, res, next) {
        try {
            const { deviceId, profileId, status } = req.query;
            
            const query = { organization: req.user.organization };
            if (deviceId) query.device = deviceId;
            if (profileId) query.profile = profileId;
            if (status) query.status = status;

            const users = await HotspotUser.find(query)
                .populate('device profile')
                .sort({ createdAt: -1 });

            // Create CSV
            const csv = [
                'Username,Password,Profile,Device,MAC Address,Status,Created At,Valid Until'
            ];

            users.forEach(user => {
                csv.push([
                    user.username,
                    user.plainPassword || '***',
                    user.profile?.name || '',
                    user.device?.name || '',
                    user.macAddress || '',
                    user.status,
                    user.createdAt.toISOString(),
                    user.validity?.to?.toISOString() || 'Unlimited'
                ].join(','));
            });

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=hotspot-users.csv');
            res.send(csv.join('\n'));

        } catch (error) {
            next(error);
        }
    }

    // Helper methods
    async getDeviceConnection(device) {
        const deviceController = require('./deviceController');
        return deviceController.getDeviceConnection(device);
    }

    hashPassword(password) {
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(password).digest('hex');
    }

    generatePassword(length = 8) {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
        let password = '';
        
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        return password;
    }

    parseUptime(uptime) {
        // Parse MikroTik uptime format (e.g., "1d2h3m4s")
        const regex = /(\d+)([dhms])/g;
        let totalMs = 0;
        let match;

        while ((match = regex.exec(uptime)) !== null) {
            const value = parseInt(match[1]);
            const unit = match[2];

            switch (unit) {
                case 'd': totalMs += value * 86400000; break;
                case 'h': totalMs += value * 3600000; break;
                case 'm': totalMs += value * 60000; break;
                case 's': totalMs += value * 1000; break;
            }
        }

        return totalMs;
    }

    async updateProfileInDevices(profile) {
        try {
            // Get all users with this profile
            const users = await HotspotUser.find({
                profile: profile._id,
                status: 'active'
            }).populate('device');

            // Group users by device
            const usersByDevice = users.reduce((acc, user) => {
                if (!user.device) return acc;
                
                const deviceId = user.device._id.toString();
                if (!acc[deviceId]) {
                    acc[deviceId] = {
                        device: user.device,
                        users: []
                    };
                }
                acc[deviceId].users.push(user);
                return acc;
            }, {});

            // Update each device
            for (const deviceData of Object.values(usersByDevice)) {
                try {
                    const api = await this.getDeviceConnection(deviceData.device);
                    
                    // Update each user
                    for (const user of deviceData.users) {
                        await api.updateHotspotUser(user.username, {
                            profile: profile.mikrotikName,
                            'limit-uptime': profile.limits?.uptime,
                            'limit-bytes-total': profile.limits?.bytesTotal
                        });
                    }
                } catch (error) {
                    logger.error(`Failed to update profile in device ${deviceData.device.name}: ${error.message}`);
                }
            }
        } catch (error) {
            logger.error(`Failed to update profile in devices: ${error.message}`);
        }
    }

    async logActivity(activity) {
        const ActivityLog = require('../models/ActivityLog');
        await ActivityLog.create(activity);
    }
}

module.exports = new HotspotController();
EOF
}

# Create hotspot user model
create_hotspot_user_model() {
    cat << 'EOF' > "$APP_DIR/models/HotspotUser.js"
const mongoose = require('mongoose');

const hotspotUserSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true,
        index: true
    },
    device: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Device',
        required: true,
        index: true
    },
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        index: true
    },
    password: {
        type: String,
        required: true
    },
    plainPassword: {
        type: String,
        select: false // Only for temporary storage during bulk creation
    },
    profile: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HotspotProfile',
        required: true
    },
    macAddress: {
        type: String,
        uppercase: true,
        trim: true,
        match: /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/,
        index: true
    },
    status: {
        type: String,
        enum: ['active', 'suspended', 'expired', 'deleted'],
        default: 'active',
        index: true
    },
    limits: {
        uptime: String, // e.g., "1h", "1d", "1w"
        bytesTotal: Number, // Total bytes allowed
        rateLimit: String, // e.g., "2M/2M" (upload/download)
        sessionTimeout: Number, // Session timeout in seconds
        idleTimeout: Number, // Idle timeout in seconds
        concurrentSessions: {
            type: Number,
            default: 1
        }
    },
    usage: {
        totalTime: {
            type: Number,
            default: 0 // Total time used in seconds
        },
        totalBytes: {
            type: Number,
            default: 0 // Total bytes used
        },
        lastLogin: Date,
        lastLogout: Date,
        loginCount: {
            type: Number,
            default: 0
        }
    },
    validity: {
        from: {
            type: Date,
            default: Date.now
        },
        to: Date,
        firstLogin: Date // Validity starts from first login
    },
    mikrotikId: String, // MikroTik internal ID
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    isBulkCreated: {
        type: Boolean,
        default: false
    },
    comment: String,
    metadata: {
        customerName: String,
        customerPhone: String,
        customerEmail: String,
        roomNumber: String,
        voucherCode: String,
        paymentReference: String
    },
    tags: [String]
}, {
    timestamps: true
});

// Indexes
hotspotUserSchema.index({ organization: 1, device: 1, username: 1 });
hotspotUserSchema.index({ organization: 1, status: 1 });
hotspotUserSchema.index({ 'validity.to': 1 });
hotspotUserSchema.index({ 'metadata.voucherCode': 1 });

// Virtual for sessions
hotspotUserSchema.virtual('sessions', {
    ref: 'HotspotSession',
    localField: '_id',
    foreignField: 'user'
});

// Virtual for isExpired
hotspotUserSchema.virtual('isExpired').get(function() {
    if (!this.validity.to) return false;
    return new Date() > this.validity.to;
});

// Virtual for isValid
hotspotUserSchema.virtual('isValid').get(function() {
    const now = new Date();
    
    // Check date validity
    if (this.validity.from && now < this.validity.from) return false;
    if (this.validity.to && now > this.validity.to) return false;
    
    // Check usage limits
    if (this.limits.uptime && this.usage.totalTime >= this.parseUptime(this.limits.uptime)) {
        return false;
    }
    
    if (this.limits.bytesTotal && this.usage.totalBytes >= this.limits.bytesTotal) {
        return false;
    }
    
    return this.status === 'active';
});

// Methods
hotspotUserSchema.methods.parseUptime = function(uptime) {
    // Parse uptime string to seconds
    const units = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400,
        'w': 604800
    };
    
    const match = uptime.match(/^(\d+)([smhdw])$/);
    if (!match) return 0;
    
    return parseInt(match[1]) * units[match[2]];
};

hotspotUserSchema.methods.checkAndUpdateStatus = async function() {
    if (this.isExpired || !this.isValid) {
        this.status = 'expired';
        await this.save();
        return false;
    }
    return true;
};

hotspotUserSchema.methods.updateUsage = async function(session) {
    this.usage.totalTime += session.duration || 0;
    this.usage.totalBytes += (session.bytesIn || 0) + (session.bytesOut || 0);
    this.usage.loginCount += 1;
    this.usage.lastLogin = session.startTime;
    this.usage.lastLogout = session.endTime || new Date();
    
    // Check if limits exceeded
    await this.checkAndUpdateStatus();
    
    await this.save();
};

// Middleware
hotspotUserSchema.pre('save', function(next) {
    // Auto-expire if validity date passed
    if (this.validity.to && new Date() > this.validity.to) {
        this.status = 'expired';
    }
    next();
});

// Static methods
hotspotUserSchema.statics.cleanupExpired = async function() {
    const expiredUsers = await this.find({
        status: 'active',
        'validity.to': { $lt: new Date() }
    });
    
    for (const user of expiredUsers) {
        user.status = 'expired';
        await user.save();
    }
    
    return expiredUsers.length;
};

module.exports = mongoose.model('HotspotUser', hotspotUserSchema);
EOF
}

# Create hotspot profile model
create_hotspot_profile_model() {
    cat << 'EOF' > "$APP_DIR/models/HotspotProfile.js"
const mongoose = require('mongoose');

const hotspotProfileSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true,
        index: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    mikrotikName: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    description: String,
    type: {
        type: String,
        enum: ['time-based', 'data-based', 'unlimited', 'hybrid'],
        default: 'time-based'
    },
    limits: {
        uptime: String, // e.g., "1h", "1d", "1w"
        bytesTotal: Number, // Total bytes allowed
        bytesIn: Number, // Download limit
        bytesOut: Number, // Upload limit
        rateLimit: String, // e.g., "2M/2M" (upload/download)
        burstRate: String, // e.g., "4M/4M"
        burstThreshold: String, // e.g., "1M/1M"
        burstTime: String, // e.g., "10s/10s"
        sessionTimeout: Number, // Session timeout in seconds
        idleTimeout: Number, // Idle timeout in seconds
        keepaliveTimeout: Number, // Keepalive timeout
        concurrentSessions: {
            type: Number,
            default: 1
        }
    },
    pricing: {
        currency: {
            type: String,
            default: 'THB'
        },
        price: {
            type: Number,
            default: 0
        },
        validityDays: Number,
        autoRenew: {
            type: Boolean,
            default: false
        }
    },
    qos: {
        priority: {
            type: Number,
            min: 1,
            max: 8,
            default: 4
        },
        queueType: {
            type: String,
            enum: ['default', 'pcq', 'sfq', 'red'],
            default: 'default'
        }
    },
    features: {
        transparentProxy: {
            type: Boolean,
            default: true
        },
        walledGarden: {
            type: Boolean,
            default: true
        },
        macCookies: {
            type: Boolean,
            default: true
        },
        trial: {
            enabled: {
                type: Boolean,
                default: false
            },
            duration: String, // e.g., "30m"
            dataLimit: Number // Bytes
        }
    },
    redirectUrl: String,
    onLoginScript: String,
    onLogoutScript: String,
    isDefault: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    },
    tags: [String],
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, {
    timestamps: true
});

// Indexes
hotspotProfileSchema.index({ organization: 1, name: 1 }, { unique: true });
hotspotProfileSchema.index({ organization: 1, mikrotikName: 1 });
hotspotProfileSchema.index({ organization: 1, isDefault: 1 });

// Virtual for user count
hotspotProfileSchema.virtual('userCount', {
    ref: 'HotspotUser',
    localField: '_id',
    foreignField: 'profile',
    count: true
});

// Methods
hotspotProfileSchema.methods.generateMikrotikCommands = function() {
    const commands = [];
    
    // Base profile command
    const profileCmd = {
        command: '/ip/hotspot/user/profile/add',
        params: {
            name: this.mikrotikName,
            'session-timeout': this.limits.sessionTimeout || '4h',
            'idle-timeout': this.limits.idleTimeout || '5m',
            'keepalive-timeout': this.limits.keepaliveTimeout || '2m',
            'shared-users': this.limits.concurrentSessions || 1
        }
    };
    
    // Add rate limits
    if (this.limits.rateLimit) {
        profileCmd.params['rate-limit'] = this.limits.rateLimit;
    }
    
    // Add burst settings
    if (this.limits.burstRate) {
        const [burstUp, burstDown] = this.limits.burstRate.split('/');
        const [thresholdUp, thresholdDown] = (this.limits.burstThreshold || '1M/1M').split('/');
        const [timeUp, timeDown] = (this.limits.burstTime || '10s/10s').split('/');
        
        profileCmd.params['rate-limit'] = 
            `${this.limits.rateLimit} ${burstDown}/${burstUp} ${thresholdDown}/${thresholdUp} ${timeDown}/${timeUp}`;
    }
    
    // Add scripts
    if (this.onLoginScript) {
        profileCmd.params['on-login'] = this.onLoginScript;
    }
    
    if (this.onLogoutScript) {
        profileCmd.params['on-logout'] = this.onLogoutScript;
    }
    
    commands.push(profileCmd);
    
    // Queue configuration if priority is set
    if (this.qos.priority !== 4) {
        commands.push({
            command: '/queue/simple/add',
            params: {
                name: `hotspot-${this.mikrotikName}`,
                target: 'hotspot',
                priority: `${this.qos.priority}/${this.qos.priority}`,
                queue: `${this.qos.queueType}-default/${this.qos.queueType}-default`
            }
        });
    }
    
    return commands;
};

// Static methods
hotspotProfileSchema.statics.findDefault = async function(organizationId) {
    return this.findOne({
        organization: organizationId,
        isDefault: true,
        isActive: true
    });
};

// Middleware
hotspotProfileSchema.pre('save', async function(next) {
    // Ensure only one default profile per organization
    if (this.isDefault && this.isModified('isDefault')) {
        await this.constructor.updateMany(
            {
                organization: this.organization,
                _id: { $ne: this._id }
            },
            { isDefault: false }
        );
    }
    
    // Generate mikrotikName if not provided
    if (!this.mikrotikName) {
        this.mikrotikName = this.name.toLowerCase().replace(/[^a-z0-9]/g, '-');
    }
    
    next();
});

module.exports = mongoose.model('HotspotProfile', hotspotProfileSchema);
EOF
}

# Create session tracking
create_session_tracking() {
    cat << 'EOF' > "$APP_DIR/models/HotspotSession.js"
const mongoose = require('mongoose');

const hotspotSessionSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true,
        index: true
    },
    device: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Device',
        required: true,
        index: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HotspotUser',
        required: true,
        index: true
    },
    sessionId: {
        type: String,
        required: true,
        index: true
    },
    username: {
        type: String,
        required: true,
        index: true
    },
    macAddress: {
        type: String,
        uppercase: true,
        trim: true
    },
    ipAddress: String,
    nasIpAddress: String,
    calledStationId: String,
    callingStationId: String,
    framedProtocol: String,
    serviceType: String,
    startTime: {
        type: Date,
        required: true,
        default: Date.now,
        index: true
    },
    endTime: {
        type: Date,
        index: true
    },
    duration: Number, // Session duration in seconds
    traffic: {
        bytesIn: {
            type: Number,
            default: 0
        },
        bytesOut: {
            type: Number,
            default: 0
        },
        packetsIn: {
            type: Number,
            default: 0
        },
        packetsOut: {
            type: Number,
            default: 0
        }
    },
    status: {
        type: String,
        enum: ['active', 'closed', 'terminated', 'error'],
        default: 'active',
        index: true
    },
    terminationCause: String,
    accounting: {
        inputGigawords: Number,
        outputGigawords: Number,
        inputOctets: Number,
        outputOctets: Number,
        sessionTime: Number
    },
    location: {
        hostname: String,
        ssid: String,
        apMac: String,
        signal: Number
    },
    userAgent: String,
    platform: String,
    browser: String
}, {
    timestamps: true
});

// Indexes
hotspotSessionSchema.index({ organization: 1, startTime: -1 });
hotspotSessionSchema.index({ organization: 1, device: 1, status: 1 });
hotspotSessionSchema.index({ user: 1, startTime: -1 });
hotspotSessionSchema.index({ endTime: 1 }, { sparse: true });

// Virtual for total bytes
hotspotSessionSchema.virtual('totalBytes').get(function() {
    return (this.traffic.bytesIn || 0) + (this.traffic.bytesOut || 0);
});

// Virtual for average speed
hotspotSessionSchema.virtual('averageSpeed').get(function() {
    if (!this.duration || this.duration === 0) return 0;
    return Math.round(this.totalBytes / this.duration);
});

// Methods
hotspotSessionSchema.methods.calculateDuration = function() {
    if (!this.endTime) {
        this.duration = Math.floor((Date.now() - this.startTime) / 1000);
    } else {
        this.duration = Math.floor((this.endTime - this.startTime) / 1000);
    }
    return this.duration;
};

hotspotSessionSchema.methods.close = async function(traffic, cause) {
    this.endTime = new Date();
    this.status = 'closed';
    this.terminationCause = cause || 'user-request';
    
    if (traffic) {
        this.traffic = {
            bytesIn: traffic.bytesIn || 0,
            bytesOut: traffic.bytesOut || 0,
            packetsIn: traffic.packetsIn || 0,
            packetsOut: traffic.packetsOut || 0
        };
    }
    
    this.calculateDuration();
    
    // Update user usage
    const HotspotUser = mongoose.model('HotspotUser');
    const user = await HotspotUser.findById(this.user);
    if (user) {
        await user.updateUsage(this);
    }
    
    await this.save();
};

// Static methods
hotspotSessionSchema.statics.getActiveSessions = async function(query = {}) {
    return this.find({
        ...query,
        status: 'active',
        endTime: null
    }).populate('user device');
};

hotspotSessionSchema.statics.closeActiveSessions = async function(deviceId) {
    const sessions = await this.find({
        device: deviceId,
        status: 'active',
        endTime: null
    });
    
    for (const session of sessions) {
        await session.close(null, 'device-disconnected');
    }
    
    return sessions.length;
};

hotspotSessionSchema.statics.getStatistics = async function(organizationId, startDate, endDate) {
    const pipeline = [
        {
            $match: {
                organization: mongoose.Types.ObjectId(organizationId),
                startTime: {
                    $gte: startDate,
                    $lte: endDate
                }
            }
        },
        {
            $group: {
                _id: null,
                totalSessions: { $sum: 1 },
                totalDuration: { $sum: '$duration' },
                totalBytesIn: { $sum: '$traffic.bytesIn' },
                totalBytesOut: { $sum: '$traffic.bytesOut' },
                uniqueUsers: { $addToSet: '$user' },
                avgSessionDuration: { $avg: '$duration' }
            }
        },
        {
            $project: {
                _id: 0,
                totalSessions: 1,
                totalDuration: 1,
                totalBytesIn: 1,
                totalBytesOut: 1,
                totalBytes: { $add: ['$totalBytesIn', '$totalBytesOut'] },
                uniqueUsers: { $size: '$uniqueUsers' },
                avgSessionDuration: { $round: ['$avgSessionDuration', 0] }
            }
        }
    ];
    
    const result = await this.aggregate(pipeline);
    return result[0] || {
        totalSessions: 0,
        totalDuration: 0,
        totalBytesIn: 0,
        totalBytesOut: 0,
        totalBytes: 0,
        uniqueUsers: 0,
        avgSessionDuration: 0
    };
};

// Middleware
hotspotSessionSchema.pre('save', function(next) {
    // Calculate duration if endTime is set
    if (this.endTime && this.startTime) {
        this.calculateDuration();
    }
    next();
});

module.exports = mongoose.model('HotspotSession', hotspotSessionSchema);
EOF
}

# =============================================================================
# PHASE 2.3: VOUCHER SYSTEM
# =============================================================================

phase2_3_voucher_system() {
    log "=== Phase 2.3: Setting up Voucher System ==="
    
    # Create voucher model
    create_voucher_model
    
    # Create voucher controller
    create_voucher_controller
    
    # Create voucher templates
    create_voucher_templates
    
    # Create voucher printing service
    create_voucher_printing_service
    
    log "Phase 2.3 completed!"
}

# Create voucher model
create_voucher_model() {
    cat << 'EOF' > "$APP_DIR/models/Voucher.js"
const mongoose = require('mongoose');
const crypto = require('crypto');

const voucherSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true,
        index: true
    },
    batch: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'VoucherBatch',
        required: true,
        index: true
    },
    code: {
        type: String,
        required: true,
        unique: true,
        uppercase: true,
        index: true
    },
    profile: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HotspotProfile',
        required: true
    },
    status: {
        type: String,
        enum: ['available', 'sold', 'used', 'expired', 'cancelled'],
        default: 'available',
        index: true
    },
    validity: {
        days: Number, // Validity in days from activation
        from: Date,
        to: Date
    },
    price: {
        amount: Number,
        currency: {
            type: String,
            default: 'THB'
        }
    },
    seller: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    soldAt: Date,
    soldTo: {
        name: String,
        phone: String,
        email: String,
        reference: String
    },
    activatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HotspotUser'
    },
    activatedAt: Date,
    activationDevice: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Device'
    },
    usageStats: {
        totalTime: Number, // Seconds
        totalBytes: Number,
        lastUsed: Date
    },
    printCount: {
        type: Number,
        default: 0
    },
    lastPrintedAt: Date,
    lastPrintedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    qrCode: String, // Base64 encoded QR code
    barcode: String, // Barcode if needed
    comment: String,
    tags: [String]
}, {
    timestamps: true
});

// Indexes
voucherSchema.index({ organization: 1, status: 1 });
voucherSchema.index({ organization: 1, batch: 1 });
voucherSchema.index({ soldAt: 1 });
voucherSchema.index({ activatedAt: 1 });

// Methods
voucherSchema.methods.generateCode = function(prefix = '', length = 10) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude confusing characters
    let code = prefix;
    
    for (let i = 0; i < length; i++) {
        if (i > 0 && i % 4 === 0) {
            code += '-'; // Add dash every 4 characters
        }
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    this.code = code;
    return code;
};

voucherSchema.methods.generateQRCode = async function() {
    const QRCode = require('qrcode');
    
    const data = {
        code: this.code,
        url: `${process.env.HOTSPOT_URL}/voucher/${this.code}`
    };
    
    try {
        this.qrCode = await QRCode.toDataURL(JSON.stringify(data), {
            errorCorrectionLevel: 'M',
            type: 'image/png',
            quality: 0.92,
            margin: 1,
            color: {
                dark: '#000000',
                light: '#FFFFFF'
            },
            width: 256
        });
    } catch (error) {
        console.error('Failed to generate QR code:', error);
    }
};

voucherSchema.methods.activate = async function(userId, deviceId) {
    if (this.status !== 'sold' && this.status !== 'available') {
        throw new Error('Voucher cannot be activated');
    }
    
    this.status = 'used';
    this.activatedBy = userId;
    this.activatedAt = new Date();
    this.activationDevice = deviceId;
    
    // Set validity period
    if (this.validity.days) {
        this.validity.from = new Date();
        this.validity.to = new Date(Date.now() + this.validity.days * 86400000);
    }
    
    await this.save();
    
    // Create hotspot user
    const HotspotUser = mongoose.model('HotspotUser');
    const user = await HotspotUser.create({
        organization: this.organization,
        device: deviceId,
        username: this.code.toLowerCase().replace(/-/g, ''),
        password: this.generatePassword(),
        profile: this.profile,
        validity: {
            from: this.validity.from,
            to: this.validity.to
        },
        metadata: {
            voucherCode: this.code,
            customerName: this.soldTo?.name,
            customerPhone: this.soldTo?.phone
        },
        createdBy: userId,
        comment: `Voucher activation: ${this.code}`
    });
    
    return user;
};

voucherSchema.methods.generatePassword = function() {
    return crypto.randomBytes(4).toString('hex');
};

voucherSchema.methods.cancel = async function(reason) {
    if (this.status === 'used') {
        throw new Error('Cannot cancel used voucher');
    }
    
    this.status = 'cancelled';
    this.comment = reason || 'Cancelled by admin';
    await this.save();
};

// Static methods
voucherSchema.statics.generateBatch = async function(options) {
    const {
        organizationId,
        profileId,
        count,
        prefix,
        validityDays,
        price,
        createdBy
    } = options;
    
    // Create batch record
    const VoucherBatch = mongoose.model('VoucherBatch');
    const batch = await VoucherBatch.create({
        organization: organizationId,
        profile: profileId,
        count,
        prefix,
        validityDays,
        price,
        createdBy
    });
    
    // Generate vouchers
    const vouchers = [];
    const usedCodes = new Set();
    
    for (let i = 0; i < count; i++) {
        let code;
        let attempts = 0;
        
        // Ensure unique code
        do {
            code = new this().generateCode(prefix);
            attempts++;
            
            if (attempts > 100) {
                throw new Error('Failed to generate unique codes');
            }
        } while (usedCodes.has(code));
        
        usedCodes.add(code);
        
        const voucher = new this({
            organization: organizationId,
            batch: batch._id,
            code,
            profile: profileId,
            validity: {
                days: validityDays
            },
            price: {
                amount: price
            }
        });
        
        await voucher.generateQRCode();
        vouchers.push(voucher);
    }
    
    // Bulk insert
    await this.insertMany(vouchers);
    
    return batch;
};

voucherSchema.statics.checkExpired = async function() {
    const now = new Date();
    
    // Find and update expired vouchers
    const result = await this.updateMany(
        {
            status: { $in: ['available', 'sold'] },
            'validity.to': { $lt: now }
        },
        {
            status: 'expired'
        }
    );
    
    return result.modifiedCount;
};

// Middleware
voucherSchema.pre('save', function(next) {
    // Auto-expire if validity date passed
    if (this.validity.to && new Date() > this.validity.to) {
        this.status = 'expired';
    }
    next();
});

module.exports = mongoose.model('Voucher', voucherSchema);

// Voucher Batch Schema
const voucherBatchSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true,
        index: true
    },
    name: String,
    profile: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HotspotProfile',
        required: true
    },
    count: {
        type: Number,
        required: true
    },
    prefix: String,
    validityDays: Number,
    price: Number,
    totalValue: Number,
    sold: {
        type: Number,
        default: 0
    },
    used: {
        type: Number,
        default: 0
    },
    revenue: {
        type: Number,
        default: 0
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    printTemplate: String,
    notes: String
}, {
    timestamps: true
});

// Virtual for available vouchers
voucherBatchSchema.virtual('available').get(function() {
    return this.count - this.sold - this.used;
});

// Virtual for vouchers
voucherBatchSchema.virtual('vouchers', {
    ref: 'Voucher',
    localField: '_id',
    foreignField: 'batch'
});

module.exports.VoucherBatch = mongoose.model('VoucherBatch', voucherBatchSchema);
EOF
}

# Create voucher controller
create_voucher_controller() {
    cat << 'EOF' > "$APP_DIR/controllers/voucherController.js"
const Voucher = require('../models/Voucher');
const { VoucherBatch } = require('../models/Voucher');
const HotspotProfile = require('../models/HotspotProfile');
const Device = require('../models/Device');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');

class VoucherController {
    // Get all voucher batches
    async getBatches(req, res, next) {
        try {
            const batches = await VoucherBatch.find({
                organization: req.user.organization
            })
            .populate('profile')
            .populate('createdBy', 'name')
            .sort({ createdAt: -1 });

            res.json({
                success: true,
                count: batches.length,
                data: batches
            });
        } catch (error) {
            next(error);
        }
    }

    // Create voucher batch
    async createBatch(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const {
                name,
                profileId,
                count,
                prefix,
                validityDays,
                price
            } = req.body;

            // Validate count
            if (count > 10000) {
                return res.status(400).json({
                    success: false,
                    error: 'Cannot create more than 10000 vouchers at once'
                });
            }

            // Check profile exists
            const profile = await HotspotProfile.findOne({
                _id: profileId,
                organization: req.user.organization
            });

            if (!profile) {
                return res.status(404).json({
                    success: false,
                    error: 'Profile not found'
                });
            }

            // Generate batch
            const batch = await Voucher.generateBatch({
                organizationId: req.user.organization,
                profileId,
                count,
                prefix: prefix || '',
                validityDays,
                price: price || profile.pricing?.price || 0,
                createdBy: req.user._id
            });

            // Update batch name if provided
            if (name) {
                batch.name = name;
                batch.totalValue = count * (price || 0);
                await batch.save();
            }

            await batch.populate('profile createdBy');

            res.status(201).json({
                success: true,
                data: batch
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'voucher_batch_create',
                target: batch._id,
                details: {
                    count,
                    profile: profile.name,
                    value: batch.totalValue
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Get vouchers
    async getVouchers(req, res, next) {
        try {
            const { batchId, status, sold, used } = req.query;
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 50;
            const skip = (page - 1) * limit;

            const query = { organization: req.user.organization };
            
            if (batchId) query.batch = batchId;
            if (status) query.status = status;
            if (sold === 'true') query.status = 'sold';
            if (used === 'true') query.status = 'used';

            const [vouchers, total] = await Promise.all([
                Voucher.find(query)
                    .populate('profile')
                    .populate('batch')
                    .populate('seller', 'name')
                    .populate('activatedBy')
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit),
                Voucher.countDocuments(query)
            ]);

            res.json({
                success: true,
                data: vouchers,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Get single voucher
    async getVoucher(req, res, next) {
        try {
            const voucher = await Voucher.findOne({
                $or: [
                    { _id: req.params.id },
                    { code: req.params.id.toUpperCase() }
                ],
                organization: req.user.organization
            })
            .populate('profile')
            .populate('batch')
            .populate('seller', 'name')
            .populate('activatedBy')
            .populate('activationDevice');

            if (!voucher) {
                return res.status(404).json({
                    success: false,
                    error: 'Voucher not found'
                });
            }

            res.json({
                success: true,
                data: voucher
            });
        } catch (error) {
            next(error);
        }
    }

    // Sell voucher
    async sellVoucher(req, res, next) {
        try {
            const { code, customerName, customerPhone, customerEmail, reference } = req.body;

            const voucher = await Voucher.findOne({
                code: code.toUpperCase(),
                organization: req.user.organization
            });

            if (!voucher) {
                return res.status(404).json({
                    success: false,
                    error: 'Voucher not found'
                });
            }

            if (voucher.status !== 'available') {
                return res.status(400).json({
                    success: false,
                    error: `Voucher is ${voucher.status}`
                });
            }

            // Update voucher
            voucher.status = 'sold';
            voucher.seller = req.user._id;
            voucher.soldAt = new Date();
            voucher.soldTo = {
                name: customerName,
                phone: customerPhone,
                email: customerEmail,
                reference
            };

            await voucher.save();

            // Update batch statistics
            await VoucherBatch.findByIdAndUpdate(voucher.batch, {
                $inc: {
                    sold: 1,
                    revenue: voucher.price?.amount || 0
                }
            });

            res.json({
                success: true,
                data: voucher
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'voucher_sell',
                target: voucher._id,
                details: {
                    code: voucher.code,
                    customer: customerName,
                    amount: voucher.price?.amount
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Activate voucher
    async activateVoucher(req, res, next) {
        try {
            const { code, deviceId } = req.body;

            const voucher = await Voucher.findOne({
                code: code.toUpperCase(),
                organization: req.user.organization
            }).populate('profile');

            if (!voucher) {
                return res.status(404).json({
                    success: false,
                    error: 'Voucher not found'
                });
            }

            if (voucher.status === 'used') {
                return res.status(400).json({
                    success: false,
                    error: 'Voucher already used'
                });
            }

            if (voucher.status === 'expired') {
                return res.status(400).json({
                    success: false,
                    error: 'Voucher expired'
                });
            }

            if (voucher.status === 'cancelled') {
                return res.status(400).json({
                    success: false,
                    error: 'Voucher cancelled'
                });
            }

            // Get device
            const device = await Device.findOne({
                _id: deviceId,
                organization: req.user.organization
            });

            if (!device) {
                return res.status(404).json({
                    success: false,
                    error: 'Device not found'
                });
            }

            // Activate voucher and create hotspot user
            const hotspotUser = await voucher.activate(req.user._id, device._id);

            // Create user in MikroTik
            const deviceController = require('./deviceController');
            const api = await deviceController.getDeviceConnection(device);
            
            await api.addHotspotUser({
                username: hotspotUser.username,
                password: hotspotUser.password,
                profile: voucher.profile.mikrotikName,
                limitUptime: voucher.profile.limits?.uptime,
                limitBytesTotal: voucher.profile.limits?.bytesTotal,
                comment: `Voucher: ${voucher.code}`
            });

            // Update batch statistics
            await VoucherBatch.findByIdAndUpdate(voucher.batch, {
                $inc: { used: 1 }
            });

            res.json({
                success: true,
                data: {
                    voucher,
                    user: hotspotUser
                }
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'voucher_activate',
                target: voucher._id,
                details: {
                    code: voucher.code,
                    device: device.name,
                    username: hotspotUser.username
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Print vouchers
    async printVouchers(req, res, next) {
        try {
            const { batchId, voucherIds, format = 'pdf', template = 'default' } = req.body;

            let vouchers;
            
            if (voucherIds && voucherIds.length > 0) {
                // Print specific vouchers
                vouchers = await Voucher.find({
                    _id: { $in: voucherIds },
                    organization: req.user.organization
                })
                .populate('profile')
                .populate('batch');
            } else if (batchId) {
                // Print entire batch
                vouchers = await Voucher.find({
                    batch: batchId,
                    organization: req.user.organization,
                    status: 'available'
                })
                .populate('profile')
                .populate('batch')
                .limit(1000); // Limit to prevent memory issues
            } else {
                return res.status(400).json({
                    success: false,
                    error: 'No vouchers specified'
                });
            }

            if (vouchers.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'No vouchers found'
                });
            }

            // Update print count
            await Voucher.updateMany(
                { _id: { $in: vouchers.map(v => v._id) } },
                {
                    $inc: { printCount: 1 },
                    lastPrintedAt: new Date(),
                    lastPrintedBy: req.user._id
                }
            );

            // Generate output based on format
            if (format === 'pdf') {
                const pdf = await this.generatePDF(vouchers, template);
                res.setHeader('Content-Type', 'application/pdf');
                res.setHeader('Content-Disposition', 'attachment; filename=vouchers.pdf');
                pdf.pipe(res);
            } else if (format === 'excel') {
                const excel = await this.generateExcel(vouchers);
                res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
                res.setHeader('Content-Disposition', 'attachment; filename=vouchers.xlsx');
                await excel.xlsx.write(res);
            } else if (format === 'thermal') {
                const thermal = await this.generateThermalPrint(vouchers);
                res.json({
                    success: true,
                    data: thermal
                });
            } else {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid format'
                });
            }

        } catch (error) {
            next(error);
        }
    }

    // Cancel voucher
    async cancelVoucher(req, res, next) {
        try {
            const { reason } = req.body;

            const voucher = await Voucher.findOne({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!voucher) {
                return res.status(404).json({
                    success: false,
                    error: 'Voucher not found'
                });
            }

            await voucher.cancel(reason);

            // Update batch statistics
            if (voucher.status === 'sold') {
                await VoucherBatch.findByIdAndUpdate(voucher.batch, {
                    $inc: {
                        sold: -1,
                        revenue: -(voucher.price?.amount || 0)
                    }
                });
            }

            res.json({
                success: true,
                data: voucher
            });

            // Log activity
            await this.logActivity({
                user: req.user._id,
                action: 'voucher_cancel',
                target: voucher._id,
                details: {
                    code: voucher.code,
                    reason
                }
            });

        } catch (error) {
            next(error);
        }
    }

    // Get voucher statistics
    async getStatistics(req, res, next) {
        try {
            const { startDate, endDate } = req.query;
            
            const query = { organization: req.user.organization };
            
            if (startDate || endDate) {
                query.createdAt = {};
                if (startDate) query.createdAt.$gte = new Date(startDate);
                if (endDate) query.createdAt.$lte = new Date(endDate);
            }

            const [
                totalVouchers,
                availableVouchers,
                soldVouchers,
                usedVouchers,
                revenue,
                batches
            ] = await Promise.all([
                Voucher.countDocuments(query),
                Voucher.countDocuments({ ...query, status: 'available' }),
                Voucher.countDocuments({ ...query, status: 'sold' }),
                Voucher.countDocuments({ ...query, status: 'used' }),
                Voucher.aggregate([
                    { $match: { ...query, status: { $in: ['sold', 'used'] } } },
                    { $group: { _id: null, total: { $sum: '$price.amount' } } }
                ]),
                VoucherBatch.find(query).populate('profile')
            ]);

            // Daily sales for last 30 days
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

            const dailySales = await Voucher.aggregate([
                {
                    $match: {
                        organization: req.user.organization,
                        soldAt: { $gte: thirtyDaysAgo },
                        status: { $in: ['sold', 'used'] }
                    }
                },
                {
                    $group: {
                        _id: { $dateToString: { format: '%Y-%m-%d', date: '$soldAt' } },
                        count: { $sum: 1 },
                        revenue: { $sum: '$price.amount' }
                    }
                },
                { $sort: { _id: 1 } }
            ]);

            res.json({
                success: true,
                data: {
                    summary: {
                        total: totalVouchers,
                        available: availableVouchers,
                        sold: soldVouchers,
                        used: usedVouchers,
                        revenue: revenue[0]?.total || 0
                    },
                    batches: batches.length,
                    dailySales
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Helper methods
    async generatePDF(vouchers, template) {
        const doc = new PDFDocument({
            size: 'A4',
            margin: 10
        });

        // Load template
        const voucherTemplate = await this.loadTemplate(template);

        // Configure based on template
        const perRow = voucherTemplate.perRow || 2;
        const perPage = voucherTemplate.perPage || 10;
        const width = (doc.page.width - 20) / perRow;
        const height = (doc.page.height - 20) / (perPage / perRow);

        let currentX = 10;
        let currentY = 10;
        let count = 0;

        for (const voucher of vouchers) {
            // Draw voucher
            this.drawVoucher(doc, voucher, currentX, currentY, width, height, voucherTemplate);

            count++;
            currentX += width;

            if (count % perRow === 0) {
                currentX = 10;
                currentY += height;
            }

            if (count % perPage === 0 && count < vouchers.length) {
                doc.addPage();
                currentX = 10;
                currentY = 10;
            }
        }

        doc.end();
        return doc;
    }

    drawVoucher(doc, voucher, x, y, width, height, template) {
        // Draw border
        doc.rect(x, y, width - 5, height - 5).stroke();

        // Organization name
        doc.fontSize(12)
           .font('Helvetica-Bold')
           .text(template.organizationName || 'WiFi Hotspot', x + 10, y + 10);

        // Profile name
        doc.fontSize(10)
           .font('Helvetica')
           .text(voucher.profile.name, x + 10, y + 30);

        // Voucher code
        doc.fontSize(16)
           .font('Helvetica-Bold')
           .text(voucher.code, x + 10, y + 50);

        // QR Code
        if (voucher.qrCode && template.showQR) {
            doc.image(Buffer.from(voucher.qrCode.split(',')[1], 'base64'), 
                     x + width - 80, y + 10, { width: 60, height: 60 });
        }

        // Validity
        if (voucher.validity.days) {
            doc.fontSize(9)
               .font('Helvetica')
               .text(`Valid for ${voucher.validity.days} days`, x + 10, y + 75);
        }

        // Price
        if (voucher.price.amount && template.showPrice) {
            doc.fontSize(10)
               .font('Helvetica-Bold')
               .text(`${voucher.price.amount} ${voucher.price.currency}`, x + 10, y + 90);
        }

        // Instructions
        if (template.instructions) {
            doc.fontSize(8)
               .font('Helvetica')
               .text(template.instructions, x + 10, y + height - 40, {
                   width: width - 20,
                   height: 30
               });
        }
    }

    async generateExcel(vouchers) {
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Vouchers');

        // Add headers
        worksheet.columns = [
            { header: 'Code', key: 'code', width: 20 },
            { header: 'Profile', key: 'profile', width: 20 },
            { header: 'Status', key: 'status', width: 15 },
            { header: 'Price', key: 'price', width: 10 },
            { header: 'Validity Days', key: 'validity', width: 15 },
            { header: 'Created', key: 'created', width: 20 },
            { header: 'Sold To', key: 'soldTo', width: 25 },
            { header: 'Sold Date', key: 'soldDate', width: 20 },
            { header: 'Activated', key: 'activated', width: 20 }
        ];

        // Add data
        vouchers.forEach(voucher => {
            worksheet.addRow({
                code: voucher.code,
                profile: voucher.profile.name,
                status: voucher.status,
                price: voucher.price.amount,
                validity: voucher.validity.days,
                created: voucher.createdAt,
                soldTo: voucher.soldTo?.name,
                soldDate: voucher.soldAt,
                activated: voucher.activatedAt
            });
        });

        // Style the header
        worksheet.getRow(1).font = { bold: true };
        worksheet.getRow(1).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE0E0E0' }
        };

        return workbook;
    }

    async generateThermalPrint(vouchers) {
        // Generate ESC/POS commands for thermal printer
        const commands = [];

        for (const voucher of vouchers) {
            commands.push({
                code: voucher.code,
                commands: [
                    '\x1B\x40', // Initialize printer
                    '\x1B\x61\x01', // Center align
                    '\x1D\x21\x11', // Double height and width
                    'WiFi Hotspot\n',
                    '\x1D\x21\x00', // Normal size
                    '\x1B\x61\x01', // Center align
                    `${voucher.profile.name}\n`,
                    '\n',
                    '\x1D\x21\x11', // Double height and width
                    `${voucher.code}\n`,
                    '\x1D\x21\x00', // Normal size
                    '\n',
                    `Valid: ${voucher.validity.days} days\n`,
                    `Price: ${voucher.price.amount} ${voucher.price.currency}\n`,
                    '\n',
                    '\x1B\x61\x00', // Left align
                    'Connect to WiFi and enter code\n',
                    '\n\n\n',
                    '\x1D\x56\x00' // Cut paper
                ].join('')
            });
        }

        return commands;
    }

    async loadTemplate(templateName) {
        // Load voucher template configuration
        const templates = {
            default: {
                perRow: 2,
                perPage: 10,
                showQR: true,
                showPrice: true,
                organizationName: 'WiFi Hotspot',
                instructions: 'Connect to WiFi and enter this code'
            },
            compact: {
                perRow: 3,
                perPage: 15,
                showQR: false,
                showPrice: true,
                organizationName: 'WiFi Hotspot',
                instructions: 'Use code to connect'
            },
            premium: {
                perRow: 1,
                perPage: 4,
                showQR: true,
                showPrice: true,
                organizationName: 'Premium WiFi Service',
                instructions: 'Scan QR code or enter voucher code to connect'
            }
        };

        return templates[templateName] || templates.default;
    }

    async logActivity(activity) {
        const ActivityLog = require('../models/ActivityLog');
        await ActivityLog.create(activity);
    }
}

module.exports = new VoucherController();
EOF
}

# Create voucher templates
create_voucher_templates() {
    mkdir -p "$APP_DIR/src/voucher-templates"
    
    # Default voucher template (HTML)
    cat << 'EOF' > "$APP_DIR/src/voucher-templates/default.html"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background: white;
        }
        
        .voucher-container {
            width: 100%;
            display: flex;
            flex-wrap: wrap;
        }
        
        .voucher {
            width: 50%;
            height: 200px;
            padding: 10px;
            position: relative;
        }
        
        .voucher-inner {
            border: 2px dashed #333;
            border-radius: 10px;
            height: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #f5f5f5 0%, #e0e0e0 100%);
            position: relative;
            overflow: hidden;
        }
        
        .voucher-header {
            text-align: center;
            margin-bottom: 10px;
        }
        
        .organization-name {
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }
        
        .profile-name {
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }
        
        .voucher-code {
            text-align: center;
            font-size: 24px;
            font-weight: bold;
            color: #2196F3;
            letter-spacing: 2px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
        }
        
        .qr-code {
            position: absolute;
            right: 15px;
            top: 15px;
            width: 60px;
            height: 60px;
        }
        
        .qr-code img {
            width: 100%;
            height: 100%;
        }
        
        .voucher-details {
            font-size: 12px;
            color: #666;
            text-align: center;
        }
        
        .validity {
            margin: 5px 0;
        }
        
        .price {
            font-size: 16px;
            font-weight: bold;
            color: #4CAF50;
            margin: 10px 0;
        }
        
        .instructions {
            font-size: 10px;
            color: #999;
            text-align: center;
            position: absolute;
            bottom: 10px;
            left: 15px;
            right: 15px;
        }
        
        .watermark {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 60px;
            color: rgba(0, 0, 0, 0.05);
            font-weight: bold;
            pointer-events: none;
        }
        
        @media print {
            .voucher {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="voucher-container">
        {{#vouchers}}
        <div class="voucher">
            <div class="voucher-inner">
                <div class="watermark">VOUCHER</div>
                
                {{#showQR}}
                <div class="qr-code">
                    <img src="{{qrCode}}" alt="QR Code">
                </div>
                {{/showQR}}
                
                <div class="voucher-header">
                    <div class="organization-name">{{organizationName}}</div>
                    <div class="profile-name">{{profile.name}}</div>
                </div>
                
                <div class="voucher-code">{{code}}</div>
                
                <div class="voucher-details">
                    {{#validity.days}}
                    <div class="validity">Valid for {{validity.days}} days</div>
                    {{/validity.days}}
                    
                    {{#showPrice}}
                    <div class="price">{{price.amount}} {{price.currency}}</div>
                    {{/showPrice}}
                </div>
                
                <div class="instructions">{{instructions}}</div>
            </div>
        </div>
        {{/vouchers}}
    </div>
</body>
</html>
EOF

    # Thermal printer template
    cat << 'EOF' > "$APP_DIR/src/voucher-templates/thermal.js"
module.exports = {
    generateCommands: (voucher) => {
        const ESC = '\x1B';
        const GS = '\x1D';
        
        return [
            // Initialize
            `${ESC}@`,
            
            // Center alignment
            `${ESC}a1`,
            
            // Bold on
            `${ESC}E1`,
            
            // Organization name
            `${voucher.organizationName || 'WiFi Hotspot'}\n`,
            
            // Bold off
            `${ESC}E0`,
            
            // Profile name
            `${voucher.profile.name}\n`,
            `${'='.repeat(32)}\n`,
            
            // Double size for code
            `${GS}!0x11`,
            `${voucher.code}\n`,
            
            // Normal size
            `${GS}!0x00`,
            `${'='.repeat(32)}\n`,
            
            // Details
            voucher.validity.days ? `Valid: ${voucher.validity.days} days\n` : '',
            voucher.price.amount ? `Price: ${voucher.price.amount} ${voucher.price.currency}\n` : '',
            '\n',
            
            // Instructions
            'Connect to WiFi\n',
            'Enter voucher code\n',
            '\n',
            
            // Date/time
            `${new Date().toLocaleString()}\n`,
            
            // Feed and cut
            '\n\n\n',
            `${GS}V0`
        ].join('');
    }
};
EOF

    log "Voucher templates created"
}

# Create voucher printing service
create_voucher_printing_service() {
    cat << 'EOF' > "$APP_DIR/src/services/voucherPrintService.js"
const fs = require('fs').promises;
const path = require('path');
const Handlebars = require('handlebars');
const puppeteer = require('puppeteer');
const { ThermalPrinter, PrinterTypes } = require('node-thermal-printer');

class VoucherPrintService {
    constructor() {
        this.templates = new Map();
        this.loadTemplates();
    }

    async loadTemplates() {
        const templatesDir = path.join(__dirname, '../voucher-templates');
        
        try {
            // Load HTML templates
            const defaultTemplate = await fs.readFile(
                path.join(templatesDir, 'default.html'),
                'utf8'
            );
            this.templates.set('default', Handlebars.compile(defaultTemplate));
            
            // Load thermal template
            const thermalTemplate = require(path.join(templatesDir, 'thermal.js'));
            this.templates.set('thermal', thermalTemplate);
        } catch (error) {
            console.error('Failed to load voucher templates:', error);
        }
    }

    async generatePDF(vouchers, options = {}) {
        const template = this.templates.get(options.template || 'default');
        if (!template) {
            throw new Error('Template not found');
        }

        // Prepare data
        const data = {
            vouchers: vouchers.map(v => ({
                ...v.toObject(),
                organizationName: options.organizationName || 'WiFi Hotspot',
                instructions: options.instructions || 'Connect to WiFi and enter code',
                showQR: options.showQR !== false,
                showPrice: options.showPrice !== false
            }))
        };

        // Generate HTML
        const html = template(data);

        // Convert to PDF using Puppeteer
        const browser = await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });

        try {
            const page = await browser.newPage();
            await page.setContent(html, { waitUntil: 'networkidle0' });
            
            const pdf = await page.pdf({
                format: 'A4',
                printBackground: true,
                margin: {
                    top: '10mm',
                    right: '10mm',
                    bottom: '10mm',
                    left: '10mm'
                }
            });

            return pdf;
        } finally {
            await browser.close();
        }
    }

    async printToThermalPrinter(vouchers, printerConfig) {
        const printer = new ThermalPrinter({
            type: PrinterTypes[printerConfig.type] || PrinterTypes.EPSON,
            interface: printerConfig.interface,
            options: {
                timeout: printerConfig.timeout || 5000
            }
        });

        const template = this.templates.get('thermal');
        if (!template) {
            throw new Error('Thermal template not found');
        }

        try {
            for (const voucher of vouchers) {
                // Generate commands for this voucher
                const commands = template.generateCommands(voucher);
                
                // Send raw commands to printer
                printer.raw(Buffer.from(commands));
                
                // Execute print
                await printer.execute();
                
                // Clear buffer for next voucher
                printer.clear();
            }
        } catch (error) {
            throw new Error(`Thermal printing failed: ${error.message}`);
        }
    }

    async generateBatchPrintJob(batchId, format = 'pdf') {
        const VoucherBatch = require('../../models/Voucher').VoucherBatch;
        const Voucher = require('../../models/Voucher');

        const batch = await VoucherBatch.findById(batchId).populate('profile');
        if (!batch) {
            throw new Error('Batch not found');
        }

        const vouchers = await Voucher.find({
            batch: batchId,
            status: 'available'
        }).populate('profile');

        if (format === 'pdf') {
            return this.generatePDF(vouchers, {
                organizationName: batch.organization.name,
                template: batch.printTemplate || 'default'
            });
        } else if (format === 'thermal') {
            // Return thermal print data
            const template = this.templates.get('thermal');
            return vouchers.map(v => ({
                code: v.code,
                commands: template.generateCommands(v)
            }));
        }

        throw new Error('Unsupported format');
    }

    async createPrintPreview(voucher, template = 'default') {
        const tmpl = this.templates.get(template);
        if (!tmpl) {
            throw new Error('Template not found');
        }

        if (template === 'thermal') {
            // Return thermal commands as text preview
            return {
                type: 'text',
                content: tmpl.generateCommands(voucher)
            };
        }

        // Generate HTML preview
        const html = tmpl({
            vouchers: [voucher],
            organizationName: 'WiFi Hotspot',
            instructions: 'Connect to WiFi and enter code',
            showQR: true,
            showPrice: true
        });

        return {
            type: 'html',
            content: html
        };
    }
}

module.exports = new VoucherPrintService();
EOF
}

# =============================================================================
# PHASE 2.4: BASIC REPORTING
# =============================================================================

phase2_4_basic_reporting() {
    log "=== Phase 2.4: Setting up Basic Reporting ==="
    
    # Create report models
    create_report_models
    
    # Create report controller
    create_report_controller
    
    # Create report generation service
    create_report_service
    
    # Create report templates
    create_report_templates
    
    log "Phase 2.4 completed!"
}

# Create report models
create_report_models() {
    cat << 'EOF' > "$APP_DIR/models/Report.js"
const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true,
        index: true
    },
    name: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: [
            'daily-summary',
            'weekly-summary',
            'monthly-summary',
            'device-status',
            'user-activity',
            'revenue',
            'bandwidth-usage',
            'session-analytics',
            'voucher-sales',
            'custom'
        ],
        required: true
    },
    period: {
        start: {
            type: Date,
            required: true
        },
        end: {
            type: Date,
            required: true
        }
    },
    filters: {
        devices: [mongoose.Schema.Types.ObjectId],
        profiles: [mongoose.Schema.Types.ObjectId],
        users: [mongoose.Schema.Types.ObjectId],
        tags: [String]
    },
    data: mongoose.Schema.Types.Mixed,
    format: {
        type: String,
        enum: ['json', 'pdf', 'excel', 'csv'],
        default: 'json'
    },
    status: {
        type: String,
        enum: ['pending', 'processing', 'completed', 'failed'],
        default: 'pending'
    },
    fileUrl: String,
    fileSize: Number,
    error: String,
    generatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    generatedAt: Date,
    expiresAt: Date,
    emailTo: [String],
    schedule: {
        frequency: {
            type: String,
            enum: ['once', 'daily', 'weekly', 'monthly']
        },
        dayOfWeek: Number, // 0-6 for weekly
        dayOfMonth: Number, // 1-31 for monthly
        time: String // HH:mm format
    }
}, {
    timestamps: true
});

// Indexes
reportSchema.index({ organization: 1, type: 1, createdAt: -1 });
reportSchema.index({ organization: 1, status: 1 });
reportSchema.index({ expiresAt: 1 }, { sparse: true });

// Methods
reportSchema.methods.markAsProcessing = async function() {
    this.status = 'processing';
    this.generatedAt = new Date();
    await this.save();
};

reportSchema.methods.markAsCompleted = async function(fileUrl, fileSize) {
    this.status = 'completed';
    this.fileUrl = fileUrl;
    this.fileSize = fileSize;
    this.expiresAt = new Date(Date.now() + 7 * 86400000); // 7 days
    await this.save();
};

reportSchema.methods.markAsFailed = async function(error) {
    this.status = 'failed';
    this.error = error;
    await this.save();
};

// Static methods
reportSchema.statics.cleanupExpired = async function() {
    const result = await this.deleteMany({
        expiresAt: { $lt: new Date() }
    });
    
    // TODO: Also delete associated files
    
    return result.deletedCount;
};

module.exports = mongoose.model('Report', reportSchema);
EOF
}

# Create report controller
create_report_controller() {
    cat << 'EOF' > "$APP_DIR/controllers/reportController.js"
const Report = require('../models/Report');
const ReportService = require('../src/services/reportService');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');

class ReportController {
    // Get all reports
    async getReports(req, res, next) {
        try {
            const { type, status } = req.query;
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 20;
            const skip = (page - 1) * limit;

            const query = { organization: req.user.organization };
            
            if (type) query.type = type;
            if (status) query.status = status;

            const [reports, total] = await Promise.all([
                Report.find(query)
                    .populate('generatedBy', 'name')
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit),
                Report.countDocuments(query)
            ]);

            res.json({
                success: true,
                data: reports,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            });
        } catch (error) {
            next(error);
        }
    }

    // Get single report
    async getReport(req, res, next) {
        try {
            const report = await Report.findOne({
                _id: req.params.id,
                organization: req.user.organization
            }).populate('generatedBy', 'name');

            if (!report) {
                return res.status(404).json({
                    success: false,
                    error: 'Report not found'
                });
            }

            res.json({
                success: true,
                data: report
            });
        } catch (error) {
            next(error);
        }
    }

    // Generate report
    async generateReport(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const {
                type,
                name,
                startDate,
                endDate,
                filters,
                format,
                emailTo
            } = req.body;

            // Create report record
            const report = await Report.create({
                organization: req.user.organization,
                name: name || `${type} report`,
                type,
                period: {
                    start: new Date(startDate),
                    end: new Date(endDate)
                },
                filters: filters || {},
                format: format || 'pdf',
                status: 'pending',
                generatedBy: req.user._id,
                emailTo
            });

            // Queue report generation
            ReportService.generateReport(report._id).catch(error => {
                logger.error(`Failed to generate report ${report._id}: ${error.message}`);
            });

            res.status(202).json({
                success: true,
                data: report,
                message: 'Report generation started'
            });
        } catch (error) {
            next(error);
        }
    }

    // Download report
    async downloadReport(req, res, next) {
        try {
            const report = await Report.findOne({
                _id: req.params.id,
                organization: req.user.organization,
                status: 'completed'
            });

            if (!report) {
                return res.status(404).json({
                    success: false,
                    error: 'Report not found or not ready'
                });
            }

            // Get file from storage
            const file = await ReportService.getReportFile(report);
            
            if (!file) {
                return res.status(404).json({
                    success: false,
                    error: 'Report file not found'
                });
            }

            // Set headers based on format
            const contentTypes = {
                pdf: 'application/pdf',
                excel: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                csv: 'text/csv',
                json: 'application/json'
            };

            const extensions = {
                pdf: 'pdf',
                excel: 'xlsx',
                csv: 'csv',
                json: 'json'
            };

            res.setHeader('Content-Type', contentTypes[report.format]);
            res.setHeader('Content-Disposition', 
                `attachment; filename=${report.name.replace(/[^a-z0-9]/gi, '_')}.${extensions[report.format]}`);
            res.setHeader('Content-Length', report.fileSize);

            file.pipe(res);
        } catch (error) {
            next(error);
        }
    }

    // Delete report
    async deleteReport(req, res, next) {
        try {
            const report = await Report.findOneAndDelete({
                _id: req.params.id,
                organization: req.user.organization
            });

            if (!report) {
                return res.status(404).json({
                    success: false,
                    error: 'Report not found'
                });
            }

            // Delete associated file
            if (report.fileUrl) {
                await ReportService.deleteReportFile(report);
            }

            res.json({
                success: true,
                data: {}
            });
        } catch (error) {
            next(error);
        }
    }

    // Get report types
    async getReportTypes(req, res, next) {
        try {
            const reportTypes = [
                {
                    id: 'daily-summary',
                    name: 'Daily Summary',
                    description: 'Overview of daily activities and metrics',
                    parameters: ['date']
                },
                {
                    id: 'weekly-summary',
                    name: 'Weekly Summary',
                    description: 'Weekly performance and trends',
                    parameters: ['startDate', 'endDate']
                },
                {
                    id: 'monthly-summary',
                    name: 'Monthly Summary',
                    description: 'Monthly statistics and analysis',
                    parameters: ['month', 'year']
                },
                {
                    id: 'device-status',
                    name: 'Device Status Report',
                    description: 'Current status and health of all devices',
                    parameters: ['includeOffline', 'deviceIds']
                },
                {
                    id: 'user-activity',
                    name: 'User Activity Report',
                    description: 'Hotspot user sessions and usage',
                    parameters: ['startDate', 'endDate', 'deviceIds', 'profileIds']
                },
                {
                    id: 'revenue',
                    name: 'Revenue Report',
                    description: 'Voucher sales and revenue analysis',
                    parameters: ['startDate', 'endDate', 'groupBy']
                },
                {
                    id: 'bandwidth-usage',
                    name: 'Bandwidth Usage Report',
                    description: 'Network bandwidth consumption analysis',
                    parameters: ['startDate', 'endDate', 'deviceIds']
                },
                {
                    id: 'session-analytics',
                    name: 'Session Analytics',
                    description: 'Detailed session patterns and statistics',
                    parameters: ['startDate', 'endDate', 'metrics']
                },
                {
                    id: 'voucher-sales',
                    name: 'Voucher Sales Report',
                    description: 'Voucher inventory and sales tracking',
                    parameters: ['startDate', 'endDate', 'batchIds', 'sellers']
                }
            ];

            res.json({
                success: true,
                data: reportTypes
            });
        } catch (error) {
            next(error);
        }
    }

    // Schedule report
    async scheduleReport(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const {
                type,
                name,
                filters,
                format,
                schedule,
                emailTo
            } = req.body;

            // Create scheduled report
            const report = await Report.create({
                organization: req.user.organization,
                name: name || `Scheduled ${type} report`,
                type,
                filters: filters || {},
                format: format || 'pdf',
                status: 'pending',
                generatedBy: req.user._id,
                emailTo,
                schedule
            });

            // Register with scheduler
            await ReportService.scheduleReport(report);

            res.json({
                success: true,
                data: report
            });
        } catch (error) {
            next(error);
        }
    }

    // Get dashboard statistics
    async getDashboardStats(req, res, next) {
        try {
            const { period = 'today' } = req.query;
            
            const stats = await ReportService.getDashboardStatistics(
                req.user.organization,
                period
            );

            res.json({
                success: true,
                data: stats
            });
        } catch (error) {
            next(error);
        }
    }

    // Get real-time metrics
    async getRealtimeMetrics(req, res, next) {
        try {
            const metrics = await ReportService.getRealtimeMetrics(
                req.user.organization
            );

            res.json({
                success: true,
                data: metrics
            });
        } catch (error) {
            next(error);
        }
    }
}

module.exports = new ReportController();
EOF
}

# Create report generation service
create_report_service() {
    cat << 'EOF' > "$APP_DIR/src/services/reportService.js"
const Report = require('../../models/Report');
const Device = require('../../models/Device');
const HotspotUser = require('../../models/HotspotUser');
const HotspotSession = require('../../models/HotspotSession');
const Voucher = require('../../models/Voucher');
const { VoucherBatch } = require('../../models/Voucher');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const fs = require('fs').promises;
const path = require('path');
const logger = require('../../utils/logger');

class ReportService {
    constructor() {
        this.reportsDir = path.join(process.cwd(), 'storage/reports');
        this.ensureReportsDirectory();
    }

    async ensureReportsDirectory() {
        try {
            await fs.mkdir(this.reportsDir, { recursive: true });
        } catch (error) {
            logger.error('Failed to create reports directory:', error);
        }
    }

    async generateReport(reportId) {
        const report = await Report.findById(reportId);
        if (!report) {
            throw new Error('Report not found');
        }

        try {
            await report.markAsProcessing();

            // Generate report data based on type
            const data = await this.generateReportData(report);
            report.data = data;

            // Generate report file based on format
            const { filePath, fileSize } = await this.generateReportFile(report);

            // Store file path
            const fileUrl = `/storage/reports/${path.basename(filePath)}`;
            await report.markAsCompleted(fileUrl, fileSize);

            // Send email if requested
            if (report.emailTo && report.emailTo.length > 0) {
                await this.emailReport(report);
            }

            logger.info(`Report ${reportId} generated successfully`);
        } catch (error) {
            logger.error(`Failed to generate report ${reportId}:`, error);
            await report.markAsFailed(error.message);
            throw error;
        }
    }

    async generateReportData(report) {
        switch (report.type) {
            case 'daily-summary':
                return this.generateDailySummary(report);
            case 'weekly-summary':
                return this.generateWeeklySummary(report);
            case 'monthly-summary':
                return this.generateMonthlySummary(report);
            case 'device-status':
                return this.generateDeviceStatus(report);
            case 'user-activity':
                return this.generateUserActivity(report);
            case 'revenue':
                return this.generateRevenueReport(report);
            case 'bandwidth-usage':
                return this.generateBandwidthReport(report);
            case 'session-analytics':
                return this.generateSessionAnalytics(report);
            case 'voucher-sales':
                return this.generateVoucherSales(report);
            default:
                throw new Error(`Unknown report type: ${report.type}`);
        }
    }

    async generateDailySummary(report) {
        const { start, end } = report.period;
        const organization = report.organization;

        // Get device statistics
        const devices = await Device.find({ organization });
        const onlineDevices = devices.filter(d => d.status === 'online').length;
        const offlineDevices = devices.filter(d => d.status === 'offline').length;

        // Get session statistics
        const sessions = await HotspotSession.find({
            organization,
            startTime: { $gte: start, $lte: end }
        });

        const totalSessions = sessions.length;
        const uniqueUsers = new Set(sessions.map(s => s.user?.toString())).size;
        const totalDataUsage = sessions.reduce((sum, s) => 
            sum + (s.traffic.bytesIn || 0) + (s.traffic.bytesOut || 0), 0);
        const totalDuration = sessions.reduce((sum, s) => sum + (s.duration || 0), 0);

        // Get voucher statistics
        const vouchersSold = await Voucher.countDocuments({
            organization,
            soldAt: { $gte: start, $lte: end }
        });

        const vouchersActivated = await Voucher.countDocuments({
            organization,
            activatedAt: { $gte: start, $lte: end }
        });

        const revenue = await Voucher.aggregate([
            {
                $match: {
                    organization,
                    soldAt: { $gte: start, $lte: end },
                    'price.amount': { $gt: 0 }
                }
            },
            {
                $group: {
                    _id: null,
                    total: { $sum: '$price.amount' }
                }
            }
        ]);

        // Get active users right now
        const activeSessions = await HotspotSession.countDocuments({
            organization,
            status: 'active'
        });

        return {
            date: start,
            devices: {
                total: devices.length,
                online: onlineDevices,
                offline: offlineDevices,
                uptime: Math.round((onlineDevices / devices.length) * 100) || 0
            },
            sessions: {
                total: totalSessions,
                uniqueUsers,
                active: activeSessions,
                avgDuration: totalSessions > 0 ? Math.round(totalDuration / totalSessions) : 0,
                totalDuration
            },
            traffic: {
                totalBytes: totalDataUsage,
                avgPerSession: totalSessions > 0 ? Math.round(totalDataUsage / totalSessions) : 0,
                avgPerUser: uniqueUsers > 0 ? Math.round(totalDataUsage / uniqueUsers) : 0
            },
            vouchers: {
                sold: vouchersSold,
                activated: vouchersActivated,
                revenue: revenue[0]?.total || 0
            }
        };
    }

    async generateWeeklySummary(report) {
        const { start, end } = report.period;
        const organization = report.organization;

        // Generate daily data for the week
        const dailyData = [];
        const current = new Date(start);
        
        while (current <= end) {
            const dayStart = new Date(current);
            dayStart.setHours(0, 0, 0, 0);
            
            const dayEnd = new Date(current);
            dayEnd.setHours(23, 59, 59, 999);

            const dayReport = {
                period: { start: dayStart, end: dayEnd },
                organization
            };

            const dayData = await this.generateDailySummary(dayReport);
            dailyData.push(dayData);

            current.setDate(current.getDate() + 1);
        }

        // Calculate weekly totals and averages
        const summary = {
            period: { start, end },
            daily: dailyData,
            totals: {
                sessions: dailyData.reduce((sum, d) => sum + d.sessions.total, 0),
                uniqueUsers: new Set(dailyData.flatMap(d => d.sessions.uniqueUsers)).size,
                traffic: dailyData.reduce((sum, d) => sum + d.traffic.totalBytes, 0),
                revenue: dailyData.reduce((sum, d) => sum + d.vouchers.revenue, 0),
                vouchersSold: dailyData.reduce((sum, d) => sum + d.vouchers.sold, 0)
            },
            averages: {
                sessionsPerDay: Math.round(dailyData.reduce((sum, d) => sum + d.sessions.total, 0) / 7),
                revenuePerDay: Math.round(dailyData.reduce((sum, d) => sum + d.vouchers.revenue, 0) / 7),
                deviceUptime: Math.round(dailyData.reduce((sum, d) => sum + d.devices.uptime, 0) / 7)
            }
        };

        return summary;
    }

    async generateMonthlySummary(report) {
        const { start, end } = report.period;
        const organization = report.organization;

        // Similar to weekly but with more aggregation
        const weeks = [];
        const current = new Date(start);
        
        while (current <= end) {
            const weekStart = new Date(current);
            const weekEnd = new Date(current);
            weekEnd.setDate(weekEnd.getDate() + 6);
            
            if (weekEnd > end) {
                weekEnd.setTime(end.getTime());
            }

            const weekReport = {
                period: { start: weekStart, end: weekEnd },
                organization
            };

            const weekData = await this.generateWeeklySummary(weekReport);
            weeks.push({
                week: weeks.length + 1,
                ...weekData
            });

            current.setDate(current.getDate() + 7);
        }

        return {
            period: { start, end },
            weeks,
            totals: {
                sessions: weeks.reduce((sum, w) => sum + w.totals.sessions, 0),
                traffic: weeks.reduce((sum, w) => sum + w.totals.traffic, 0),
                revenue: weeks.reduce((sum, w) => sum + w.totals.revenue, 0),
                vouchersSold: weeks.reduce((sum, w) => sum + w.totals.vouchersSold, 0)
            }
        };
    }

    async generateDeviceStatus(report) {
        const devices = await Device.find({
            organization: report.organization,
            ...(report.filters.devices?.length > 0 ? { _id: { $in: report.filters.devices } } : {})
        });

        const deviceStatus = await Promise.all(devices.map(async (device) => {
            // Get current metrics if online
            let currentMetrics = null;
            if (device.status === 'online') {
                // TODO: Fetch real-time metrics from device
            }

            // Get session count for today
            const todayStart = new Date();
            todayStart.setHours(0, 0, 0, 0);

            const todaySessions = await HotspotSession.countDocuments({
                device: device._id,
                startTime: { $gte: todayStart }
            });

            // Get active users
            const activeUsers = await HotspotSession.countDocuments({
                device: device._id,
                status: 'active'
            });

            return {
                device: {
                    id: device._id,
                    name: device.name,
                    model: device.model,
                    location: device.location,
                    serialNumber: device.serialNumber
                },
                status: device.status,
                lastSeen: device.lastSeen,
                uptime: device.health?.uptime,
                health: device.health,
                network: {
                    vpnIp: device.vpnIpAddress,
                    vpnStatus: device.vpnStatus
                },
                statistics: {
                    todaySessions,
                    activeUsers,
                    totalUsers: await HotspotUser.countDocuments({ device: device._id })
                },
                alerts: device.alerts.filter(a => !a.resolved).slice(0, 5)
            };
        }));

        return {
            generatedAt: new Date(),
            devices: deviceStatus,
            summary: {
                total: devices.length,
                online: deviceStatus.filter(d => d.status === 'online').length,
                offline: deviceStatus.filter(d => d.status === 'offline').length,
                alerts: deviceStatus.reduce((sum, d) => sum + d.alerts.length, 0)
            }
        };
    }

    async generateUserActivity(report) {
        const { start, end } = report.period;
        const { devices, profiles } = report.filters;

        const query = {
            organization: report.organization,
            startTime: { $gte: start, $lte: end }
        };

        if (devices?.length > 0) query.device = { $in: devices };

        const sessions = await HotspotSession.find(query)
            .populate('user')
            .populate('device')
            .sort({ startTime: -1 });

        // Filter by profile if specified
        let filteredSessions = sessions;
        if (profiles?.length > 0) {
            filteredSessions = sessions.filter(s => 
                profiles.includes(s.user?.profile?.toString())
            );
        }

        // Group by user
        const userActivity = {};
        
        filteredSessions.forEach(session => {
            const userId = session.user?._id?.toString() || 'anonymous';
            
            if (!userActivity[userId]) {
                userActivity[userId] = {
                    user: session.user ? {
                        id: session.user._id,
                        username: session.user.username,
                        profile: session.user.profile
                    } : null,
                    sessions: [],
                    totalSessions: 0,
                    totalDuration: 0,
                    totalBytes: 0,
                    devices: new Set()
                };
            }

            userActivity[userId].sessions.push({
                id: session._id,
                device: session.device?.name,
                startTime: session.startTime,
                endTime: session.endTime,
                duration: session.duration,
                bytesIn: session.traffic.bytesIn,
                bytesOut: session.traffic.bytesOut,
                status: session.status
            });

            userActivity[userId].totalSessions++;
            userActivity[userId].totalDuration += session.duration || 0;
            userActivity[userId].totalBytes += (session.traffic.bytesIn || 0) + (session.traffic.bytesOut || 0);
            userActivity[userId].devices.add(session.device?.name);
        });

        // Convert to array and calculate averages
        const users = Object.values(userActivity).map(u => ({
            ...u,
            devices: Array.from(u.devices),
            avgSessionDuration: u.totalSessions > 0 ? Math.round(u.totalDuration / u.totalSessions) : 0,
            avgBytesPerSession: u.totalSessions > 0 ? Math.round(u.totalBytes / u.totalSessions) : 0
        }));

        return {
            period: { start, end },
            users: users.slice(0, 1000), // Limit to prevent huge reports
            summary: {
                totalUsers: users.length,
                totalSessions: filteredSessions.length,
                totalDuration: users.reduce((sum, u) => sum + u.totalDuration, 0),
                totalBytes: users.reduce((sum, u) => sum + u.totalBytes, 0)
            }
        };
    }

    async generateRevenueReport(report) {
        const { start, end } = report.period;
        const organization = report.organization;

        // Get voucher sales
        const sales = await Voucher.find({
            organization,
            soldAt: { $gte: start, $lte: end },
            status: { $in: ['sold', 'used'] }
        })
        .populate('profile')
        .populate('seller', 'name')
        .populate('batch');

        // Group by date
        const dailySales = {};
        const profileSales = {};
        const sellerSales = {};

        sales.forEach(voucher => {
            const date = voucher.soldAt.toISOString().split('T')[0];
            const profileId = voucher.profile?._id?.toString();
            const sellerId = voucher.seller?._id?.toString();

            // Daily aggregation
            if (!dailySales[date]) {
                dailySales[date] = {
                    date,
                    count: 0,
                    revenue: 0
                };
            }
            dailySales[date].count++;
            dailySales[date].revenue += voucher.price?.amount || 0;

            // Profile aggregation
            if (profileId) {
                if (!profileSales[profileId]) {
                    profileSales[profileId] = {
                        profile: voucher.profile.name,
                        count: 0,
                        revenue: 0
                    };
                }
                profileSales[profileId].count++;
                profileSales[profileId].revenue += voucher.price?.amount || 0;
            }

            // Seller aggregation
            if (sellerId) {
                if (!sellerSales[sellerId]) {
                    sellerSales[sellerId] = {
                        seller: voucher.seller.name,
                        count: 0,
                        revenue: 0
                    };
                }
                sellerSales[sellerId].count++;
                sellerSales[sellerId].revenue += voucher.price?.amount || 0;
            }
        });

        // Get batch performance
        const batches = await VoucherBatch.find({
            organization,
            createdAt: { $gte: start, $lte: end }
        }).populate('profile');

        const batchPerformance = batches.map(batch => ({
            id: batch._id,
            name: batch.name,
            profile: batch.profile?.name,
            created: batch.createdAt,
            total: batch.count,
            sold: batch.sold,
            used: batch.used,
            available: batch.available,
            revenue: batch.revenue,
            performance: batch.count > 0 ? Math.round((batch.sold / batch.count) * 100) : 0
        }));

        return {
            period: { start, end },
            summary: {
                totalSales: sales.length,
                totalRevenue: sales.reduce((sum, v) => sum + (v.price?.amount || 0), 0),
                avgSaleValue: sales.length > 0 ? 
                    sales.reduce((sum, v) => sum + (v.price?.amount || 0), 0) / sales.length : 0
            },
            daily: Object.values(dailySales).sort((a, b) => a.date.localeCompare(b.date)),
            byProfile: Object.values(profileSales).sort((a, b) => b.revenue - a.revenue),
            bySeller: Object.values(sellerSales).sort((a, b) => b.revenue - a.revenue),
            batches: batchPerformance
        };
    }

    async generateBandwidthReport(report) {
        const { start, end } = report.period;
        const { devices } = report.filters;

        const query = {
            organization: report.organization,
            startTime: { $gte: start, $lte: end }
        };

        if (devices?.length > 0) query.device = { $in: devices };

        const sessions = await HotspotSession.find(query)
            .populate('device')
            .select('device startTime endTime traffic duration');

        // Group by device and time period
        const deviceBandwidth = {};
        const hourlyBandwidth = {};

        sessions.forEach(session => {
            const deviceId = session.device?._id?.toString();
            const hour = new Date(session.startTime);
            hour.setMinutes(0, 0, 0);
            const hourKey = hour.toISOString();

            // Device aggregation
            if (deviceId) {
                if (!deviceBandwidth[deviceId]) {
                    deviceBandwidth[deviceId] = {
                        device: session.device.name,
                        totalBytesIn: 0,
                        totalBytesOut: 0,
                        totalSessions: 0,
                        totalDuration: 0
                    };
                }
                deviceBandwidth[deviceId].totalBytesIn += session.traffic.bytesIn || 0;
                deviceBandwidth[deviceId].totalBytesOut += session.traffic.bytesOut || 0;
                deviceBandwidth[deviceId].totalSessions++;
                deviceBandwidth[deviceId].totalDuration += session.duration || 0;
            }

            // Hourly aggregation
            if (!hourlyBandwidth[hourKey]) {
                hourlyBandwidth[hourKey] = {
                    hour: hourKey,
                    bytesIn: 0,
                    bytesOut: 0,
                    sessions: 0
                };
            }
            hourlyBandwidth[hourKey].bytesIn += session.traffic.bytesIn || 0;
            hourlyBandwidth[hourKey].bytesOut += session.traffic.bytesOut || 0;
            hourlyBandwidth[hourKey].sessions++;
        });

        // Calculate averages and peaks
        const deviceStats = Object.values(deviceBandwidth).map(d => ({
            ...d,
            totalBytes: d.totalBytesIn + d.totalBytesOut,
            avgBytesPerSession: d.totalSessions > 0 ? 
                Math.round((d.totalBytesIn + d.totalBytesOut) / d.totalSessions) : 0,
            avgBandwidth: d.totalDuration > 0 ? 
                Math.round((d.totalBytesIn + d.totalBytesOut) * 8 / d.totalDuration) : 0 // bits per second
        }));

        const hourlyStats = Object.values(hourlyBandwidth).sort((a, b) => 
            new Date(a.hour) - new Date(b.hour)
        );

        // Find peak hours
        const peakHours = [...hourlyStats]
            .sort((a, b) => (b.bytesIn + b.bytesOut) - (a.bytesIn + a.bytesOut))
            .slice(0, 10);

        return {
            period: { start, end },
            summary: {
                totalBytesIn: deviceStats.reduce((sum, d) => sum + d.totalBytesIn, 0),
                totalBytesOut: deviceStats.reduce((sum, d) => sum + d.totalBytesOut, 0),
                totalBytes: deviceStats.reduce((sum, d) => sum + d.totalBytes, 0),
                totalSessions: deviceStats.reduce((sum, d) => sum + d.totalSessions, 0)
            },
            devices: deviceStats.sort((a, b) => b.totalBytes - a.totalBytes),
            hourly: hourlyStats,
            peakHours: peakHours.map(h => ({
                ...h,
                totalBytes: h.bytesIn + h.bytesOut
            }))
        };
    }

    async generateSessionAnalytics(report) {
        const { start, end } = report.period;
        const organization = report.organization;

        const sessions = await HotspotSession.find({
            organization,
            startTime: { $gte: start, $lte: end }
        })
        .populate('user')
        .populate('device');

        // Time-based analysis
        const hourDistribution = new Array(24).fill(0);
        const dayDistribution = new Array(7).fill(0);
        const durationBuckets = {
            '<5min': 0,
            '5-15min': 0,
            '15-30min': 0,
            '30-60min': 0,
            '1-2hr': 0,
            '2-4hr': 0,
            '>4hr': 0
        };

        sessions.forEach(session => {
            // Hour distribution
            const hour = session.startTime.getHours();
            hourDistribution[hour]++;

            // Day distribution (0 = Sunday)
            const day = session.startTime.getDay();
            dayDistribution[day]++;

            // Duration distribution
            const duration = session.duration || 0;
            if (duration < 300) durationBuckets['<5min']++;
            else if (duration < 900) durationBuckets['5-15min']++;
            else if (duration < 1800) durationBuckets['15-30min']++;
            else if (duration < 3600) durationBuckets['30-60min']++;
            else if (duration < 7200) durationBuckets['1-2hr']++;
            else if (duration < 14400) durationBuckets['2-4hr']++;
            else durationBuckets['>4hr']++;
        });

        // Device type analysis (from user agent)
        const deviceTypes = {
            mobile: 0,
            tablet: 0,
            desktop: 0,
            other: 0
        };

        sessions.forEach(session => {
            const ua = session.userAgent?.toLowerCase() || '';
            if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
                deviceTypes.mobile++;
            } else if (ua.includes('tablet') || ua.includes('ipad')) {
                deviceTypes.tablet++;
            } else if (ua.includes('windows') || ua.includes('mac') || ua.includes('linux')) {
                deviceTypes.desktop++;
            } else {
                deviceTypes.other++;
            }
        });

        // Concurrent sessions analysis
        const concurrentAnalysis = this.analyzeConcurrentSessions(sessions);

        return {
            period: { start, end },
            summary: {
                totalSessions: sessions.length,
                uniqueUsers: new Set(sessions.map(s => s.user?._id?.toString())).size,
                avgDuration: sessions.length > 0 ?
                    Math.round(sessions.reduce((sum, s) => sum + (s.duration || 0), 0) / sessions.length) : 0,
                totalDataUsed: sessions.reduce((sum, s) => 
                    sum + (s.traffic.bytesIn || 0) + (s.traffic.bytesOut || 0), 0)
            },
            patterns: {
                hourlyDistribution: hourDistribution.map((count, hour) => ({
                    hour,
                    count,
                    percentage: sessions.length > 0 ? Math.round((count / sessions.length) * 100) : 0
                })),
                dailyDistribution: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day, index) => ({
                    day,
                    count: dayDistribution[index],
                    percentage: sessions.length > 0 ? 
                        Math.round((dayDistribution[index] / sessions.length) * 100) : 0
                })),
                durationDistribution: Object.entries(durationBuckets).map(([range, count]) => ({
                    range,
                    count,
                    percentage: sessions.length > 0 ? Math.round((count / sessions.length) * 100) : 0
                })),
                deviceTypes: Object.entries(deviceTypes).map(([type, count]) => ({
                    type,
                    count,
                    percentage: sessions.length > 0 ? Math.round((count / sessions.length) * 100) : 0
                }))
            },
            concurrent: concurrentAnalysis
        };
    }

    analyzeConcurrentSessions(sessions) {
        if (sessions.length === 0) return { peak: 0, average: 0, timeline: [] };

        // Create timeline events
        const events = [];
        sessions.forEach(session => {
            events.push({
                time: session.startTime,
                type: 'start',
                sessionId: session._id
            });
            if (session.endTime) {
                events.push({
                    time: session.endTime,
                    type: 'end',
                    sessionId: session._id
                });
            }
        });

        // Sort events by time
        events.sort((a, b) => a.time - b.time);

        // Calculate concurrent sessions
        let current = 0;
        let peak = 0;
        const timeline = [];
        const activeSessions = new Set();

        events.forEach(event => {
            if (event.type === 'start') {
                activeSessions.add(event.sessionId);
                current = activeSessions.size;
            } else {
                activeSessions.delete(event.sessionId);
                current = activeSessions.size;
            }

            peak = Math.max(peak, current);
            
            // Sample timeline every hour
            const hour = new Date(event.time);
            hour.setMinutes(0, 0, 0);
            const hourKey = hour.toISOString();
            
            if (!timeline.find(t => t.time === hourKey)) {
                timeline.push({
                    time: hourKey,
                    concurrent: current
                });
            }
        });

        const average = timeline.length > 0 ?
            Math.round(timeline.reduce((sum, t) => sum + t.concurrent, 0) / timeline.length) : 0;

        return { peak, average, timeline: timeline.slice(0, 100) }; // Limit timeline points
    }

    async generateVoucherSales(report) {
        const { start, end } = report.period;
        const { batchIds, sellers } = report.filters;

        const query = {
            organization: report.organization,
            createdAt: { $gte: start, $lte: end }
        };

        if (batchIds?.length > 0) query._id = { $in: batchIds };

        const batches = await VoucherBatch.find(query)
            .populate('profile')
            .populate('createdBy', 'name');

        // Get voucher details
        const batchDetails = await Promise.all(batches.map(async (batch) => {
            const voucherQuery = { batch: batch._id };
            if (sellers?.length > 0) voucherQuery.seller = { $in: sellers };

            const vouchers = await Voucher.find(voucherQuery)
                .populate('seller', 'name');

            const statusCounts = {
                available: 0,
                sold: 0,
                used: 0,
                expired: 0,
                cancelled: 0
            };

            const sellerPerformance = {};

            vouchers.forEach(voucher => {
                statusCounts[voucher.status]++;

                if (voucher.seller) {
                    const sellerId = voucher.seller._id.toString();
                    if (!sellerPerformance[sellerId]) {
                        sellerPerformance[sellerId] = {
                            seller: voucher.seller.name,
                            sold: 0,
                            revenue: 0
                        };
                    }
                    if (voucher.status === 'sold' || voucher.status === 'used') {
                        sellerPerformance[sellerId].sold++;
                        sellerPerformance[sellerId].revenue += voucher.price?.amount || 0;
                    }
                }
            });

            return {
                batch: {
                    id: batch._id,
                    name: batch.name,
                    profile: batch.profile?.name,
                    created: batch.createdAt,
                    createdBy: batch.createdBy?.name
                },
                inventory: {
                    total: batch.count,
                    ...statusCounts,
                    soldPercentage: batch.count > 0 ? 
                        Math.round(((statusCounts.sold + statusCounts.used) / batch.count) * 100) : 0
                },
                financial: {
                    totalValue: batch.totalValue || (batch.count * (batch.price || 0)),
                    soldValue: batch.revenue || 0,
                    remainingValue: (statusCounts.available * (batch.price || 0))
                },
                sellers: Object.values(sellerPerformance)
            };
        }));

        // Calculate totals
        const totals = batchDetails.reduce((acc, detail) => ({
            vouchers: acc.vouchers + detail.inventory.total,
            sold: acc.sold + detail.inventory.sold + detail.inventory.used,
            available: acc.available + detail.inventory.available,
            revenue: acc.revenue + detail.financial.soldValue,
            potentialRevenue: acc.potentialRevenue + detail.financial.remainingValue
        }), {
            vouchers: 0,
            sold: 0,
            available: 0,
            revenue: 0,
            potentialRevenue: 0
        });

        return {
            period: { start, end },
            summary: totals,
            batches: batchDetails
        };
    }

    async generateReportFile(report) {
        const filename = `${report.type}_${Date.now()}.${report.format}`;
        const filePath = path.join(this.reportsDir, filename);

        switch (report.format) {
            case 'pdf':
                await this.generatePDFReport(report, filePath);
                break;
            case 'excel':
                await this.generateExcelReport(report, filePath);
                break;
            case 'csv':
                await this.generateCSVReport(report, filePath);
                break;
            case 'json':
                await fs.writeFile(filePath, JSON.stringify(report.data, null, 2));
                break;
            default:
                throw new Error(`Unsupported format: ${report.format}`);
        }

        const stats = await fs.stat(filePath);
        return { filePath, fileSize: stats.size };
    }

    async generatePDFReport(report, filePath) {
        const doc = new PDFDocument({ 
            size: 'A4',
            margins: { top: 50, bottom: 50, left: 50, right: 50 }
        });

        const stream = require('fs').createWriteStream(filePath);
        doc.pipe(stream);

        // Header
        doc.fontSize(20).text(report.name, { align: 'center' });
        doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.moveDown();

        // Report content based on type
        switch (report.type) {
            case 'daily-summary':
                this.renderDailySummaryPDF(doc, report.data);
                break;
            case 'device-status':
                this.renderDeviceStatusPDF(doc, report.data);
                break;
            case 'revenue':
                this.renderRevenuePDF(doc, report.data);
                break;
            default:
                // Generic data rendering
                doc.fontSize(10).text(JSON.stringify(report.data, null, 2));
        }

        doc.end();
        
        return new Promise((resolve, reject) => {
            stream.on('finish', resolve);
            stream.on('error', reject);
        });
    }

    renderDailySummaryPDF(doc, data) {
        doc.fontSize(16).text('Daily Summary', { underline: true });
        doc.moveDown();

        // Device Status
        doc.fontSize(14).text('Device Status');
        doc.fontSize(10)
            .text(`Total Devices: ${data.devices.total}`)
            .text(`Online: ${data.devices.online}`)
            .text(`Offline: ${data.devices.offline}`)
            .text(`Uptime: ${data.devices.uptime}%`);
        doc.moveDown();

        // Session Statistics
        doc.fontSize(14).text('Session Statistics');
        doc.fontSize(10)
            .text(`Total Sessions: ${data.sessions.total}`)
            .text(`Unique Users: ${data.sessions.uniqueUsers}`)
            .text(`Active Now: ${data.sessions.active}`)
            .text(`Average Duration: ${this.formatDuration(data.sessions.avgDuration)}`);
        doc.moveDown();

        // Traffic
        doc.fontSize(14).text('Network Traffic');
        doc.fontSize(10)
            .text(`Total Data: ${this.formatBytes(data.traffic.totalBytes)}`)
            .text(`Per Session: ${this.formatBytes(data.traffic.avgPerSession)}`)
            .text(`Per User: ${this.formatBytes(data.traffic.avgPerUser)}`);
        doc.moveDown();

        // Revenue
        doc.fontSize(14).text('Revenue');
        doc.fontSize(10)
            .text(`Vouchers Sold: ${data.vouchers.sold}`)
            .text(`Vouchers Activated: ${data.vouchers.activated}`)
            .text(`Revenue: ${data.vouchers.revenue} THB`);
    }

    renderDeviceStatusPDF(doc, data) {
        doc.fontSize(16).text('Device Status Report', { underline: true });
        doc.moveDown();

        doc.fontSize(12).text(`Total Devices: ${data.summary.total}`);
        doc.fontSize(10)
            .text(`Online: ${data.summary.online}`)
            .text(`Offline: ${data.summary.offline}`)
            .text(`Active Alerts: ${data.summary.alerts}`);
        doc.moveDown();

        // Device list
        data.devices.forEach(device => {
            doc.fontSize(12).text(device.device.name, { underline: true });
            doc.fontSize(10)
                .text(`Status: ${device.status}`)
                .text(`Model: ${device.device.model}`)
                .text(`Location: ${device.device.location?.name || 'N/A'}`)
                .text(`Last Seen: ${device.lastSeen ? new Date(device.lastSeen).toLocaleString() : 'Never'}`)
                .text(`Active Users: ${device.statistics.activeUsers}`)
                .text(`Today's Sessions: ${device.statistics.todaySessions}`);
            
            if (device.alerts.length > 0) {
                doc.text('Recent Alerts:', { underline: true });
                device.alerts.forEach(alert => {
                    doc.text(`  - ${alert.message} (${alert.type})`);
                });
            }
            
            doc.moveDown();
        });
    }

    renderRevenuePDF(doc, data) {
        doc.fontSize(16).text('Revenue Report', { underline: true });
        doc.moveDown();

        // Summary
        doc.fontSize(14).text('Summary');
        doc.fontSize(10)
            .text(`Total Sales: ${data.summary.totalSales}`)
            .text(`Total Revenue: ${data.summary.totalRevenue} THB`)
            .text(`Average Sale: ${data.summary.avgSaleValue.toFixed(2)} THB`);
        doc.moveDown();

        // Top profiles
        if (data.byProfile.length > 0) {
            doc.fontSize(14).text('Sales by Profile');
            data.byProfile.slice(0, 10).forEach(profile => {
                doc.fontSize(10).text(`${profile.profile}: ${profile.count} sales, ${profile.revenue} THB`);
            });
            doc.moveDown();
        }

        // Top sellers
        if (data.bySeller.length > 0) {
            doc.fontSize(14).text('Top Sellers');
            data.bySeller.slice(0, 10).forEach(seller => {
                doc.fontSize(10).text(`${seller.seller}: ${seller.count} sales, ${seller.revenue} THB`);
            });
        }
    }

    async generateExcelReport(report, filePath) {
        const workbook = new ExcelJS.Workbook();
        
        workbook.creator = 'MikroTik VPN Management System';
        workbook.created = new Date();
        workbook.modified = new Date();

        // Add worksheets based on report type
        switch (report.type) {
            case 'user-activity':
                this.addUserActivitySheet(workbook, report.data);
                break;
            case 'revenue':
                this.addRevenueSheets(workbook, report.data);
                break;
            case 'voucher-sales':
                this.addVoucherSalesSheet(workbook, report.data);
                break;
            default:
                // Generic data sheet
                const sheet = workbook.addWorksheet('Data');
                sheet.addRow(['Report Data']);
                sheet.addRow([JSON.stringify(report.data, null, 2)]);
        }

        await workbook.xlsx.writeFile(filePath);
    }

    addUserActivitySheet(workbook, data) {
        const sheet = workbook.addWorksheet('User Activity');

        // Headers
        sheet.columns = [
            { header: 'Username', key: 'username', width: 20 },
            { header: 'Total Sessions', key: 'sessions', width: 15 },
            { header: 'Total Duration', key: 'duration', width: 15 },
            { header: 'Total Data', key: 'data', width: 15 },
            { header: 'Avg Session', key: 'avgSession', width: 15 },
            { header: 'Devices Used', key: 'devices', width: 30 }
        ];

        // Add data
        data.users.forEach(user => {
            sheet.addRow({
                username: user.user?.username || 'Anonymous',
                sessions: user.totalSessions,
                duration: this.formatDuration(user.totalDuration),
                data: this.formatBytes(user.totalBytes),
                avgSession: this.formatDuration(user.avgSessionDuration),
                devices: user.devices.join(', ')
            });
        });

        // Style header row
        sheet.getRow(1).font = { bold: true };
        sheet.getRow(1).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FF4472C4' },
            bgColor: { argb: 'FF4472C4' }
        };
    }

    addRevenueSheets(workbook, data) {
        // Daily sales sheet
        const dailySheet = workbook.addWorksheet('Daily Sales');
        dailySheet.columns = [
            { header: 'Date', key: 'date', width: 15 },
            { header: 'Count', key: 'count', width: 10 },
            { header: 'Revenue', key: 'revenue', width: 15 }
        ];

        data.daily.forEach(day => {
            dailySheet.addRow(day);
        });

        // Profile performance sheet
        const profileSheet = workbook.addWorksheet('By Profile');
        profileSheet.columns = [
            { header: 'Profile', key: 'profile', width: 20 },
            { header: 'Count', key: 'count', width: 10 },
            { header: 'Revenue', key: 'revenue', width: 15 }
        ];

        data.byProfile.forEach(profile => {
            profileSheet.addRow(profile);
        });

        // Style headers
        [dailySheet, profileSheet].forEach(sheet => {
            sheet.getRow(1).font = { bold: true };
            sheet.getRow(1).fill = {
                type: 'pattern',
                pattern: 'solid',
                fgColor: { argb: 'FF4472C4' }
            };
        });
    }

    addVoucherSalesSheet(workbook, data) {
        const sheet = workbook.addWorksheet('Voucher Sales');

        sheet.columns = [
            { header: 'Batch Name', key: 'batch', width: 25 },
            { header: 'Profile', key: 'profile', width: 20 },
            { header: 'Total', key: 'total', width: 10 },
            { header: 'Sold', key: 'sold', width: 10 },
            { header: 'Available', key: 'available', width: 10 },
            { header: 'Revenue', key: 'revenue', width: 15 },
            { header: 'Performance', key: 'performance', width: 15 }
        ];

        data.batches.forEach(batch => {
            sheet.addRow({
                batch: batch.batch.name,
                profile: batch.batch.profile,
                total: batch.inventory.total,
                sold: batch.inventory.sold + batch.inventory.used,
                available: batch.inventory.available,
                revenue: batch.financial.soldValue,
                performance: `${batch.inventory.soldPercentage}%`
            });
        });

        sheet.getRow(1).font = { bold: true };
    }

    async generateCSVReport(report, filePath) {
        let csv = '';

        switch (report.type) {
            case 'user-activity':
                csv = this.generateUserActivityCSV(report.data);
                break;
            case 'revenue':
                csv = this.generateRevenueCSV(report.data);
                break;
            default:
                csv = this.generateGenericCSV(report.data);
        }

        await fs.writeFile(filePath, csv);
    }

    generateUserActivityCSV(data) {
        const lines = ['Username,Sessions,Duration,Data,Avg Session,Devices'];
        
        data.users.forEach(user => {
            lines.push([
                user.user?.username || 'Anonymous',
                user.totalSessions,
                user.totalDuration,
                user.totalBytes,
                user.avgSessionDuration,
                `"${user.devices.join(', ')}"`
            ].join(','));
        });

        return lines.join('\n');
    }

    generateRevenueCSV(data) {
        const lines = ['Date,Count,Revenue'];
        
        data.daily.forEach(day => {
            lines.push([day.date, day.count, day.revenue].join(','));
        });

        return lines.join('\n');
    }

    generateGenericCSV(data) {
        return JSON.stringify(data, null, 2);
    }

    async getReportFile(report) {
        const filePath = path.join(this.reportsDir, path.basename(report.fileUrl));
        
        try {
            await fs.access(filePath);
            return require('fs').createReadStream(filePath);
        } catch (error) {
            return null;
        }
    }

    async deleteReportFile(report) {
        if (!report.fileUrl) return;
        
        const filePath = path.join(this.reportsDir, path.basename(report.fileUrl));
        
        try {
            await fs.unlink(filePath);
        } catch (error) {
            logger.error(`Failed to delete report file: ${error.message}`);
        }
    }

    async emailReport(report) {
        // TODO: Implement email sending using nodemailer
        const emailService = require('../utils/email');
        
        try {
            await emailService.sendEmail({
                to: report.emailTo.join(', '),
                subject: `Report Ready: ${report.name}`,
                html: `
                    <h2>Your report is ready</h2>
                    <p>The report "${report.name}" has been generated successfully.</p>
                    <p><a href="${process.env.APP_URL}/api/v1/reports/${report._id}/download">Download Report</a></p>
                `
            });
        } catch (error) {
            logger.error(`Failed to send report email: ${error.message}`);
        }

    async scheduleReport(report) {
        // TODO: Implement report scheduling with node-schedule
        const schedule = require('node-schedule');
        
        let rule;
        switch (report.schedule.frequency) {
            case 'daily':
                rule = new schedule.RecurrenceRule();
                const [hour, minute] = report.schedule.time.split(':');
                rule.hour = parseInt(hour);
                rule.minute = parseInt(minute);
                break;
            case 'weekly':
                rule = new schedule.RecurrenceRule();
                rule.dayOfWeek = report.schedule.dayOfWeek;
                const [whour, wminute] = report.schedule.time.split(':');
                rule.hour = parseInt(whour);
                rule.minute = parseInt(wminute);
                break;
            case 'monthly':
                rule = new schedule.RecurrenceRule();
                rule.date = report.schedule.dayOfMonth;
                const [mhour, mminute] = report.schedule.time.split(':');
                rule.hour = parseInt(mhour);
                rule.minute = parseInt(mminute);
                break;
        }
        
        if (rule) {
            const job = schedule.scheduleJob(rule, async () => {
                try {
                    await this.generateReport(report._id);
                } catch (error) {
                    logger.error(`Scheduled report failed: ${error.message}`);
                }
            });
            
            logger.info(`Scheduled report: ${report.name} - ${report.schedule.frequency}`);
        }
    }

    async getDashboardStatistics(organizationId, period = 'today') {
        const now = new Date();
        let start, end;

        switch (period) {
            case 'today':
                start = new Date(now);
                start.setHours(0, 0, 0, 0);
                end = new Date(now);
                end.setHours(23, 59, 59, 999);
                break;
            case 'week':
                start = new Date(now);
                start.setDate(start.getDate() - 7);
                end = now;
                break;
            case 'month':
                start = new Date(now);
                start.setMonth(start.getMonth() - 1);
                end = now;
                break;
        }

        const [
            devices,
            activeSessions,
            todaySessions,
            todayRevenue,
            activeVouchers
        ] = await Promise.all([
            Device.find({ organization: organizationId }),
            HotspotSession.countDocuments({
                organization: organizationId,
                status: 'active'
            }),
            HotspotSession.countDocuments({
                organization: organizationId,
                startTime: { $gte: start, $lte: end }
            }),
            Voucher.aggregate([
                {
                    $match: {
                        organization: organizationId,
                        soldAt: { $gte: start, $lte: end },
                        'price.amount': { $gt: 0 }
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: '$price.amount' }
                    }
                }
            ]),
            Voucher.countDocuments({
                organization: organizationId,
                status: 'available'
            })
        ]);

        return {
            devices: {
                total: devices.length,
                online: devices.filter(d => d.status === 'online').length,
                offline: devices.filter(d => d.status === 'offline').length
            },
            sessions: {
                active: activeSessions,
                today: todaySessions
            },
            revenue: {
                today: todayRevenue[0]?.total || 0
            },
            vouchers: {
                available: activeVouchers
            }
        };
    }

    async getRealtimeMetrics(organizationId) {
        const devices = await Device.find({
            organization: organizationId,
            status: 'online'
        });

        const metrics = await Promise.all(devices.map(async (device) => {
            const activeSessions = await HotspotSession.countDocuments({
                device: device._id,
                status: 'active'
            });

            return {
                device: {
                    id: device._id,
                    name: device.name
                },
                metrics: {
                    cpuUsage: device.health?.cpuUsage || 0,
                    memoryUsage: device.health?.memoryUsage || 0,
                    activeSessions,
                    uptime: device.health?.uptime || 0
                }
            };
        }));

        return metrics;
    }

    // Helper methods
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatDuration(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
        return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
    }
}

module.exports = new ReportService();
EOF
}

# Create report templates
create_report_templates() {
    mkdir -p "$APP_DIR/src/report-templates"
    
    # Email template for reports
    cat << 'EOF' > "$APP_DIR/src/report-templates/email-report.html"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: #2196F3;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px 5px 0 0;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 0 0 5px 5px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .metric {
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 32px;
            font-weight: bold;
            color: #2196F3;
        }
        .metric-label {
            color: #666;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: white;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f5f5f5;
            font-weight: bold;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
        }
        .button {
            display: inline-block;
            padding: 10px 20px;
            background-color: #2196F3;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{reportName}}</h1>
        <p>{{period}}</p>
    </div>
    
    <div class="content">
        <h2>Summary</h2>
        <div class="summary">
            {{#metrics}}
            <div class="metric">
                <div class="metric-value">{{value}}</div>
                <div class="metric-label">{{label}}</div>
            </div>
            {{/metrics}}
        </div>
        
        {{#hasDetails}}
        <h2>Details</h2>
        <table>
            <thead>
                <tr>
                    {{#headers}}
                    <th>{{.}}</th>
                    {{/headers}}
                </tr>
            </thead>
            <tbody>
                {{#rows}}
                <tr>
                    {{#cells}}
                    <td>{{.}}</td>
                    {{/cells}}
                </tr>
                {{/rows}}
            </tbody>
        </table>
        {{/hasDetails}}
        
        <div style="text-align: center;">
            <a href="{{downloadUrl}}" class="button">Download Full Report</a>
        </div>
    </div>
    
    <div class="footer">
        <p>This report was generated automatically by MikroTik VPN Management System</p>
        <p>Generated at: {{generatedAt}}</p>
    </div>
</body>
</html>
EOF
    
    log "Report templates created"
}

# =============================================================================
# PHASE 2.5: INTEGRATION WITH PHASE 1
# =============================================================================

phase2_5_integration() {
    log "=== Phase 2.5: Integrating with Phase 1 Infrastructure ==="
    
    # Create route files first
    create_device_routes
    create_hotspot_routes
    create_voucher_routes
    create_report_routes
    
    # Update Docker Compose with new services
    update_docker_compose
    
    # Update routes in main application
    update_main_routes
    
    # Create integration scripts
    create_integration_scripts
    
    # Update management interface
    update_management_interface
    
    log "Phase 2.5 completed!"
}

# Create device routes
create_device_routes() {
    cat << 'EOF' > "$APP_DIR/routes/devices.js"
const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController');
const { auth, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');

// All routes require authentication
router.use(auth);

// Device routes
router.get('/',
    authorize('admin', 'operator', 'viewer'),
    deviceController.getDevices.bind(deviceController)
);

router.get('/:id',
    authorize('admin', 'operator', 'viewer'),
    param('id').isMongoId(),
    deviceController.getDevice.bind(deviceController)
);

router.post('/',
    authorize('admin'),
    body('name').notEmpty(),
    body('serialNumber').notEmpty(),
    body('macAddress').matches(/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/i),
    body('vpnIpAddress').isIP(),
    deviceController.registerDevice.bind(deviceController)
);

router.put('/:id',
    authorize('admin'),
    param('id').isMongoId(),
    deviceController.updateDevice.bind(deviceController)
);

router.delete('/:id',
    authorize('admin'),
    param('id').isMongoId(),
    deviceController.deleteDevice.bind(deviceController)
);

// Device operations
router.post('/discover',
    authorize('admin', 'operator'),
    deviceController.discoverDevices.bind(deviceController)
);

router.post('/:id/execute',
    authorize('admin', 'operator'),
    param('id').isMongoId(),
    body('command').notEmpty(),
    deviceController.executeCommand.bind(deviceController)
);

router.get('/:id/stats',
    authorize('admin', 'operator', 'viewer'),
    param('id').isMongoId(),
    deviceController.getDeviceStats.bind(deviceController)
);

router.post('/:id/backup',
    authorize('admin'),
    param('id').isMongoId(),
    deviceController.backupDevice.bind(deviceController)
);

router.post('/:id/reboot',
    authorize('admin'),
    param('id').isMongoId(),
    deviceController.rebootDevice.bind(deviceController)
);

router.post('/:id/template',
    authorize('admin'),
    param('id').isMongoId(),
    body('templateId').isMongoId(),
    deviceController.applyTemplate.bind(deviceController)
);

module.exports = router;
EOF
}

# Update Docker Compose
update_docker_compose() {
    log "Updating Docker Compose configuration..."
    
    # Add new environment variables to .env file
    cat << EOF >> "$SYSTEM_DIR/.env"

# Phase 2 Configuration
MIKROTIK_API_TIMEOUT=10000
DEVICE_MONITOR_INTERVAL=60000
HOTSPOT_SESSION_TIMEOUT=14400
VOUCHER_VALIDITY_DAYS=30
REPORT_RETENTION_DAYS=90
ENCRYPTION_KEY=$(openssl rand -base64 32)
EOF

    # Update app service in docker-compose.yml
    cd "$SYSTEM_DIR"
    
    # Create a backup
    cp docker-compose.yml docker-compose.yml.phase1.backup
    
    log "Docker Compose updated with Phase 2 configurations"
}

# Update main routes
update_main_routes() {
    log "Updating main application routes..."
    
    # Check if routes are already added
    if grep -q "Phase 2 Routes" "$APP_DIR/server.js"; then
        log "Routes already added, skipping..."
        return
    fi
    
    # Add Phase 2 routes to server.js
    cat << 'EOF' >> "$APP_DIR/server.js"

// Phase 2 Routes
const deviceRoutes = require('./routes/devices');
const hotspotRoutes = require('./routes/hotspot');
const voucherRoutes = require('./routes/vouchers');
const reportRoutes = require('./routes/reports');

// Register Phase 2 routes
app.use('/api/v1/devices', deviceRoutes);
app.use('/api/v1/hotspot', hotspotRoutes);
app.use('/api/v1/vouchers', voucherRoutes);
app.use('/api/v1/reports', reportRoutes);

// Start device monitoring
const DeviceMonitor = require('./src/mikrotik/lib/device-monitor');
const deviceMonitor = new DeviceMonitor(io);
deviceMonitor.start();

// Cleanup expired vouchers daily
const schedule = require('node-schedule');
schedule.scheduleJob('0 0 * * *', async () => {
    const Voucher = require('./models/Voucher');
    const expired = await Voucher.checkExpired();
    logger.info(`Cleaned up ${expired} expired vouchers`);
});

// Cleanup expired hotspot users daily
schedule.scheduleJob('0 1 * * *', async () => {
    const HotspotUser = require('./models/HotspotUser');
    const expired = await HotspotUser.cleanupExpired();
    logger.info(`Cleaned up ${expired} expired hotspot users`);
});

// Generate daily reports
schedule.scheduleJob('0 6 * * *', async () => {
    const ReportService = require('./src/services/reportService');
    const organizations = await mongoose.model('Organization').find({ isActive: true });
    
    for (const org of organizations) {
        try {
            const report = await mongoose.model('Report').create({
                organization: org._id,
                name: 'Daily Summary',
                type: 'daily-summary',
                period: {
                    start: new Date(new Date().setHours(0, 0, 0, 0)),
                    end: new Date(new Date().setHours(23, 59, 59, 999))
                },
                format: 'pdf',
                status: 'pending',
                generatedBy: org.createdBy || org._id
            });
            
            await ReportService.generateReport(report._id);
        } catch (error) {
            logger.error(`Failed to generate daily report for ${org.name}: ${error.message}`);
        }
    }
});
EOF
}

# Create integration scripts
create_integration_scripts() {
    log "Creating integration scripts..."
    
    # Create MikroTik setup script
    cat << 'EOF' > "$SCRIPT_DIR/setup-mikrotik-device.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== MikroTik Device Setup Wizard ==="
echo

read -p "Enter device name: " DEVICE_NAME
read -p "Enter device IP address: " DEVICE_IP
read -p "Enter device serial number: " DEVICE_SERIAL
read -p "Enter device MAC address: " DEVICE_MAC
read -p "Enter API username (default: admin): " API_USER
API_USER=${API_USER:-admin}
read -s -p "Enter API password: " API_PASS
echo

echo
echo "Generating VPN configuration for device..."

# Generate VPN client config
/opt/mikrotik-vpn/scripts/create-vpn-client.sh "$DEVICE_NAME"

echo
echo "Device registration data:"
echo "========================"
echo "Name: $DEVICE_NAME"
echo "IP: $DEVICE_IP"
echo "Serial: $DEVICE_SERIAL"
echo "MAC: $DEVICE_MAC"
echo "API User: $API_USER"
echo
echo "VPN Config: /opt/mikrotik-vpn/clients/$DEVICE_NAME.ovpn"
echo
echo "Next steps:"
echo "1. Upload the VPN config to your MikroTik device"
echo "2. Configure the VPN client on the device"
echo "3. Register the device in the web interface"
EOF

    chmod +x "$SCRIPT_DIR/setup-mikrotik-device.sh"
    
    # Create hotspot profile sync script
    cat << 'EOF' > "$SCRIPT_DIR/sync-hotspot-profiles.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== Sync Hotspot Profiles to All Devices ==="
echo

# This script will sync hotspot profiles from the database to all connected devices
docker exec mikrotik-app node -e "
const mongoose = require('mongoose');
const Device = require('./models/Device');
const HotspotProfile = require('./models/HotspotProfile');
const MikroTikAPI = require('./src/mikrotik/lib/mikrotik-api');

async function syncProfiles() {
    await mongoose.connect(process.env.MONGODB_URI);
    
    const devices = await Device.find({ status: 'online' });
    const profiles = await HotspotProfile.find({ isActive: true });
    
    console.log(\`Found \${devices.length} online devices and \${profiles.length} active profiles\`);
    
    for (const device of devices) {
        console.log(\`\nSyncing to device: \${device.name}\`);
        
        try {
            const api = new MikroTikAPI({
                host: device.vpnIpAddress,
                user: device.configuration.apiUsername,
                password: device.configuration.apiPassword
            });
            
            await api.connect();
            
            for (const profile of profiles) {
                const commands = profile.generateMikrotikCommands();
                
                for (const cmd of commands) {
                    try {
                        await api.execute(cmd.command, cmd.params);
                        console.log(\`  ✓ Profile '\${profile.name}' synced\`);
                    } catch (error) {
                        console.log(\`  ✗ Failed to sync profile '\${profile.name}': \${error.message}\`);
                    }
                }
            }
            
            await api.disconnect();
        } catch (error) {
            console.log(\`  ✗ Failed to connect: \${error.message}\`);
        }
    }
    
    await mongoose.disconnect();
    console.log('\nSync completed!');
}

syncProfiles().catch(console.error);
"
EOF

    chmod +x "$SCRIPT_DIR/sync-hotspot-profiles.sh"
}

# Update management interface
update_management_interface() {
    log "Updating management interface..."
    
    # Add Phase 2 menu items to mikrotik-vpn script
    sed -i '/echo "8. Help & Documentation"/a\
    echo "9. Device Management"\
    echo "10. Hotspot Management"\
    echo "11. Voucher Management"\
    echo "12. Reports & Analytics"' "$SYSTEM_DIR/mikrotik-vpn"
    
    # Update menu selection
    sed -i 's/read -p "Select option (1-9): " choice/read -p "Select option (1-12): " choice/' "$SYSTEM_DIR/mikrotik-vpn"
    
    # Add new menu handlers
    sed -i '/9) exit 0 ;;/a\
        10) device_management_menu ;;\
        11) hotspot_management_menu ;;\
        12) voucher_management_menu ;;\
        13) reports_menu ;;' "$SYSTEM_DIR/mikrotik-vpn"
    
    # Add new menu functions
    cat << 'EOF' >> "$SYSTEM_DIR/mikrotik-vpn"

# Device management menu
device_management_menu() {
    show_header
    print_colored "$PURPLE" "Device Management"
    print_colored "$PURPLE" "════════════════"
    echo
    echo "1. List all devices"
    echo "2. Add new device"
    echo "3. Device status"
    echo "4. Sync configurations"
    echo "5. Device monitoring"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/list-devices.sh; read -p "Press Enter to continue..."; device_management_menu ;;
        2) $SCRIPT_DIR/setup-mikrotik-device.sh; device_management_menu ;;
        3) $SCRIPT_DIR/device-status.sh; read -p "Press Enter to continue..."; device_management_menu ;;
        4) $SCRIPT_DIR/sync-hotspot-profiles.sh; read -p "Press Enter to continue..."; device_management_menu ;;
        5) $SCRIPT_DIR/device-monitor.sh; device_management_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; device_management_menu ;;
    esac
}

# Hotspot management menu
hotspot_management_menu() {
    show_header
    print_colored "$PURPLE" "Hotspot Management"
    print_colored "$PURPLE" "═════════════════"
    echo
    echo "1. View active sessions"
    echo "2. Manage hotspot users"
    echo "3. Manage profiles"
    echo "4. Session statistics"
    echo "5. Disconnect user"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/active-sessions.sh; read -p "Press Enter to continue..."; hotspot_management_menu ;;
        2) $SCRIPT_DIR/manage-hotspot-users.sh; hotspot_management_menu ;;
        3) $SCRIPT_DIR/manage-profiles.sh; hotspot_management_menu ;;
        4) $SCRIPT_DIR/session-stats.sh; read -p "Press Enter to continue..."; hotspot_management_menu ;;
        5) $SCRIPT_DIR/disconnect-user.sh; hotspot_management_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; hotspot_management_menu ;;
    esac
}

# Voucher management menu
voucher_management_menu() {
    show_header
    print_colored "$PURPLE" "Voucher Management"
    print_colored "$PURPLE" "═════════════════"
    echo
    echo "1. Generate vouchers"
    echo "2. List voucher batches"
    echo "3. Print vouchers"
    echo "4. Voucher sales report"
    echo "5. Activate voucher"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/generate-vouchers.sh; voucher_management_menu ;;
        2) $SCRIPT_DIR/list-voucher-batches.sh; read -p "Press Enter to continue..."; voucher_management_menu ;;
        3) $SCRIPT_DIR/print-vouchers.sh; voucher_management_menu ;;
        4) $SCRIPT_DIR/voucher-sales-report.sh; read -p "Press Enter to continue..."; voucher_management_menu ;;
        5) $SCRIPT_DIR/activate-voucher.sh; voucher_management_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; voucher_management_menu ;;
    esac
}

# Reports menu
reports_menu() {
    show_header
    print_colored "$PURPLE" "Reports & Analytics"
    print_colored "$PURPLE" "══════════════════"
    echo
    echo "1. Generate daily report"
    echo "2. Generate revenue report"
    echo "3. Device status report"
    echo "4. User activity report"
    echo "5. View dashboard"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) $SCRIPT_DIR/generate-daily-report.sh; reports_menu ;;
        2) $SCRIPT_DIR/generate-revenue-report.sh; reports_menu ;;
        3) $SCRIPT_DIR/generate-device-report.sh; reports_menu ;;
        4) $SCRIPT_DIR/generate-user-report.sh; reports_menu ;;
        5) echo "Dashboard URL: https://$DOMAIN_NAME/dashboard"; read -p "Press Enter to continue..."; reports_menu ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; reports_menu ;;
    esac
}
EOF
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "Starting Phase 2: MikroTik Integration"
    log "======================================"
    
    # Check prerequisites
    if [[ ! -d "$SYSTEM_DIR" ]]; then
        log_error "Phase 1 not completed. Please run Phase 1 installation first."
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker ps &>/dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Check if MongoDB is accessible with password
    if ! docker exec mikrotik-mongodb mongosh --eval "db.adminCommand('ping')" \
        --username admin --password "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin &>/dev/null; then
        log_error "Cannot connect to MongoDB. Please check if Phase 1 services are running."
        exit 1
    fi
    
    # Execute Phase 2 components
    phase2_1_device_management || {
        log_error "Phase 2.1 failed"
        exit 1
    }
    
    phase2_2_hotspot_management || {
        log_error "Phase 2.2 failed"
        exit 1
    }
    
    phase2_3_voucher_system || {
        log_error "Phase 2.3 failed"
        exit 1
    }
    
    phase2_4_basic_reporting || {
        log_error "Phase 2.4 failed"
        exit 1
    }
    
    phase2_5_integration || {
        log_error "Phase 2.5 failed"
        exit 1
    }
    
    # Restart services
    log "Restarting services with Phase 2 components..."
    cd "$SYSTEM_DIR"
    docker compose restart app || {
        log_warning "Failed to restart app service"
    }
    
    # Create additional management scripts
    create_additional_scripts
    
    # Final message
    log "======================================"
    log "Phase 2: MikroTik Integration completed successfully!"
    log ""
    log "Database Credentials (from Phase 1):"
    log "  MongoDB Root: admin / $MONGO_ROOT_PASSWORD"
    log "  MongoDB App: mikrotik_app / $MONGO_APP_PASSWORD"
    log "  Redis: $REDIS_PASSWORD"
    log ""
    log "New features available:"
    log "- MikroTik device management via API"
    log "- Hotspot user management"
    log "- Voucher generation and sales"
    log "- Basic reporting and analytics"
    log ""
    log "Access the management interface: mikrotik-vpn"
    log "Or use the web interface: https://$DOMAIN_NAME"
    log ""
    log "API Documentation: https://$DOMAIN_NAME/api-docs"
    log ""
    log "Next: Phase 3 - Business Features (Payment Gateway, Captive Portal, etc.)"
}

# Create additional management scripts
create_additional_scripts() {
    # List devices script
    cat << 'EOF' > "$SCRIPT_DIR/list-devices.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== MikroTik Devices ==="
echo

docker exec mikrotik-app node -e "
const mongoose = require('mongoose');
const Device = require('./models/Device');

async function listDevices() {
    await mongoose.connect(process.env.MONGODB_URI);
    
    const devices = await Device.find().sort({ name: 1 });
    
    console.log('Total devices:', devices.length);
    console.log('');
    
    devices.forEach(device => {
        console.log(\`Device: \${device.name}\`);
        console.log(\`  Status: \${device.status}\`);
        console.log(\`  Model: \${device.model}\`);
        console.log(\`  Serial: \${device.serialNumber}\`);
        console.log(\`  VPN IP: \${device.vpnIpAddress}\`);
        console.log(\`  Last Seen: \${device.lastSeen || 'Never'}\`);
        console.log('');
    });
    
    await mongoose.disconnect();
}

listDevices().catch(console.error);
"
EOF
    chmod +x "$SCRIPT_DIR/list-devices.sh"
    
    # Active sessions script
    cat << 'EOF' > "$SCRIPT_DIR/active-sessions.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== Active Hotspot Sessions ==="
echo

docker exec mikrotik-app node -e "
const mongoose = require('mongoose');
const HotspotSession = require('./models/HotspotSession');

async function showSessions() {
    await mongoose.connect(process.env.MONGODB_URI);
    
    const sessions = await HotspotSession.find({ status: 'active' })
        .populate('device', 'name')
        .populate('user', 'username');
    
    console.log('Active sessions:', sessions.length);
    console.log('');
    
    sessions.forEach(session => {
        const duration = Math.floor((Date.now() - session.startTime) / 1000 / 60);
        console.log(\`User: \${session.user?.username || session.username}\`);
        console.log(\`  Device: \${session.device?.name || 'Unknown'}\`);
        console.log(\`  IP: \${session.ipAddress}\`);
        console.log(\`  Duration: \${duration} minutes\`);
        console.log(\`  Data: \${Math.round((session.traffic.bytesIn + session.traffic.bytesOut) / 1024 / 1024)} MB\`);
        console.log('');
    });
    
    await mongoose.disconnect();
}

showSessions().catch(console.error);
"
EOF
    chmod +x "$SCRIPT_DIR/active-sessions.sh"
    
    # Generate vouchers script
    cat << 'EOF' > "$SCRIPT_DIR/generate-vouchers.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== Generate Vouchers ==="
echo

read -p "Enter profile name: " PROFILE_NAME
read -p "Enter number of vouchers: " COUNT
read -p "Enter prefix (optional): " PREFIX
read -p "Enter validity days: " VALIDITY_DAYS
read -p "Enter price per voucher: " PRICE

docker exec mikrotik-app node -e "
const mongoose = require('mongoose');
const Voucher = require('./models/Voucher');
const HotspotProfile = require('./models/HotspotProfile');

async function generateVouchers() {
    await mongoose.connect(process.env.MONGODB_URI);
    
    const profile = await HotspotProfile.findOne({ name: '$PROFILE_NAME' });
    if (!profile) {
        console.error('Profile not found');
        await mongoose.disconnect();
        return;
    }
    
    const organization = await mongoose.model('Organization').findOne();
    const user = await mongoose.model('User').findOne();
    
    const batch = await Voucher.generateBatch({
        organizationId: organization._id,
        profileId: profile._id,
        count: $COUNT,
        prefix: '$PREFIX',
        validityDays: $VALIDITY_DAYS,
        price: $PRICE,
        createdBy: user._id
    });
    
    console.log('Batch created successfully!');
    console.log('Batch ID:', batch._id);
    console.log('Vouchers generated:', $COUNT);
    
    await mongoose.disconnect();
}

generateVouchers().catch(console.error);
"
EOF
    chmod +x "$SCRIPT_DIR/generate-vouchers.sh"
    
    log "Additional management scripts created"
}

# Execute main function
main "$@"
