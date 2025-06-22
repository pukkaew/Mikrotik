#!/bin/bash
# =============================================================================
# Phase 2: MikroTik Integration - Part 2: Hotspot and User Management
# Version: 2.0
# Description: Complete implementation of Hotspot user management
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

# Load environment
if [[ -f "$CONFIG_DIR/setup.env" ]]; then
    source "$CONFIG_DIR/setup.env"
else
    echo -e "${RED}ERROR: Configuration file not found. Please run Phase 1 first.${NC}"
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

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_DIR/phase2.log"
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
    
    # Create activity log model
    create_activity_log_model
    
    # Create hotspot services
    create_hotspot_services
    
    # Create hotspot utilities
    create_hotspot_utilities
    
    # Update MikroTik API for hotspot
    update_mikrotik_api_hotspot
    
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
const bcrypt = require('bcryptjs');

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
        // Using bcryptjs instead of crypto for better security
        return bcrypt.hashSync(password, 10);
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
                organization: new mongoose.Types.ObjectId(organizationId),
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

# Create ActivityLog model
create_activity_log_model() {
    cat << 'EOF' > "$APP_DIR/models/ActivityLog.js"
const mongoose = require('mongoose');

const activityLogSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        index: true
    },
    action: {
        type: String,
        required: true,
        index: true
    },
    target: {
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'targetModel'
    },
    targetModel: {
        type: String,
        enum: ['Device', 'HotspotUser', 'HotspotProfile', 'Voucher', 'User', 'Organization']
    },
    details: mongoose.Schema.Types.Mixed,
    ipAddress: String,
    userAgent: String,
    result: {
        type: String,
        enum: ['success', 'failure'],
        default: 'success'
    },
    errorMessage: String
}, {
    timestamps: true
});

// Indexes
activityLogSchema.index({ createdAt: -1 });
activityLogSchema.index({ user: 1, createdAt: -1 });
activityLogSchema.index({ organization: 1, createdAt: -1 });
activityLogSchema.index({ action: 1, createdAt: -1 });

// Auto-expire old logs after 90 days
activityLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 7776000 });

module.exports = mongoose.model('ActivityLog', activityLogSchema);
EOF
}

# Create hotspot services
create_hotspot_services() {
    log "Creating hotspot services..."
    
    # Create hotspot service
    cat << 'EOF' > "$APP_DIR/services/hotspotService.js"
const HotspotUser = require('../models/HotspotUser');
const HotspotSession = require('../models/HotspotSession');
const Device = require('../models/Device');
const logger = require('../utils/logger');
const EventEmitter = require('events');

class HotspotService extends EventEmitter {
    constructor() {
        super();
        this.sessionCheckInterval = null;
        this.sessionTimeout = 300000; // 5 minutes
    }

    // Start session monitoring
    startSessionMonitoring() {
        if (this.sessionCheckInterval) {
            clearInterval(this.sessionCheckInterval);
        }

        this.sessionCheckInterval = setInterval(async () => {
            try {
                await this.checkActiveSessions();
                await this.syncSessionsWithDevices();
            } catch (error) {
                logger.error('Session monitoring error:', error);
            }
        }, 60000); // Check every minute

        logger.info('Hotspot session monitoring started');
    }

    // Stop session monitoring
    stopSessionMonitoring() {
        if (this.sessionCheckInterval) {
            clearInterval(this.sessionCheckInterval);
            this.sessionCheckInterval = null;
        }
        logger.info('Hotspot session monitoring stopped');
    }

    // Check active sessions
    async checkActiveSessions() {
        const staleSessions = await HotspotSession.find({
            status: 'active',
            updatedAt: { $lt: new Date(Date.now() - this.sessionTimeout) }
        });

        for (const session of staleSessions) {
            await session.close(null, 'timeout');
            this.emit('sessionTimeout', session);
        }
    }

    // Sync sessions with devices
    async syncSessionsWithDevices() {
        const onlineDevices = await Device.find({ status: 'online' });

        for (const device of onlineDevices) {
            try {
                await this.syncDeviceSessions(device);
            } catch (error) {
                logger.error(`Failed to sync sessions for device ${device.name}:`, error);
            }
        }
    }

    // Sync sessions for a specific device
    async syncDeviceSessions(device) {
        const deviceController = require('../controllers/deviceController');
        const api = await deviceController.getDeviceConnection(device);

        // Get active sessions from MikroTik
        const mikrotikSessions = await api.getHotspotActive();
        const mikrotikSessionIds = mikrotikSessions.map(s => s['.id']);

        // Get active sessions from database
        const dbSessions = await HotspotSession.find({
            device: device._id,
            status: 'active'
        });

        // Check for closed sessions
        for (const dbSession of dbSessions) {
            if (!mikrotikSessionIds.includes(dbSession.sessionId)) {
                // Session no longer active in MikroTik
                const mikrotikSession = mikrotikSessions.find(
                    s => s.user === dbSession.username
                );

                if (mikrotikSession) {
                    await dbSession.close({
                        bytesIn: parseInt(mikrotikSession['bytes-in'] || 0),
                        bytesOut: parseInt(mikrotikSession['bytes-out'] || 0),
                        packetsIn: parseInt(mikrotikSession['packets-in'] || 0),
                        packetsOut: parseInt(mikrotikSession['packets-out'] || 0)
                    }, 'normal');
                } else {
                    await dbSession.close(null, 'device-disconnected');
                }

                this.emit('sessionClosed', dbSession);
            }
        }

        // Check for new sessions
        for (const mikrotikSession of mikrotikSessions) {
            const existingSession = dbSessions.find(
                s => s.sessionId === mikrotikSession['.id']
            );

            if (!existingSession) {
                // New session in MikroTik
                await this.createSessionFromMikrotik(device, mikrotikSession);
            }
        }
    }

    // Create session from MikroTik data
    async createSessionFromMikrotik(device, mikrotikSession) {
        const user = await HotspotUser.findOne({
            device: device._id,
            username: mikrotikSession.user.toLowerCase()
        });

        if (!user) {
            logger.warn(`User ${mikrotikSession.user} not found for session`);
            return;
        }

        const session = await HotspotSession.create({
            organization: device.organization,
            device: device._id,
            user: user._id,
            sessionId: mikrotikSession['.id'],
            username: user.username,
            macAddress: mikrotikSession['mac-address'],
            ipAddress: mikrotikSession.address,
            nasIpAddress: device.ipAddress,
            startTime: new Date(Date.now() - this.parseUptime(mikrotikSession.uptime)),
            status: 'active'
        });

        this.emit('sessionCreated', session);
        return session;
    }

    // Parse MikroTik uptime format
    parseUptime(uptime) {
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

    // Get user statistics
    async getUserStatistics(userId, startDate, endDate) {
        const sessions = await HotspotSession.find({
            user: userId,
            startTime: {
                $gte: startDate || new Date(0),
                $lte: endDate || new Date()
            }
        });

        const stats = {
            totalSessions: sessions.length,
            totalDuration: 0,
            totalBytesIn: 0,
            totalBytesOut: 0,
            totalBytes: 0,
            activeSessions: 0,
            lastSession: null
        };

        sessions.forEach(session => {
            stats.totalDuration += session.duration || 0;
            stats.totalBytesIn += session.traffic.bytesIn || 0;
            stats.totalBytesOut += session.traffic.bytesOut || 0;
            
            if (session.status === 'active') {
                stats.activeSessions++;
            }
            
            if (!stats.lastSession || session.startTime > stats.lastSession.startTime) {
                stats.lastSession = session;
            }
        });

        stats.totalBytes = stats.totalBytesIn + stats.totalBytesOut;

        return stats;
    }

    // Get device statistics
    async getDeviceStatistics(deviceId, startDate, endDate) {
        return HotspotSession.getStatistics(
            deviceId,
            startDate || new Date(0),
            endDate || new Date()
        );
    }

    // Cleanup expired users
    async cleanupExpiredUsers() {
        const count = await HotspotUser.cleanupExpired();
        logger.info(`Cleaned up ${count} expired hotspot users`);
        return count;
    }

    // Generate usage report
    async generateUsageReport(organizationId, startDate, endDate) {
        const pipeline = [
            {
                $match: {
                    organization: organizationId,
                    startTime: {
                        $gte: startDate,
                        $lte: endDate
                    }
                }
            },
            {
                $lookup: {
                    from: 'hotspotusers',
                    localField: 'user',
                    foreignField: '_id',
                    as: 'userInfo'
                }
            },
            {
                $unwind: '$userInfo'
            },
            {
                $lookup: {
                    from: 'devices',
                    localField: 'device',
                    foreignField: '_id',
                    as: 'deviceInfo'
                }
            },
            {
                $unwind: '$deviceInfo'
            },
            {
                $group: {
                    _id: {
                        date: { $dateToString: { format: '%Y-%m-%d', date: '$startTime' } },
                        device: '$deviceInfo.name'
                    },
                    sessions: { $sum: 1 },
                    uniqueUsers: { $addToSet: '$user' },
                    totalDuration: { $sum: '$duration' },
                    totalBytesIn: { $sum: '$traffic.bytesIn' },
                    totalBytesOut: { $sum: '$traffic.bytesOut' }
                }
            },
            {
                $project: {
                    _id: 0,
                    date: '$_id.date',
                    device: '$_id.device',
                    sessions: 1,
                    uniqueUsers: { $size: '$uniqueUsers' },
                    totalDuration: 1,
                    totalBytesIn: 1,
                    totalBytesOut: 1,
                    totalBytes: { $add: ['$totalBytesIn', '$totalBytesOut'] }
                }
            },
            {
                $sort: { date: -1, device: 1 }
            }
        ];

        return HotspotSession.aggregate(pipeline);
    }
}

module.exports = new HotspotService();
EOF

    # Create session cleanup job
    cat << 'EOF' > "$APP_DIR/jobs/sessionCleanup.js"
const cron = require('node-cron');
const HotspotSession = require('../models/HotspotSession');
const HotspotUser = require('../models/HotspotUser');
const logger = require('../utils/logger');

class SessionCleanupJob {
    constructor() {
        this.job = null;
    }

    start() {
        // Run every hour
        this.job = cron.schedule('0 * * * *', async () => {
            logger.info('Starting session cleanup job');
            
            try {
                // Close stale active sessions
                await this.closeStaleActiveSessions();
                
                // Cleanup expired users
                await this.cleanupExpiredUsers();
                
                // Archive old sessions
                await this.archiveOldSessions();
                
                logger.info('Session cleanup job completed');
            } catch (error) {
                logger.error('Session cleanup job failed:', error);
            }
        });

        logger.info('Session cleanup job scheduled');
    }

    stop() {
        if (this.job) {
            this.job.stop();
            this.job = null;
        }
        logger.info('Session cleanup job stopped');
    }

    async closeStaleActiveSessions() {
        const staleTimeout = 6 * 60 * 60 * 1000; // 6 hours
        const staleSessions = await HotspotSession.find({
            status: 'active',
            updatedAt: { $lt: new Date(Date.now() - staleTimeout) }
        });

        let count = 0;
        for (const session of staleSessions) {
            await session.close(null, 'timeout-cleanup');
            count++;
        }

        if (count > 0) {
            logger.info(`Closed ${count} stale active sessions`);
        }
    }

    async cleanupExpiredUsers() {
        const count = await HotspotUser.cleanupExpired();
        if (count > 0) {
            logger.info(`Marked ${count} users as expired`);
        }
    }

    async archiveOldSessions() {
        // Archive sessions older than 90 days
        const archiveDate = new Date();
        archiveDate.setDate(archiveDate.getDate() - 90);

        const oldSessions = await HotspotSession.find({
            endTime: { $lt: archiveDate }
        }).limit(1000); // Process in batches

        if (oldSessions.length > 0) {
            // Here you could move to archive collection or external storage
            // For now, we'll just log
            logger.info(`Found ${oldSessions.length} sessions ready for archiving`);
        }
    }
}

module.exports = new SessionCleanupJob();
EOF
}

# Create hotspot utilities
create_hotspot_utilities() {
    log "Creating hotspot utilities..."
    
    # Create voucher generator utility
    cat << 'EOF' > "$APP_DIR/utils/voucherGenerator.js"
const crypto = require('crypto');

class VoucherGenerator {
    constructor() {
        this.defaultFormat = 'XXXX-XXXX-XXXX';
        this.characters = {
            'X': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'N': '0123456789',
            'A': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        };
    }

    // Generate single voucher code
    generate(format = this.defaultFormat) {
        let code = '';
        
        for (const char of format) {
            if (this.characters[char]) {
                const chars = this.characters[char];
                code += chars.charAt(Math.floor(Math.random() * chars.length));
            } else {
                code += char;
            }
        }
        
        return code;
    }

    // Generate multiple unique codes
    generateBatch(count, format = this.defaultFormat) {
        const codes = new Set();
        
        while (codes.size < count) {
            codes.add(this.generate(format));
        }
        
        return Array.from(codes);
    }

    // Generate secure code
    generateSecure(length = 16) {
        const bytes = crypto.randomBytes(Math.ceil(length * 0.75));
        return bytes.toString('base64')
            .slice(0, length)
            .replace(/\+/g, '0')
            .replace(/\//g, '1');
    }

    // Generate QR code data
    generateQRData(username, password, ssid, authType = 'WPA') {
        // WiFi QR code format
        return `WIFI:T:${authType};S:${ssid};P:${password};H:false;;`;
    }

    // Generate human-friendly code
    generateFriendly(wordCount = 3) {
        const adjectives = [
            'happy', 'sunny', 'blue', 'green', 'swift', 'calm', 'bright', 'cool'
        ];
        const nouns = [
            'ocean', 'mountain', 'river', 'forest', 'cloud', 'star', 'moon', 'sun'
        ];
        const numbers = Math.floor(Math.random() * 9999);
        
        const words = [];
        for (let i = 0; i < wordCount - 1; i++) {
            words.push(adjectives[Math.floor(Math.random() * adjectives.length)]);
        }
        words.push(nouns[Math.floor(Math.random() * nouns.length)]);
        words.push(numbers);
        
        return words.join('-');
    }

    // Validate voucher format
    validateFormat(code, format) {
        if (code.length !== format.length) return false;
        
        for (let i = 0; i < format.length; i++) {
            const formatChar = format[i];
            const codeChar = code[i];
            
            if (this.characters[formatChar]) {
                if (!this.characters[formatChar].includes(codeChar)) {
                    return false;
                }
            } else if (formatChar !== codeChar) {
                return false;
            }
        }
        
        return true;
    }
}

module.exports = new VoucherGenerator();
EOF

    # Create bandwidth calculator utility
    cat << 'EOF' > "$APP_DIR/utils/bandwidthCalculator.js"
class BandwidthCalculator {
    constructor() {
        this.units = {
            'b': 1,
            'k': 1000,
            'K': 1024,
            'm': 1000000,
            'M': 1048576,
            'g': 1000000000,
            'G': 1073741824
        };
    }

    // Parse bandwidth string (e.g., "2M", "512k")
    parse(bandwidthStr) {
        const match = bandwidthStr.match(/^(\d+(?:\.\d+)?)\s*([bkKmMgG])?$/);
        if (!match) return null;
        
        const value = parseFloat(match[1]);
        const unit = match[2] || 'b';
        
        return value * (this.units[unit] || 1);
    }

    // Format bytes to human readable
    format(bytes, binary = true) {
        const divisor = binary ? 1024 : 1000;
        const units = binary ? ['B', 'KiB', 'MiB', 'GiB', 'TiB'] : ['B', 'KB', 'MB', 'GB', 'TB'];
        
        let value = bytes;
        let unitIndex = 0;
        
        while (value >= divisor && unitIndex < units.length - 1) {
            value /= divisor;
            unitIndex++;
        }
        
        return `${value.toFixed(2)} ${units[unitIndex]}`;
    }

    // Calculate time to download/upload
    calculateTime(bytes, bandwidthBps) {
        const seconds = bytes / bandwidthBps;
        
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
        return `${Math.round(seconds / 86400)}d`;
    }

    // Parse MikroTik rate limit format (e.g., "2M/2M")
    parseRateLimit(rateLimit) {
        const parts = rateLimit.split('/');
        return {
            upload: this.parse(parts[0]),
            download: this.parse(parts[1] || parts[0])
        };
    }

    // Calculate usage percentage
    calculateUsagePercentage(used, total) {
        if (!total || total === 0) return 0;
        return Math.min(100, (used / total) * 100);
    }

    // Estimate remaining time based on current usage
    estimateRemainingTime(remainingBytes, averageBps) {
        if (!averageBps || averageBps === 0) return Infinity;
        return this.calculateTime(remainingBytes, averageBps);
    }
}

module.exports = new BandwidthCalculator();
EOF
}

# Update MikroTik API for hotspot
update_mikrotik_api_hotspot() {
    log "Updating MikroTik API for hotspot support..."
    
    # Add hotspot methods to MikroTik API
    cat << 'EOF' >> "$APP_DIR/src/mikrotik/lib/mikrotik-api.js"

// Hotspot API Methods
class HotspotAPI {
    constructor(connection) {
        this.connection = connection;
    }

    // Get hotspot users
    async getUsers() {
        return this.connection.write('/ip/hotspot/user/print');
    }

    // Get specific user
    async getUser(username) {
        return this.connection.write('/ip/hotspot/user/print', {
            where: { name: username }
        });
    }

    // Add hotspot user
    async addUser(params) {
        const userData = {
            name: params.username,
            password: params.password,
            profile: params.profile || 'default'
        };

        if (params.macAddress) userData['mac-address'] = params.macAddress;
        if (params.limitUptime) userData['limit-uptime'] = params.limitUptime;
        if (params.limitBytesTotal) userData['limit-bytes-total'] = params.limitBytesTotal;
        if (params.comment) userData.comment = params.comment;

        return this.connection.write('/ip/hotspot/user/add', userData);
    }

    // Update hotspot user
    async updateUser(username, updates) {
        const user = await this.getUser(username);
        if (!user || user.length === 0) {
            throw new Error('User not found');
        }

        return this.connection.write('/ip/hotspot/user/set', {
            '.id': user[0]['.id'],
            ...updates
        });
    }

    // Remove hotspot user
    async removeUser(username) {
        const user = await this.getUser(username);
        if (!user || user.length === 0) {
            throw new Error('User not found');
        }

        return this.connection.write('/ip/hotspot/user/remove', {
            '.id': user[0]['.id']
        });
    }

    // Get active hotspot sessions
    async getActiveSessions() {
        return this.connection.write('/ip/hotspot/active/print');
    }

    // Disconnect hotspot user
    async disconnectUser(sessionId) {
        return this.connection.write('/ip/hotspot/active/remove', {
            '.id': sessionId
        });
    }

    // Get hotspot profiles
    async getProfiles() {
        return this.connection.write('/ip/hotspot/user/profile/print');
    }

    // Add hotspot profile
    async addProfile(params) {
        return this.connection.write('/ip/hotspot/user/profile/add', params);
    }

    // Get hotspot server info
    async getServers() {
        return this.connection.write('/ip/hotspot/print');
    }

    // Get hotspot hosts
    async getHosts() {
        return this.connection.write('/ip/hotspot/host/print');
    }

    // Get hotspot cookies
    async getCookies() {
        return this.connection.write('/ip/hotspot/cookie/print');
    }

    // Get IP bindings
    async getBindings() {
        return this.connection.write('/ip/hotspot/ip-binding/print');
    }

    // Add IP binding
    async addBinding(params) {
        return this.connection.write('/ip/hotspot/ip-binding/add', params);
    }

    // Get walled garden
    async getWalledGarden() {
        return this.connection.write('/ip/hotspot/walled-garden/print');
    }

    // Add walled garden entry
    async addWalledGarden(params) {
        return this.connection.write('/ip/hotspot/walled-garden/add', params);
    }
}

// Extend main API class
MikroTikAPI.prototype.getHotspotUsers = async function() {
    const hotspot = new HotspotAPI(this);
    return hotspot.getUsers();
};

MikroTikAPI.prototype.getHotspotUser = async function(username) {
    const hotspot = new HotspotAPI(this);
    return hotspot.getUser(username);
};

MikroTikAPI.prototype.addHotspotUser = async function(params) {
    const hotspot = new HotspotAPI(this);
    return hotspot.addUser(params);
};

MikroTikAPI.prototype.updateHotspotUser = async function(username, updates) {
    const hotspot = new HotspotAPI(this);
    return hotspot.updateUser(username, updates);
};

MikroTikAPI.prototype.removeHotspotUser = async function(username) {
    const hotspot = new HotspotAPI(this);
    return hotspot.removeUser(username);
};

MikroTikAPI.prototype.getHotspotActive = async function() {
    const hotspot = new HotspotAPI(this);
    return hotspot.getActiveSessions();
};

MikroTikAPI.prototype.disconnectHotspotUser = async function(sessionId) {
    const hotspot = new HotspotAPI(this);
    return hotspot.disconnectUser(sessionId);
};

MikroTikAPI.prototype.getHotspotProfiles = async function() {
    const hotspot = new HotspotAPI(this);
    return hotspot.getProfiles();
};

MikroTikAPI.prototype.addHotspotProfile = async function(params) {
    const hotspot = new HotspotAPI(this);
    return hotspot.addProfile(params);
};
EOF
}

# Create hotspot routes
create_hotspot_routes() {
    cat << 'EOF' > "$APP_DIR/routes/hotspot.js"
const express = require('express');
const router = express.Router();
const hotspotController = require('../controllers/hotspotController');
const { auth, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');

// All routes require authentication
router.use(auth);

// User management
router.get('/users',
    authorize('admin', 'operator', 'viewer'),
    hotspotController.getUsers.bind(hotspotController)
);

router.get('/users/:id',
    authorize('admin', 'operator', 'viewer'),
    param('id').isMongoId(),
    hotspotController.getUser.bind(hotspotController)
);

router.post('/users',
    authorize('admin', 'operator'),
    body('deviceId').isMongoId(),
    body('username').notEmpty().isAlphanumeric(),
    body('password').notEmpty().isLength({ min: 6 }),
    body('profileId').isMongoId(),
    hotspotController.createUser.bind(hotspotController)
);

router.put('/users/:id',
    authorize('admin', 'operator'),
    param('id').isMongoId(),
    hotspotController.updateUser.bind(hotspotController)
);

router.delete('/users/:id',
    authorize('admin'),
    param('id').isMongoId(),
    hotspotController.deleteUser.bind(hotspotController)
);

// Bulk operations
router.post('/users/bulk',
    authorize('admin', 'operator'),
    body('deviceId').isMongoId(),
    body('profileId').isMongoId(),
    body('count').isInt({ min: 1, max: 1000 }),
    body('prefix').notEmpty(),
    hotspotController.bulkCreateUsers.bind(hotspotController)
);

// Export users
router.get('/users/export/csv',
    authorize('admin', 'operator'),
    hotspotController.exportUsers.bind(hotspotController)
);

// Active sessions
router.get('/sessions/active',
    authorize('admin', 'operator', 'viewer'),
    hotspotController.getActiveSessions.bind(hotspotController)
);

router.post('/sessions/:deviceId/:sessionId/disconnect',
    authorize('admin', 'operator'),
    param('deviceId').isMongoId(),
    param('sessionId').notEmpty(),
    hotspotController.disconnectSession.bind(hotspotController)
);

// Profile management
router.get('/profiles',
    authorize('admin', 'operator', 'viewer'),
    hotspotController.getProfiles.bind(hotspotController)
);

router.post('/profiles',
    authorize('admin'),
    body('name').notEmpty(),
    body('mikrotikName').notEmpty(),
    body('type').isIn(['time-based', 'data-based', 'unlimited', 'hybrid']),
    hotspotController.createProfile.bind(hotspotController)
);

router.put('/profiles/:id',
    authorize('admin'),
    param('id').isMongoId(),
    hotspotController.updateProfile.bind(hotspotController)
);

router.delete('/profiles/:id',
    authorize('admin'),
    param('id').isMongoId(),
    hotspotController.deleteProfile.bind(hotspotController)
);

module.exports = router;
EOF
}

# Update app.js to include hotspot routes
update_app_routes() {
    log "Updating app.js to include hotspot routes..."
    
    # Check if API Routes section exists
    if grep -q "// API Routes" "$APP_DIR/app.js"; then
        # Add hotspot routes to app.js
        sed -i "/\/\/ API Routes/a\
app.use('/api/hotspot', require('./routes/hotspot'));" "$APP_DIR/app.js"
    else
        # Add at the end before module.exports
        sed -i "/module.exports = app/i\
\n// Hotspot routes\
app.use('/api/hotspot', require('./routes/hotspot'));\n" "$APP_DIR/app.js"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "Starting Phase 2 Part 2: Hotspot and User Management"
    log "===================================================="
    
    # Check prerequisites
    if [[ ! -d "$SYSTEM_DIR" ]]; then
        log_error "Phase 1 not completed. Please run Phase 1 installation first."
        exit 1
    fi
    
    # Execute Phase 2.2
    phase2_2_hotspot_management || {
        log_error "Phase 2.2 failed"
        exit 1
    }
    
    # Create routes
    create_hotspot_routes
    
    # Update app.js
    update_app_routes
    
    # Start services
    log "Starting hotspot services..."
    cd "$APP_DIR"
    
    # Import hotspot service in server
    cat << 'EOF' >> "$APP_DIR/server.js"

// Start hotspot service monitoring
const hotspotService = require('./services/hotspotService');
hotspotService.startSessionMonitoring();

// Start session cleanup job
const sessionCleanupJob = require('./jobs/sessionCleanup');
sessionCleanupJob.start();

// Graceful shutdown
process.on('SIGTERM', () => {
    hotspotService.stopSessionMonitoring();
    sessionCleanupJob.stop();
});
EOF
    
    log "======================================"
    log "Phase 2 Part 2 completed successfully!"
    log ""
    log "Hotspot Management components installed:"
    log "- Hotspot user management"
    log "- Hotspot profile management"
    log "- Session tracking and monitoring"
    log "- Activity logging"
    log "- Bulk user creation"
    log "- CSV export functionality"
    log "- Voucher generation utilities"
    log "- Bandwidth calculation utilities"
    log "- Automated session cleanup"
    log ""
    log "API Endpoints:"
    log "- GET    /api/hotspot/users"
    log "- POST   /api/hotspot/users"
    log "- PUT    /api/hotspot/users/:id"
    log "- DELETE /api/hotspot/users/:id"
    log "- POST   /api/hotspot/users/bulk"
    log "- GET    /api/hotspot/users/export/csv"
    log "- GET    /api/hotspot/sessions/active"
    log "- POST   /api/hotspot/sessions/:deviceId/:sessionId/disconnect"
    log "- GET    /api/hotspot/profiles"
    log "- POST   /api/hotspot/profiles"
    log "- PUT    /api/hotspot/profiles/:id"
    log "- DELETE /api/hotspot/profiles/:id"
    log ""
    log "Continue with Part 3 for Voucher System..."
}

# Execute main function
main "$@"
