#!/bin/bash
# =============================================================================
# Phase 2: MikroTik Integration - Part 3: Voucher System
# Version: 2.0
# Description: Complete implementation of Voucher generation and management
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
    
    # Create voucher routes
    create_voucher_routes
    
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
const { CheckCircle } = require('@mui/icons-material');

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

# Create voucher printing service (with recommended improvement)
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
        // Limit batch size to prevent memory issues
        const BATCH_SIZE = 100;
        if (vouchers.length > BATCH_SIZE) {
            console.warn(`Large batch detected: ${vouchers.length} vouchers. Processing first ${BATCH_SIZE} vouchers.`);
            vouchers = vouchers.slice(0, BATCH_SIZE);
        }

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

    log "Voucher print service created"
}

# Create voucher routes
create_voucher_routes() {
    cat << 'EOF' > "$APP_DIR/routes/vouchers.js"
const express = require('express');
const router = express.Router();
const voucherController = require('../controllers/voucherController');
const { auth, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');

// All routes require authentication
router.use(auth);

// Batch management
router.get('/batches',
    authorize('admin', 'operator', 'viewer', 'seller'),
    voucherController.getBatches.bind(voucherController)
);

router.post('/batches',
    authorize('admin', 'operator'),
    body('profileId').isMongoId(),
    body('count').isInt({ min: 1, max: 10000 }),
    body('validityDays').optional().isInt({ min: 1 }),
    body('price').optional().isNumeric({ min: 0 }),
    voucherController.createBatch.bind(voucherController)
);

// Voucher management
router.get('/',
    authorize('admin', 'operator', 'viewer', 'seller'),
    voucherController.getVouchers.bind(voucherController)
);

router.get('/:id',
    authorize('admin', 'operator', 'viewer', 'seller'),
    voucherController.getVoucher.bind(voucherController)
);

// Voucher operations
router.post('/sell',
    authorize('admin', 'operator', 'seller'),
    body('code').notEmpty(),
    body('customerName').notEmpty(),
    voucherController.sellVoucher.bind(voucherController)
);

router.post('/activate',
    authorize('admin', 'operator'),
    body('code').notEmpty(),
    body('deviceId').isMongoId(),
    voucherController.activateVoucher.bind(voucherController)
);

router.post('/print',
    authorize('admin', 'operator'),
    body('format').optional().isIn(['pdf', 'excel', 'thermal']),
    body('template').optional().isIn(['default', 'compact', 'premium']),
    voucherController.printVouchers.bind(voucherController)
);

router.post('/:id/cancel',
    authorize('admin'),
    param('id').isMongoId(),
    body('reason').optional(),
    voucherController.cancelVoucher.bind(voucherController)
);

// Statistics
router.get('/statistics/summary',
    authorize('admin', 'operator', 'viewer'),
    voucherController.getStatistics.bind(voucherController)
);

module.exports = router;
EOF

    log "Voucher routes created"
}

# Update main application file to include voucher routes
update_main_app() {
    log "Updating main application file..."
    
    # Add voucher routes to server.js
    sed -i "/\/\/ API Routes/a\\
app.use('/api/vouchers', require('./routes/vouchers'));" "$APP_DIR/server.js"
    
    log "Main application updated"
}

# Create voucher management CLI tool
create_voucher_cli() {
    cat << 'EOF' > "$SCRIPT_DIR/voucher-cli.js"
#!/usr/bin/env node

const mongoose = require('mongoose');
const program = require('commander');
const chalk = require('chalk');
const Table = require('cli-table3');
const inquirer = require('inquirer');
const ora = require('ora');
require('dotenv').config();

// Models
const Voucher = require('../app/models/Voucher');
const { VoucherBatch } = require('../app/models/Voucher');
const HotspotProfile = require('../app/models/HotspotProfile');
const Organization = require('../app/models/Organization');

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

program
    .version('1.0.0')
    .description('Voucher Management CLI');

// Generate vouchers
program
    .command('generate')
    .description('Generate a batch of vouchers')
    .option('-o, --org <id>', 'Organization ID')
    .option('-p, --profile <id>', 'Profile ID')
    .option('-c, --count <n>', 'Number of vouchers', parseInt)
    .option('--prefix <prefix>', 'Voucher prefix')
    .option('-d, --days <n>', 'Validity days', parseInt)
    .option('--price <n>', 'Price per voucher', parseFloat)
    .action(async (options) => {
        try {
            if (!options.org || !options.profile || !options.count) {
                console.error(chalk.red('Organization ID, Profile ID, and count are required'));
                process.exit(1);
            }

            const spinner = ora('Generating vouchers...').start();

            const batch = await Voucher.generateBatch({
                organizationId: options.org,
                profileId: options.profile,
                count: options.count,
                prefix: options.prefix || '',
                validityDays: options.days || 30,
                price: options.price || 0,
                createdBy: mongoose.Types.ObjectId() // System generated
            });

            spinner.succeed(chalk.green(`Generated ${options.count} vouchers`));
            console.log(chalk.blue('Batch ID:'), batch._id);

            process.exit(0);
        } catch (error) {
            console.error(chalk.red('Error:'), error.message);
            process.exit(1);
        }
    });

// List vouchers
program
    .command('list')
    .description('List vouchers')
    .option('-b, --batch <id>', 'Filter by batch ID')
    .option('-s, --status <status>', 'Filter by status')
    .option('-l, --limit <n>', 'Limit results', parseInt, 20)
    .action(async (options) => {
        try {
            const query = {};
            if (options.batch) query.batch = options.batch;
            if (options.status) query.status = options.status;

            const vouchers = await Voucher.find(query)
                .populate('profile')
                .limit(options.limit)
                .sort({ createdAt: -1 });

            const table = new Table({
                head: ['Code', 'Profile', 'Status', 'Price', 'Valid Days', 'Created'],
                colWidths: [20, 20, 12, 10, 12, 20]
            });

            vouchers.forEach(v => {
                table.push([
                    v.code,
                    v.profile?.name || 'N/A',
                    v.status,
                    v.price?.amount || 0,
                    v.validity?.days || 0,
                    v.createdAt.toLocaleString()
                ]);
            });

            console.log(table.toString());
            process.exit(0);
        } catch (error) {
            console.error(chalk.red('Error:'), error.message);
            process.exit(1);
        }
    });

// Check expired vouchers
program
    .command('check-expired')
    .description('Check and update expired vouchers')
    .action(async () => {
        try {
            const spinner = ora('Checking expired vouchers...').start();
            
            const count = await Voucher.checkExpired();
            
            spinner.succeed(chalk.green(`Updated ${count} expired vouchers`));
            process.exit(0);
        } catch (error) {
            console.error(chalk.red('Error:'), error.message);
            process.exit(1);
        }
    });

// Export vouchers
program
    .command('export')
    .description('Export vouchers to CSV')
    .option('-b, --batch <id>', 'Batch ID')
    .option('-o, --output <file>', 'Output file', 'vouchers.csv')
    .action(async (options) => {
        try {
            if (!options.batch) {
                console.error(chalk.red('Batch ID is required'));
                process.exit(1);
            }

            const vouchers = await Voucher.find({ batch: options.batch })
                .populate('profile');

            const csv = [
                'Code,Profile,Status,Price,Valid Days,Created',
                ...vouchers.map(v => [
                    v.code,
                    v.profile?.name || '',
                    v.status,
                    v.price?.amount || 0,
                    v.validity?.days || 0,
                    v.createdAt.toISOString()
                ].join(','))
            ].join('\n');

            require('fs').writeFileSync(options.output, csv);
            console.log(chalk.green(`Exported ${vouchers.length} vouchers to ${options.output}`));
            process.exit(0);
        } catch (error) {
            console.error(chalk.red('Error:'), error.message);
            process.exit(1);
        }
    });

// Interactive mode
program
    .command('interactive')
    .description('Interactive voucher management')
    .action(async () => {
        try {
            const { action } = await inquirer.prompt([
                {
                    type: 'list',
                    name: 'action',
                    message: 'What would you like to do?',
                    choices: [
                        'Generate vouchers',
                        'View statistics',
                        'Export vouchers',
                        'Check expired',
                        'Exit'
                    ]
                }
            ]);

            switch (action) {
                case 'Generate vouchers':
                    await generateInteractive();
                    break;
                case 'View statistics':
                    await viewStatistics();
                    break;
                case 'Export vouchers':
                    await exportInteractive();
                    break;
                case 'Check expired':
                    await checkExpiredInteractive();
                    break;
                default:
                    process.exit(0);
            }
        } catch (error) {
            console.error(chalk.red('Error:'), error.message);
            process.exit(1);
        }
    });

// Helper functions
async function generateInteractive() {
    const orgs = await Organization.find();
    const profiles = await HotspotProfile.find();

    const answers = await inquirer.prompt([
        {
            type: 'list',
            name: 'org',
            message: 'Select organization:',
            choices: orgs.map(o => ({ name: o.name, value: o._id }))
        },
        {
            type: 'list',
            name: 'profile',
            message: 'Select profile:',
            choices: profiles.map(p => ({ name: p.name, value: p._id }))
        },
        {
            type: 'number',
            name: 'count',
            message: 'Number of vouchers:',
            default: 10
        },
        {
            type: 'input',
            name: 'prefix',
            message: 'Voucher prefix (optional):'
        },
        {
            type: 'number',
            name: 'days',
            message: 'Validity days:',
            default: 30
        },
        {
            type: 'number',
            name: 'price',
            message: 'Price per voucher:',
            default: 0
        }
    ]);

    const spinner = ora('Generating vouchers...').start();

    const batch = await Voucher.generateBatch({
        organizationId: answers.org,
        profileId: answers.profile,
        count: answers.count,
        prefix: answers.prefix || '',
        validityDays: answers.days,
        price: answers.price,
        createdBy: mongoose.Types.ObjectId()
    });

    spinner.succeed(chalk.green(`Generated ${answers.count} vouchers`));
    console.log(chalk.blue('Batch ID:'), batch._id);
}

async function viewStatistics() {
    const stats = await Voucher.aggregate([
        {
            $group: {
                _id: '$status',
                count: { $sum: 1 },
                revenue: { $sum: '$price.amount' }
            }
        }
    ]);

    const table = new Table({
        head: ['Status', 'Count', 'Revenue'],
        colWidths: [15, 10, 15]
    });

    stats.forEach(s => {
        table.push([s._id, s.count, s.revenue || 0]);
    });

    console.log(table.toString());
}

program.parse(process.argv);

if (!process.argv.slice(2).length) {
    program.outputHelp();
}
EOF

    chmod +x "$SCRIPT_DIR/voucher-cli.js"
    log "Voucher CLI tool created"
}

# Create voucher statistics cron job
create_voucher_cron() {
    cat << 'EOF' > "$SCRIPT_DIR/voucher-stats.js"
#!/usr/bin/env node

const mongoose = require('mongoose');
const Voucher = require('../app/models/Voucher');
const { VoucherBatch } = require('../app/models/Voucher');
const logger = require('../app/utils/logger');
require('dotenv').config();

// Connect to database
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

async function updateVoucherStatistics() {
    try {
        logger.info('Starting voucher statistics update...');

        // Check expired vouchers
        const expiredCount = await Voucher.checkExpired();
        logger.info(`Updated ${expiredCount} expired vouchers`);

        // Update batch statistics
        const batches = await VoucherBatch.find();
        
        for (const batch of batches) {
            const stats = await Voucher.aggregate([
                { $match: { batch: batch._id } },
                {
                    $group: {
                        _id: '$status',
                        count: { $sum: 1 },
                        revenue: { $sum: '$price.amount' }
                    }
                }
            ]);

            let sold = 0, used = 0, revenue = 0;
            
            stats.forEach(stat => {
                if (stat._id === 'sold') sold = stat.count;
                if (stat._id === 'used') {
                    used = stat.count;
                    revenue += stat.revenue || 0;
                }
                if (stat._id === 'sold') {
                    revenue += stat.revenue || 0;
                }
            });

            await VoucherBatch.findByIdAndUpdate(batch._id, {
                sold,
                used,
                revenue
            });
        }

        logger.info('Voucher statistics updated successfully');
        
        // Generate daily report
        await generateDailyReport();
        
    } catch (error) {
        logger.error('Failed to update voucher statistics:', error);
    } finally {
        mongoose.connection.close();
    }
}

async function generateDailyReport() {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const dailyStats = await Voucher.aggregate([
        {
            $match: {
                soldAt: { $gte: today, $lt: tomorrow }
            }
        },
        {
            $group: {
                _id: null,
                count: { $sum: 1 },
                revenue: { $sum: '$price.amount' }
            }
        }
    ]);

    if (dailyStats.length > 0) {
        logger.info(`Daily voucher sales: ${dailyStats[0].count} vouchers, Revenue: ${dailyStats[0].revenue}`);
    }
}

// Run the update
updateVoucherStatistics();
EOF

    chmod +x "$SCRIPT_DIR/voucher-stats.js"
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 1 * * * $SCRIPT_DIR/voucher-stats.js >> $LOG_DIR/voucher-stats.log 2>&1") | crontab -
    
    log "Voucher statistics cron job created"
}

# Install additional dependencies
install_voucher_dependencies() {
    log "Installing additional voucher dependencies..."
    
    cd "$APP_DIR"
    npm install --save \
        qrcode \
        pdfkit \
        exceljs \
        handlebars \
        puppeteer \
        node-thermal-printer \
        ora \
        cli-table3 || {
        log_error "Failed to install voucher dependencies"
        return 1
    }
    
    log "Voucher dependencies installed"
}

# Create voucher dashboard components
create_voucher_dashboard() {
    mkdir -p "$APP_DIR/src/components/vouchers"
    
    # Voucher Dashboard Component
    cat << 'EOF' > "$APP_DIR/src/components/vouchers/VoucherDashboard.js"
import React, { useState, useEffect } from 'react';
import {
    Card,
    CardContent,
    CardHeader,
    Grid,
    Typography,
    Button,
    Box,
    Paper,
    Chip,
    IconButton,
    Menu,
    MenuItem,
    Dialog
} from '@mui/material';
import {
    Add as AddIcon,
    Print as PrintIcon,
    GetApp as DownloadIcon,
    MoreVert as MoreIcon,
    LocalOffer as VoucherIcon,
    AttachMoney as MoneyIcon,
    CheckCircle as ActiveIcon,
    Cancel as ExpiredIcon
} from '@mui/icons-material';
import { Line, Doughnut } from 'react-chartjs-2';
import VoucherBatchDialog from './VoucherBatchDialog';
import VoucherList from './VoucherList';
import { voucherAPI } from '../../services/api';
import { useSnackbar } from 'notistack';

function VoucherDashboard() {
    const [statistics, setStatistics] = useState(null);
    const [batches, setBatches] = useState([]);
    const [selectedBatch, setSelectedBatch] = useState(null);
    const [batchDialogOpen, setBatchDialogOpen] = useState(false);
    const [loading, setLoading] = useState(true);
    const { enqueueSnackbar } = useSnackbar();

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async () => {
        try {
            setLoading(true);
            const [statsRes, batchesRes] = await Promise.all([
                voucherAPI.getStatistics(),
                voucherAPI.getBatches()
            ]);
            setStatistics(statsRes.data.data);
            setBatches(batchesRes.data.data);
        } catch (error) {
            enqueueSnackbar('Failed to load voucher data', { variant: 'error' });
        } finally {
            setLoading(false);
        }
    };

    const handleCreateBatch = async (batchData) => {
        try {
            await voucherAPI.createBatch(batchData);
            enqueueSnackbar('Voucher batch created successfully', { variant: 'success' });
            setBatchDialogOpen(false);
            loadData();
        } catch (error) {
            enqueueSnackbar(error.response?.data?.error || 'Failed to create batch', { variant: 'error' });
        }
    };

    const handlePrintBatch = async (batchId, format = 'pdf') => {
        try {
            const response = await voucherAPI.printVouchers({
                batchId,
                format
            });
            
            if (format === 'pdf') {
                const blob = new Blob([response.data], { type: 'application/pdf' });
                const url = window.URL.createObjectURL(blob);
                window.open(url);
            }
        } catch (error) {
            enqueueSnackbar('Failed to print vouchers', { variant: 'error' });
        }
    };

    const chartData = {
        labels: statistics?.dailySales?.map(d => d._id) || [],
        datasets: [{
            label: 'Daily Sales',
            data: statistics?.dailySales?.map(d => d.revenue) || [],
            borderColor: 'rgb(75, 192, 192)',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            tension: 0.1
        }]
    };

    const doughnutData = {
        labels: ['Available', 'Sold', 'Used', 'Expired'],
        datasets: [{
            data: [
                statistics?.summary?.available || 0,
                statistics?.summary?.sold || 0,
                statistics?.summary?.used || 0,
                statistics?.summary?.expired || 0
            ],
            backgroundColor: [
                '#4CAF50',
                '#2196F3',
                '#FF9800',
                '#F44336'
            ]
        }]
    };

    return (
        <Box>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
                <Typography variant="h4">Voucher Management</Typography>
                <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => setBatchDialogOpen(true)}
                >
                    Create Batch
                </Button>
            </Box>

            {/* Statistics Cards */}
            <Grid container spacing={3} mb={3}>
                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Box display="flex" alignItems="center" justifyContent="space-between">
                                <Box>
                                    <Typography color="textSecondary" gutterBottom>
                                        Total Vouchers
                                    </Typography>
                                    <Typography variant="h4">
                                        {statistics?.summary?.total || 0}
                                    </Typography>
                                </Box>
                                <VoucherIcon color="primary" fontSize="large" />
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Box display="flex" alignItems="center" justifyContent="space-between">
                                <Box>
                                    <Typography color="textSecondary" gutterBottom>
                                        Available
                                    </Typography>
                                    <Typography variant="h4" color="success.main">
                                        {statistics?.summary?.available || 0}
                                    </Typography>
                                </Box>
                                <ActiveIcon color="success" fontSize="large" />
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Box display="flex" alignItems="center" justifyContent="space-between">
                                <Box>
                                    <Typography color="textSecondary" gutterBottom>
                                        Used
                                    </Typography>
                                    <Typography variant="h4" color="warning.main">
                                        {statistics?.summary?.used || 0}
                                    </Typography>
                                </Box>
                                <ActiveIcon color="warning" fontSize="large" />
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Box display="flex" alignItems="center" justifyContent="space-between">
                                <Box>
                                    <Typography color="textSecondary" gutterBottom>
                                        Revenue
                                    </Typography>
                                    <Typography variant="h4">
                                        ฿{statistics?.summary?.revenue || 0}
                                    </Typography>
                                </Box>
                                <MoneyIcon color="primary" fontSize="large" />
                            </Box>
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>

            {/* Charts */}
            <Grid container spacing={3} mb={3}>
                <Grid item xs={12} md={8}>
                    <Card>
                        <CardHeader title="Daily Revenue (Last 30 Days)" />
                        <CardContent>
                            <Line data={chartData} options={{ maintainAspectRatio: false }} height={300} />
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} md={4}>
                    <Card>
                        <CardHeader title="Voucher Status" />
                        <CardContent>
                            <Doughnut data={doughnutData} />
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>

            {/* Batches */}
            <Card>
                <CardHeader title="Recent Batches" />
                <CardContent>
                    <Grid container spacing={2}>
                        {batches.map(batch => (
                            <Grid item xs={12} md={6} lg={4} key={batch._id}>
                                <Paper elevation={2} sx={{ p: 2 }}>
                                    <Box display="flex" justifyContent="space-between" alignItems="start">
                                        <Box>
                                            <Typography variant="h6">
                                                {batch.name || `Batch ${batch._id.slice(-6)}`}
                                            </Typography>
                                            <Typography variant="body2" color="textSecondary">
                                                Profile: {batch.profile?.name}
                                            </Typography>
                                            <Typography variant="body2" color="textSecondary">
                                                Created: {new Date(batch.createdAt).toLocaleDateString()}
                                            </Typography>
                                            <Box mt={1}>
                                                <Chip
                                                    label={`Total: ${batch.count}`}
                                                    size="small"
                                                    sx={{ mr: 1 }}
                                                />
                                                <Chip
                                                    label={`Available: ${batch.available}`}
                                                    size="small"
                                                    color="success"
                                                />
                                            </Box>
                                        </Box>
                                        <Box>
                                            <IconButton
                                                onClick={() => handlePrintBatch(batch._id)}
                                                size="small"
                                            >
                                                <PrintIcon />
                                            </IconButton>
                                            <IconButton
                                                onClick={() => setSelectedBatch(batch)}
                                                size="small"
                                            >
                                                <MoreIcon />
                                            </IconButton>
                                        </Box>
                                    </Box>
                                </Paper>
                            </Grid>
                        ))}
                    </Grid>
                </CardContent>
            </Card>

            {/* Dialogs */}
            <VoucherBatchDialog
                open={batchDialogOpen}
                onClose={() => setBatchDialogOpen(false)}
                onSubmit={handleCreateBatch}
            />

            {selectedBatch && (
                <VoucherList
                    batch={selectedBatch}
                    onClose={() => setSelectedBatch(null)}
                />
            )}
        </Box>
    );
}

export default VoucherDashboard;
EOF

    log "Voucher dashboard components created"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "Starting Phase 2 Part 3: Voucher System"
    log "======================================"
    
    # Check prerequisites
    if [[ ! -d "$SYSTEM_DIR" ]]; then
        log_error "Phase 1 not completed. Please run Phase 1 installation first."
        exit 1
    fi
    
    # Execute Phase 2.3
    phase2_3_voucher_system || {
        log_error "Phase 2.3 failed"
        exit 1
    }
    
    # Install additional dependencies
    install_voucher_dependencies || {
        log_error "Failed to install voucher dependencies"
        exit 1
    }
    
    # Update main application
    update_main_app
    
    # Create CLI tools
    create_voucher_cli
    
    # Create cron jobs
    create_voucher_cron
    
    # Create dashboard components
    create_voucher_dashboard
    
    log "======================================"
    log "Phase 2 Part 3 completed successfully!"
    log ""
    log "Voucher System components installed:"
    log "- Voucher generation and management"
    log "- Voucher batch management"
    log "- Voucher printing (PDF, Excel, Thermal)"
    log "- Voucher sales tracking"
    log "- Voucher activation"
    log "- Revenue tracking"
    log "- CLI management tool: $SCRIPT_DIR/voucher-cli.js"
    log "- Daily statistics cron job"
    log "- React dashboard components"
    log ""
    log "CLI Usage Examples:"
    log "  Generate vouchers: $SCRIPT_DIR/voucher-cli.js generate -o ORG_ID -p PROFILE_ID -c 100"
    log "  List vouchers: $SCRIPT_DIR/voucher-cli.js list -s available"
    log "  Export vouchers: $SCRIPT_DIR/voucher-cli.js export -b BATCH_ID -o vouchers.csv"
    log "  Interactive mode: $SCRIPT_DIR/voucher-cli.js interactive"
    log ""
    log "Continue with Part 4 for Reporting System..."
}

# Execute main function
main "$@"
