#!/bin/bash
# =============================================================================
# Phase 2: MikroTik Integration - Part 4: Reporting System and Integration
# Version: 2.1 (Corrected)
# Description: Complete implementation of Reporting and Phase 1 Integration
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
    
    # Create report routes
    create_report_routes
    
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

    log "Report model created"
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

    log "Report controller created"
}

# Create report generation service
create_report_service() {
    mkdir -p "$APP_DIR/src/services"
    
    cat << 'EOF' > "$APP_DIR/src/services/reportService.js"
const mongoose = require('mongoose');
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
                    organization: mongoose.Types.ObjectId(organization),
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
        const emailService = require('../../utils/email');
        
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
                        organization: mongoose.Types.ObjectId(organizationId),
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

    log "Report service created"
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

# Create report routes
create_report_routes() {
    cat << 'EOF' > "$APP_DIR/routes/reports.js"
const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { auth, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');

// All routes require authentication
router.use(auth);

// Report management
router.get('/',
    authorize('admin', 'operator', 'viewer'),
    reportController.getReports.bind(reportController)
);

router.get('/types',
    authorize('admin', 'operator', 'viewer'),
    reportController.getReportTypes.bind(reportController)
);

router.get('/:id',
    authorize('admin', 'operator', 'viewer'),
    param('id').isMongoId(),
    reportController.getReport.bind(reportController)
);

router.post('/generate',
    authorize('admin', 'operator'),
    body('type').notEmpty(),
    body('startDate').isISO8601(),
    body('endDate').isISO8601(),
    body('format').optional().isIn(['pdf', 'excel', 'csv', 'json']),
    reportController.generateReport.bind(reportController)
);

router.get('/:id/download',
    authorize('admin', 'operator', 'viewer'),
    param('id').isMongoId(),
    reportController.downloadReport.bind(reportController)
);

router.delete('/:id',
    authorize('admin'),
    param('id').isMongoId(),
    reportController.deleteReport.bind(reportController)
);

// Scheduled reports
router.post('/schedule',
    authorize('admin'),
    body('type').notEmpty(),
    body('schedule.frequency').isIn(['daily', 'weekly', 'monthly']),
    body('schedule.time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    reportController.scheduleReport.bind(reportController)
);

// Dashboard
router.get('/dashboard/stats',
    authorize('admin', 'operator', 'viewer'),
    query('period').optional().isIn(['today', 'week', 'month']),
    reportController.getDashboardStats.bind(reportController)
);

router.get('/dashboard/realtime',
    authorize('admin', 'operator', 'viewer'),
    reportController.getRealtimeMetrics.bind(reportController)
);

module.exports = router;
EOF

    log "Report routes created"
}

# =============================================================================
# PHASE 2.5: INTEGRATION WITH PHASE 1
# =============================================================================

phase2_5_integration() {
    log "=== Phase 2.5: Integrating with Phase 1 Infrastructure ==="
    
    # Update Docker Compose with new services
    update_docker_compose
    
    # Update routes in main application
    update_main_routes
    
    # Create integration scripts
    create_integration_scripts
    
    # Update management interface
    update_management_interface
    
    # Create email utility
    create_email_utility
    
    log "Phase 2.5 completed!"
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
HOTSPOT_URL=https://${DOMAIN_NAME}
SMTP_HOST=
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
SMTP_FROM=noreply@${DOMAIN_NAME}
ALERT_EMAIL=admin@${DOMAIN_NAME}
EOF

    log "Docker Compose updated with Phase 2 configurations"
}

# Create routes
create_device_routes() {
    cat << 'EOF' > "$APP_DIR/routes/devices.js"
const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController');
const { auth, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');

// All routes require authentication
router.use(auth);

// Device management
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
    authorize('admin', 'operator'),
    body('name').notEmpty(),
    body('serialNumber').notEmpty(),
    body('macAddress').matches(/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/i),
    body('vpnIpAddress').isIP(),
    body('apiUsername').notEmpty(),
    body('apiPassword').notEmpty(),
    deviceController.registerDevice.bind(deviceController)
);

router.put('/:id',
    authorize('admin', 'operator'),
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
    body('network').optional().matches(/^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/),
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
    authorize('admin', 'operator'),
    param('id').isMongoId(),
    deviceController.backupDevice.bind(deviceController)
);

router.post('/:id/reboot',
    authorize('admin'),
    param('id').isMongoId(),
    deviceController.rebootDevice.bind(deviceController)
);

router.post('/:id/template',
    authorize('admin', 'operator'),
    param('id').isMongoId(),
    body('templateId').isMongoId(),
    deviceController.applyTemplate.bind(deviceController)
);

module.exports = router;
EOF
}

# Update main routes
update_main_routes() {
    log "Updating main application routes..."
    
    # First, ensure device routes exist
    create_device_routes
    
    # Create a script to update server.js
    cat << 'EOF' > "$SYSTEM_DIR/update-server-routes.js"
const fs = require('fs');
const path = require('path');

const serverPath = path.join(__dirname, 'app/server.js');
let serverContent = fs.readFileSync(serverPath, 'utf8');

// Check if Phase 2 routes are already added
if (serverContent.includes('Phase 2 Routes')) {
    console.log('Phase 2 routes already added');
    process.exit(0);
}

// Find the location to insert routes (before error handling)
const insertPoint = serverContent.indexOf('// Error handling middleware');

if (insertPoint === -1) {
    console.error('Could not find insertion point for routes');
    process.exit(1);
}

const phase2Routes = `
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

// Delay monitor start to ensure DB connection
setTimeout(() => {
    deviceMonitor.start().catch(err => {
        logger.error('Failed to start device monitor:', err);
    });
}, 10000);

// Cleanup expired vouchers daily
const schedule = require('node-schedule');
schedule.scheduleJob('0 0 * * *', async () => {
    try {
        const Voucher = require('./models/Voucher');
        const expired = await Voucher.checkExpired();
        logger.info(\`Cleaned up \${expired} expired vouchers\`);
    } catch (error) {
        logger.error('Voucher cleanup failed:', error);
    }
});

// Cleanup expired hotspot users daily
schedule.scheduleJob('0 1 * * *', async () => {
    try {
        const HotspotUser = require('./models/HotspotUser');
        const expired = await HotspotUser.cleanupExpired();
        logger.info(\`Cleaned up \${expired} expired hotspot users\`);
    } catch (error) {
        logger.error('Hotspot user cleanup failed:', error);
    }
});

`;

// Insert the routes
serverContent = serverContent.slice(0, insertPoint) + phase2Routes + serverContent.slice(insertPoint);

// Write back the updated content
fs.writeFileSync(serverPath, serverContent);
console.log('Phase 2 routes added successfully');
EOF

    # Run the update script
    cd "$SYSTEM_DIR"
    node update-server-routes.js
    rm update-server-routes.js
    
    log "Main routes updated with Phase 2 endpoints"
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
    
    log "Integration scripts created"
}

# Update management interface
update_management_interface() {
    log "Updating management interface..."
    
    # Create Phase 2 menu extension file
    cat << 'EOF' > "$SYSTEM_DIR/mikrotik-vpn-phase2-menu"

# ============================================
# Phase 2 Menu Functions
# ============================================

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
        1) docker exec mikrotik-app node -e "
            const mongoose = require('mongoose');
            const Device = require('./models/Device');
            mongoose.connect(process.env.MONGODB_URI).then(async () => {
                const devices = await Device.find().sort({ name: 1 });
                console.log('Total devices:', devices.length);
                console.log('');
                devices.forEach(device => {
                    console.log(\`Device: \${device.name}\`);
                    console.log(\`  Status: \${device.status}\`);
                    console.log(\`  Model: \${device.model}\`);
                    console.log(\`  VPN IP: \${device.vpnIpAddress}\`);
                    console.log(\`  Last Seen: \${device.lastSeen || 'Never'}\`);
                    console.log('');
                });
                mongoose.disconnect();
            }).catch(console.error);
            "
            read -p "Press Enter to continue..."
            device_management_menu ;;
        2) $SCRIPT_DIR/setup-mikrotik-device.sh; device_management_menu ;;
        3) docker exec mikrotik-app node -e "
            const mongoose = require('mongoose');
            const Device = require('./models/Device');
            mongoose.connect(process.env.MONGODB_URI).then(async () => {
                const devices = await Device.find();
                const online = devices.filter(d => d.status === 'online').length;
                const offline = devices.filter(d => d.status === 'offline').length;
                console.log('Device Status Summary');
                console.log('====================');
                console.log(\`Total: \${devices.length}\`);
                console.log(\`Online: \${online}\`);
                console.log(\`Offline: \${offline}\`);
                mongoose.disconnect();
            }).catch(console.error);
            "
            read -p "Press Enter to continue..."
            device_management_menu ;;
        4) $SCRIPT_DIR/sync-hotspot-profiles.sh; read -p "Press Enter to continue..."; device_management_menu ;;
        5) docker logs mikrotik-app --tail 50 | grep -E "device|Device"; read -p "Press Enter to continue..."; device_management_menu ;;
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
    echo "5. Back to main menu"
    echo
    read -p "Select option (1-5): " choice
    
    case $choice in
        1) docker exec mikrotik-app node -e "
            const mongoose = require('mongoose');
            const HotspotSession = require('./models/HotspotSession');
            mongoose.connect(process.env.MONGODB_URI).then(async () => {
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
                mongoose.disconnect();
            }).catch(console.error);
            "
            read -p "Press Enter to continue..."
            hotspot_management_menu ;;
        2) echo "Use the web interface to manage hotspot users"
            echo "URL: https://$DOMAIN_NAME/hotspot/users"
            read -p "Press Enter to continue..."
            hotspot_management_menu ;;
        3) echo "Use the web interface to manage profiles"
            echo "URL: https://$DOMAIN_NAME/hotspot/profiles"
            read -p "Press Enter to continue..."
            hotspot_management_menu ;;
        4) docker exec mikrotik-app node -e "
            const mongoose = require('mongoose');
            const HotspotSession = require('./models/HotspotSession');
            mongoose.connect(process.env.MONGODB_URI).then(async () => {
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                const sessions = await HotspotSession.find({ startTime: { \$gte: today } });
                const activeSessions = sessions.filter(s => s.status === 'active').length;
                const totalData = sessions.reduce((sum, s) => sum + (s.traffic.bytesIn || 0) + (s.traffic.bytesOut || 0), 0);
                console.log('Today\'s Session Statistics');
                console.log('=========================');
                console.log(\`Total Sessions: \${sessions.length}\`);
                console.log(\`Active Now: \${activeSessions}\`);
                console.log(\`Total Data: \${Math.round(totalData / 1024 / 1024)} MB\`);
                mongoose.disconnect();
            }).catch(console.error);
            "
            read -p "Press Enter to continue..."
            hotspot_management_menu ;;
        5) main_menu ;;
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
    echo "3. Voucher sales report"
    echo "4. Back to main menu"
    echo
    read -p "Select option (1-4): " choice
    
    case $choice in
        1) echo "Use the web interface to generate vouchers"
            echo "URL: https://$DOMAIN_NAME/vouchers/generate"
            read -p "Press Enter to continue..."
            voucher_management_menu ;;
        2) docker exec mikrotik-app node -e "
            const mongoose = require('mongoose');
            const { VoucherBatch } = require('./models/Voucher');
            mongoose.connect(process.env.MONGODB_URI).then(async () => {
                const batches = await VoucherBatch.find()
                    .populate('profile', 'name')
                    .sort({ createdAt: -1 })
                    .limit(10);
                console.log('Recent Voucher Batches');
                console.log('=====================');
                batches.forEach(batch => {
                    console.log(\`\${batch.name || 'Unnamed Batch'}\`);
                    console.log(\`  Profile: \${batch.profile?.name}\`);
                    console.log(\`  Total: \${batch.count}\`);
                    console.log(\`  Available: \${batch.available}\`);
                    console.log(\`  Revenue: \${batch.revenue} THB\`);
                    console.log(\`  Created: \${batch.createdAt.toLocaleDateString()}\`);
                    console.log('');
                });
                mongoose.disconnect();
            }).catch(console.error);
            "
            read -p "Press Enter to continue..."
            voucher_management_menu ;;
        3) docker exec mikrotik-app node -e "
            const mongoose = require('mongoose');
            const Voucher = require('./models/Voucher');
            mongoose.connect(process.env.MONGODB_URI).then(async () => {
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                const todaySales = await Voucher.find({
                    soldAt: { \$gte: today },
                    status: { \$in: ['sold', 'used'] }
                });
                const revenue = todaySales.reduce((sum, v) => sum + (v.price?.amount || 0), 0);
                console.log('Today\'s Voucher Sales');
                console.log('====================');
                console.log(\`Vouchers Sold: \${todaySales.length}\`);
                console.log(\`Total Revenue: \${revenue} THB\`);
                console.log(\`Average Sale: \${todaySales.length > 0 ? Math.round(revenue / todaySales.length) : 0} THB\`);
                mongoose.disconnect();
            }).catch(console.error);
            "
            read -p "Press Enter to continue..."
            voucher_management_menu ;;
        4) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; voucher_management_menu ;;
    esac
}
EOF

    # Append to main mikrotik-vpn script
    if ! grep -q "Phase 2 Menu Functions" "$SYSTEM_DIR/mikrotik-vpn"; then
        echo "" >> "$SYSTEM_DIR/mikrotik-vpn"
        echo "# Include Phase 2 menu functions" >> "$SYSTEM_DIR/mikrotik-vpn"
        echo "source /opt/mikrotik-vpn/mikrotik-vpn-phase2-menu" >> "$SYSTEM_DIR/mikrotik-vpn"
    fi
    
    # Update main menu to include Phase 2 options
    # Create a backup first
    cp "$SYSTEM_DIR/mikrotik-vpn" "$SYSTEM_DIR/mikrotik-vpn.backup-phase2"
    
    # Add menu items using awk for safer editing
    awk '
    /echo "9\. Exit"/ {
        print "echo \"10. Device Management\""
        print "echo \"11. Hotspot Management\"" 
        print "echo \"12. Voucher Management\""
    }
    { print }
    ' "$SYSTEM_DIR/mikrotik-vpn.backup-phase2" > "$SYSTEM_DIR/mikrotik-vpn.tmp"
    
    # Update case statement
    awk '
    /9\) exit 0 ;;/ {
        print "        10) device_management_menu ;;"
        print "        11) hotspot_management_menu ;;"
        print "        12) voucher_management_menu ;;"
    }
    { print }
    ' "$SYSTEM_DIR/mikrotik-vpn.tmp" > "$SYSTEM_DIR/mikrotik-vpn"
    
    rm "$SYSTEM_DIR/mikrotik-vpn.tmp"
    chmod +x "$SYSTEM_DIR/mikrotik-vpn"
    
    log "Management interface updated with Phase 2 features"
}

# Create email utility
create_email_utility() {
    cat << 'EOF' > "$APP_DIR/utils/email.js"
const nodemailer = require('nodemailer');
const logger = require('./logger');

class EmailService {
    constructor() {
        this.transporter = null;
        this.initTransporter();
    }

    initTransporter() {
        if (process.env.SMTP_HOST) {
            this.transporter = nodemailer.createTransporter({
                host: process.env.SMTP_HOST,
                port: process.env.SMTP_PORT || 587,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });
        }
    }

    async sendEmail(options) {
        if (!this.transporter) {
            logger.warn('Email service not configured');
            return false;
        }

        try {
            const mailOptions = {
                from: process.env.SMTP_FROM || 'noreply@mikrotik-vpn.local',
                to: options.to,
                subject: options.subject,
                text: options.text,
                html: options.html
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info(`Email sent: ${info.messageId}`);
            return true;
        } catch (error) {
            logger.error('Failed to send email:', error);
            return false;
        }
    }

    async sendAlert(alert) {
        const subject = `[Alert] ${alert.type}: ${alert.device}`;
        const html = `
            <h2>System Alert</h2>
            <p><strong>Type:</strong> ${alert.type}</p>
            <p><strong>Device:</strong> ${alert.device}</p>
            <p><strong>Message:</strong> ${alert.message}</p>
            <p><strong>Time:</strong> ${alert.timestamp}</p>
        `;

        return this.sendEmail({
            to: process.env.ALERT_EMAIL || process.env.ADMIN_EMAIL,
            subject,
            html
        });
    }
}

module.exports = new EmailService();
EOF

    log "Email utility created"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "Starting Phase 2 Part 4: Reporting System and Integration"
    log "========================================================"
    
    # Check prerequisites
    if [[ ! -d "$SYSTEM_DIR" ]]; then
        log_error "Phase 1 not completed. Please run Phase 1 installation first."
        exit 1
    fi
    
    # Check if required directories exist
    if [[ ! -d "$APP_DIR" ]]; then
        log_error "Application directory not found. Please ensure Phase 2 Part 1-3 are completed."
        exit 1
    fi
    
    # Execute Phase 2.4
    phase2_4_basic_reporting || {
        log_error "Phase 2.4 failed"
        exit 1
    }
    
    # Execute Phase 2.5
    phase2_5_integration || {
        log_error "Phase 2.5 failed"
        exit 1
    }
    
    # Create storage directory for reports
    mkdir -p "$APP_DIR/storage/reports"
    chmod 755 "$APP_DIR/storage/reports"
    
    # Restart services
    log "Restarting services with Phase 2 components..."
    cd "$SYSTEM_DIR"
    
    # Check if docker compose command exists
    if command -v docker-compose &> /dev/null; then
        docker-compose restart app || {
            log_warning "Failed to restart app service"
        }
    else
        docker compose restart app || {
            log_warning "Failed to restart app service"
        }
    fi
    
    log "======================================"
    log "Phase 2 Part 4 completed successfully!"
    log ""
    log "Reporting System components installed:"
    log "- Daily, weekly, and monthly summaries"
    log "- Device status reports"
    log "- User activity reports"
    log "- Revenue reports"
    log "- Bandwidth usage reports"
    log "- Session analytics"
    log "- Voucher sales reports"
    log "- PDF, Excel, and CSV export"
    log "- Email notifications"
    log "- Real-time dashboard metrics"
    log ""
    log "Phase 2 Integration completed!"
    log ""
    log "All Phase 2 components are now installed and integrated."
    log ""
    log "Access the system:"
    log "- Web Interface: https://$DOMAIN_NAME"
    log "- Management CLI: mikrotik-vpn"
    log "- API Documentation: https://$DOMAIN_NAME/api-docs"
    log ""
    log "Default credentials:"
    log "- Username: admin"
    log "- Email: admin@mikrotik-vpn.local"
    log "- Password: admin123"
    log ""
    log "IMPORTANT: Change the default password immediately!"
    log ""
    log "To configure email notifications:"
    log "1. Edit /opt/mikrotik-vpn/.env"
    log "2. Add SMTP configuration"
    log "3. Restart the application"
    log ""
    log "Next: Phase 3 - Business Features (Payment Gateway, Captive Portal, etc.)"
}

# Execute main function
main "$@"
