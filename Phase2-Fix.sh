#!/bin/bash
# =============================================================================
# Phase 2 Comprehensive Diagnosis and Fix Script
# =============================================================================

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Directories
SYSTEM_DIR="/opt/mikrotik-vpn"
APP_DIR="$SYSTEM_DIR/app"
CONFIG_DIR="$SYSTEM_DIR/configs"

# Load environment
if [[ -f "$CONFIG_DIR/setup.env" ]]; then
    source "$CONFIG_DIR/setup.env"
fi

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# =============================================================================
# STEP 1: Stop all services
# =============================================================================
stop_services() {
    log "Stopping all services..."
    
    cd "$SYSTEM_DIR"
    docker compose down || true
    
    # Wait for containers to stop
    sleep 5
    
    # Force stop if still running
    docker stop mikrotik-app 2>/dev/null || true
    docker stop mikrotik-mongodb 2>/dev/null || true
    docker stop mikrotik-redis 2>/dev/null || true
    
    log "All services stopped"
}

# =============================================================================
# STEP 2: Check and fix file structure
# =============================================================================
fix_file_structure() {
    log "Fixing file structure..."
    
    # Create all necessary directories
    directories=(
        "$APP_DIR/src/services"
        "$APP_DIR/src/mikrotik/lib"
        "$APP_DIR/src/mikrotik/templates"
        "$APP_DIR/src/mikrotik/scripts"
        "$APP_DIR/src/voucher-templates"
        "$APP_DIR/src/report-templates"
        "$APP_DIR/controllers"
        "$APP_DIR/models"
        "$APP_DIR/routes"
        "$APP_DIR/middleware"
        "$APP_DIR/utils"
        "$SYSTEM_DIR/storage/reports"
        "$SYSTEM_DIR/storage/backups"
        "$SYSTEM_DIR/storage/exports"
        "$SYSTEM_DIR/storage/temp"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done
    
    # Fix permissions
    chown -R 1000:1000 "$APP_DIR"
    chmod -R 755 "$APP_DIR"
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/storage"
    chmod -R 755 "$SYSTEM_DIR/storage"
}

# =============================================================================
# STEP 3: Create minimal working server.js
# =============================================================================
create_minimal_server() {
    log "Creating minimal server.js..."
    
    # Backup original server.js
    if [ -f "$APP_DIR/server.js" ]; then
        cp "$APP_DIR/server.js" "$APP_DIR/server.js.phase2.backup"
    fi
    
    # Create a minimal working server.js
    cat << 'EOF' > "$APP_DIR/server.js"
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const path = require('path');
const http = require('http');
const socketIO = require('socket.io');

// Initialize express app
const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: process.env.CLIENT_URL || '*',
        credentials: true
    }
});

// Make io globally accessible
global.io = io;

// Logger setup
const logger = require('./utils/logger');

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// Static files
app.use('/static', express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// API routes
app.get('/api', (req, res) => {
    res.json({ 
        message: 'MikroTik VPN Management API',
        version: '2.0',
        phase: 'Phase 2 - MikroTik Integration'
    });
});

// Phase 1 Routes
try {
    const authRoutes = require('./routes/auth');
    const userRoutes = require('./routes/users');
    
    app.use('/api/v1/auth', authRoutes);
    app.use('/api/v1/users', userRoutes);
    
    logger.info('Phase 1 routes loaded successfully');
} catch (error) {
    logger.error('Failed to load Phase 1 routes:', error.message);
}

// Phase 2 Routes - Load safely
const phase2Routes = [
    { path: '/api/v1/devices', file: './routes/devices', name: 'Device' },
    { path: '/api/v1/hotspot', file: './routes/hotspot', name: 'Hotspot' },
    { path: '/api/v1/vouchers', file: './routes/vouchers', name: 'Voucher' },
    { path: '/api/v1/reports', file: './routes/reports', name: 'Report' }
];

phase2Routes.forEach(route => {
    try {
        const routeModule = require(route.file);
        app.use(route.path, routeModule);
        logger.info(`${route.name} routes loaded successfully`);
    } catch (error) {
        logger.warn(`${route.name} routes not available: ${error.message}`);
    }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    logger.info(`Client connected: ${socket.id}`);
    
    socket.on('disconnect', () => {
        logger.info(`Client disconnected: ${socket.id}`);
    });
    
    // Join organization room
    socket.on('join:organization', (organizationId) => {
        socket.join(`org:${organizationId}`);
        logger.info(`Socket ${socket.id} joined organization ${organizationId}`);
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(err.status || 500).json({
        success: false,
        error: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Route not found'
    });
});

// Database connection
const connectDB = async () => {
    try {
        const mongoUri = process.env.MONGODB_URI || 
            `mongodb://mikrotik_app:${process.env.MONGO_APP_PASSWORD}@mongodb:27017/mikrotik_vpn?authSource=mikrotik_vpn`;
        
        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        logger.info('MongoDB connected successfully');
        
        // Initialize Phase 2 services after DB connection
        initializePhase2Services();
        
    } catch (error) {
        logger.error('MongoDB connection failed:', error);
        // Retry after 5 seconds
        setTimeout(connectDB, 5000);
    }
};

// Initialize Phase 2 services
const initializePhase2Services = () => {
    // Device monitoring - only if available
    try {
        const DeviceMonitor = require('./src/mikrotik/lib/device-monitor');
        const deviceMonitor = new DeviceMonitor(io);
        
        // Start monitoring after delay
        setTimeout(() => {
            deviceMonitor.start().catch(err => {
                logger.error('Device monitor start failed:', err.message);
            });
        }, 10000);
        
        logger.info('Device monitor initialized');
    } catch (error) {
        logger.warn('Device monitor not available');
    }
    
    // Scheduled tasks
    try {
        const schedule = require('node-schedule');
        
        // Daily cleanup tasks
        schedule.scheduleJob('0 0 * * *', async () => {
            logger.info('Running daily cleanup tasks...');
            
            // Cleanup vouchers
            try {
                const Voucher = require('./models/Voucher');
                if (Voucher.checkExpired) {
                    const expired = await Voucher.checkExpired();
                    logger.info(`Cleaned up ${expired} expired vouchers`);
                }
            } catch (err) {
                logger.error('Voucher cleanup failed:', err.message);
            }
            
            // Cleanup hotspot users
            try {
                const HotspotUser = require('./models/HotspotUser');
                if (HotspotUser.cleanupExpired) {
                    const expired = await HotspotUser.cleanupExpired();
                    logger.info(`Cleaned up ${expired} expired hotspot users`);
                }
            } catch (err) {
                logger.error('Hotspot user cleanup failed:', err.message);
            }
        });
        
        logger.info('Scheduled tasks initialized');
    } catch (error) {
        logger.warn('Scheduled tasks not available');
    }
};

// Start server
const PORT = process.env.PORT || 3000;

connectDB().then(() => {
    server.listen(PORT, () => {
        logger.info(`Server running on port ${PORT}`);
        logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
        logger.info('Phase 2 integration active');
    });
}).catch(err => {
    logger.error('Failed to start server:', err);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully...');
    server.close(() => {
        mongoose.connection.close(false, () => {
            logger.info('Server closed');
            process.exit(0);
        });
    });
});

module.exports = app;
EOF

    log "Minimal server.js created"
}

# =============================================================================
# STEP 4: Create missing core files
# =============================================================================
create_core_files() {
    log "Creating missing core files..."
    
    # Create logger if missing
    if [ ! -f "$APP_DIR/utils/logger.js" ]; then
        cat << 'EOF' > "$APP_DIR/utils/logger.js"
const winston = require('winston');
const path = require('path');

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.json()
    ),
    defaultMeta: { service: 'mikrotik-vpn' },
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({ 
            filename: path.join('/var/log', 'error.log'), 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: path.join('/var/log', 'combined.log') 
        })
    ]
});

module.exports = logger;
EOF
        log_info "Logger created"
    fi
    
    # Create auth middleware if missing
    if [ ! -f "$APP_DIR/middleware/auth.js" ]; then
        cat << 'EOF' > "$APP_DIR/middleware/auth.js"
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            throw new Error();
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });
        
        if (!user) {
            throw new Error();
        }
        
        req.token = token;
        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        if (roles.length && !roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        next();
    };
};

module.exports = { auth, authorize };
EOF
        log_info "Auth middleware created"
    fi
    
    # Create User model if missing
    if [ ! -f "$APP_DIR/models/User.js" ]; then
        cat << 'EOF' > "$APP_DIR/models/User.js"
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    role: {
        type: String,
        enum: ['admin', 'operator', 'viewer', 'seller'],
        default: 'viewer'
    },
    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization'
    },
    isActive: {
        type: Boolean,
        default: true
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    const user = this;
    
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
    }
    
    next();
});

// Generate auth token
userSchema.methods.generateAuthToken = async function() {
    const user = this;
    const token = jwt.sign(
        { _id: user._id.toString() }, 
        process.env.JWT_SECRET || 'your-secret-key'
    );
    
    user.tokens = user.tokens.concat({ token });
    await user.save();
    
    return token;
};

// Check password
userSchema.methods.checkPassword = async function(password) {
    return bcrypt.compare(password, this.password);
};

// Remove sensitive data
userSchema.methods.toJSON = function() {
    const user = this;
    const userObject = user.toObject();
    
    delete userObject.password;
    delete userObject.tokens;
    
    return userObject;
};

module.exports = mongoose.model('User', userSchema);
EOF
        log_info "User model created"
    fi
}

# =============================================================================
# STEP 5: Create basic routes
# =============================================================================
create_basic_routes() {
    log "Creating basic routes..."
    
    # Create auth routes if missing
    if [ ! -f "$APP_DIR/routes/auth.js" ]; then
        cat << 'EOF' > "$APP_DIR/routes/auth.js"
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { auth } = require('../middleware/auth');

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await User.findOne({ email });
        if (!user || !(await user.checkPassword(password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = await user.generateAuthToken();
        
        res.json({ user, token });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Logout
router.post('/logout', auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.filter(token => token.token !== req.token);
        await req.user.save();
        
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
EOF
        log_info "Auth routes created"
    fi
    
    # Create user routes if missing
    if [ ! -f "$APP_DIR/routes/users.js" ]; then
        cat << 'EOF' > "$APP_DIR/routes/users.js"
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { auth, authorize } = require('../middleware/auth');

// Get current user
router.get('/me', auth, async (req, res) => {
    res.json(req.user);
});

// Get all users (admin only)
router.get('/', auth, authorize('admin'), async (req, res) => {
    try {
        const users = await User.find({});
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
EOF
        log_info "User routes created"
    fi
}

# =============================================================================
# STEP 6: Install missing npm packages
# =============================================================================
install_packages() {
    log "Installing missing npm packages..."
    
    cd "$APP_DIR"
    
    # Core packages that might be missing
    packages=(
        "winston"
        "jsonwebtoken"
        "bcryptjs"
        "express-validator"
        "node-schedule"
        "dotenv"
        "compression"
        "helmet"
        "cors"
        "morgan"
    )
    
    for package in "${packages[@]}"; do
        if ! grep -q "\"$package\"" package.json; then
            log_info "Installing $package..."
            npm install --save "$package" || log_warning "Failed to install $package"
        fi
    done
}

# =============================================================================
# STEP 7: Create initialization script
# =============================================================================
create_init_script() {
    log "Creating initialization script..."
    
    cat << 'EOF' > "$APP_DIR/init-db.js"
const mongoose = require('mongoose');
const User = require('./models/User');
const Organization = require('./models/Organization');

async function initializeDatabase() {
    try {
        // Connect to MongoDB
        const mongoUri = process.env.MONGODB_URI || 
            `mongodb://mikrotik_app:${process.env.MONGO_APP_PASSWORD}@mongodb:27017/mikrotik_vpn?authSource=mikrotik_vpn`;
        
        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log('Connected to MongoDB');
        
        // Check if organization exists
        let organization = await Organization.findOne();
        if (!organization) {
            organization = await Organization.create({
                name: 'Default Organization',
                email: 'admin@mikrotik-vpn.local',
                isActive: true
            });
            console.log('Created default organization');
        }
        
        // Check if admin user exists
        const adminUser = await User.findOne({ email: 'admin@mikrotik-vpn.local' });
        if (!adminUser) {
            await User.create({
                name: 'Admin',
                email: 'admin@mikrotik-vpn.local',
                password: 'admin123',
                role: 'admin',
                organization: organization._id
            });
            console.log('Created default admin user');
            console.log('Email: admin@mikrotik-vpn.local');
            console.log('Password: admin123');
            console.log('IMPORTANT: Change this password immediately!');
        }
        
        console.log('Database initialization completed');
        process.exit(0);
    } catch (error) {
        console.error('Database initialization failed:', error);
        process.exit(1);
    }
}

initializeDatabase();
EOF
}

# =============================================================================
# STEP 8: Start services
# =============================================================================
start_services() {
    log "Starting services..."
    
    cd "$SYSTEM_DIR"
    
    # Start only essential services first
    log_info "Starting MongoDB..."
    docker compose up -d mongodb
    sleep 10
    
    log_info "Starting Redis..."
    docker compose up -d redis
    sleep 5
    
    # Initialize database
    log_info "Initializing database..."
    docker compose run --rm app node init-db.js || log_warning "Database initialization skipped"
    
    # Start app
    log_info "Starting application..."
    docker compose up -d app
    
    # Wait and check status
    sleep 10
    
    if docker ps | grep -q mikrotik-app; then
        log "Application started successfully"
        
        # Show logs
        log_info "Recent application logs:"
        docker logs mikrotik-app --tail 20
    else
        log_error "Application failed to start"
        log_info "Container status:"
        docker ps -a | grep mikrotik
        log_info "Application logs:"
        docker logs mikrotik-app --tail 50
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
main() {
    log "Starting Comprehensive Phase 2 Diagnosis and Fix"
    log "=============================================="
    
    # Step 1: Stop everything
    stop_services
    
    # Step 2: Fix file structure
    fix_file_structure
    
    # Step 3: Create minimal server
    create_minimal_server
    
    # Step 4: Create core files
    create_core_files
    
    # Step 5: Create basic routes
    create_basic_routes
    
    # Step 6: Install packages
    install_packages
    
    # Step 7: Create init script
    create_init_script
    
    # Step 8: Start services
    start_services
    
    log "=============================================="
    log "Diagnosis and fix completed!"
    log ""
    log "Check application status:"
    log "  docker ps"
    log "  docker logs mikrotik-app --tail 50"
    log ""
    log "Test the API:"
    log "  curl http://localhost:3000/health"
    log "  curl http://localhost:3000/api"
    log ""
    log "Default login:"
    log "  Email: admin@mikrotik-vpn.local"
    log "  Password: admin123"
    log ""
    log "If still having issues, check:"
    log "  1. MongoDB connection: docker logs mikrotik-mongodb"
    log "  2. Redis connection: docker logs mikrotik-redis"
    log "  3. Full app logs: docker logs mikrotik-app --tail 100"
}

# Execute main function
main "$@"
