/**
 * ============================================================
 * FIREWALL SERVER - firewallServer.js
 * ============================================================
 * 
 * This is the main firewall server running on PORT 3000.
 * 
 * Responsibilities:
 *   1. Serve the Firewall Management Center dashboard
 *   2. Apply firewall middleware to all proxied requests
 *   3. Forward allowed requests to the Application Server (port 5000)
 *   4. Provide API endpoints for dashboard data
 * 
 * Architecture:
 * 
 *   Client Request
 *        │
 *        ▼
 *   ┌──────────────────────┐
 *   │  FIREWALL (port 3000)│
 *   │  ┌────────────────┐  │
 *   │  │ Blocked IP Chk │  │
 *   │  │ Rate Limiter   │  │
 *   │  │ Access Policy  │  │
 *   │  │ IDS Scanner    │  │
 *   │  │ Traffic Logger │  │
 *   │  └────────────────┘  │
 *   └──────────┬───────────┘
 *              │ (if ALLOWED)
 *              ▼
 *   ┌──────────────────────┐
 *   │  APP SERVER (port 5000)│
 *   └──────────────────────┘
 * 
 * ============================================================
 */

require('dotenv').config();

const express = require('express');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

// ── Import firewall modules ─────────────────────────────────
const db = require('./database');
const firewall = require('./firewallMiddleware');

// ── Initialize Express app ──────────────────────────────────
const app = express();
const PORT = 4000;
const APP_SERVER_URL = 'http://127.0.0.1:5000';

// ── Database is initialized asynchronously in startServer() ──

// ============================================================
// GLOBAL MIDDLEWARE
// ============================================================

// Enable CORS for dashboard API calls
app.use(cors());

// Parse JSON and URL-encoded request bodies
// (Needed for POST request inspection by the IDS)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// ============================================================
// DASHBOARD ROUTES (served directly by the firewall)
// ============================================================

/**
 * Serve the Firewall Management Center dashboard.
 * The dashboard is a static HTML/CSS/JS application.
 */
app.use('/dashboard', express.static(path.join(__dirname, '..', 'dashboard')));

/**
 * Redirect root of firewall to the dashboard.
 * When a user visits http://localhost:3000/, they see the dashboard.
 */
app.get('/', (req, res) => {
    res.redirect('/dashboard');
});


// ============================================================
// DASHBOARD API ENDPOINTS
// ============================================================

/**
 * GET /api/traffic-logs
 * Returns all traffic log entries for the dashboard.
 */
app.get('/api/traffic-logs', (req, res) => {
    try {
        const logs = db.getTrafficLogs();
        res.json({ success: true, data: logs });
    } catch (err) {
        console.error('[API] Error fetching traffic logs:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/intrusion-logs
 * Returns all intrusion detection log entries.
 */
app.get('/api/intrusion-logs', (req, res) => {
    try {
        const logs = db.getIntrusionLogs();
        res.json({ success: true, data: logs });
    } catch (err) {
        console.error('[API] Error fetching intrusion logs:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/audit-logs
 * Returns all audit/system log entries.
 */
app.get('/api/audit-logs', (req, res) => {
    try {
        const logs = db.getAuditLogs();
        res.json({ success: true, data: logs });
    } catch (err) {
        console.error('[API] Error fetching audit logs:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/stats
 * Returns overview statistics for the dashboard header.
 */
app.get('/api/stats', (req, res) => {
    try {
        const stats = db.getStats();
        stats.aiEngineMode = process.env.OPENAI_API_KEY ? 'OPENAI' : 'FALLBACK';
        if (stats.aiBlockedRequests == null) stats.aiBlockedRequests = stats.blockedRequests;
        res.json({ success: true, data: stats });
    } catch (err) {
        console.error('[API] Error fetching stats:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/blocked-ips
 * Returns all currently blocked IP addresses.
 */
app.get('/api/blocked-ips', (req, res) => {
    try {
        const ips = db.getBlockedIPs();
        res.json({ success: true, data: ips });
    } catch (err) {
        console.error('[API] Error fetching blocked IPs:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * POST /api/blocked-ips
 * Block an IP address (body: { ip, reason }). Used for testing or manual block.
 */
app.post('/api/blocked-ips', (req, res) => {
    try {
        const { ip, reason } = req.body || {};
        if (!ip || typeof ip !== 'string' || !ip.trim()) {
            return res.status(400).json({ success: false, error: 'ip is required' });
        }
        const ipTrim = ip.trim();
        if (db.isIPBlocked(ipTrim)) {
            return res.json({ success: true, message: 'IP already blocked' });
        }
        db.blockIP(ipTrim, (reason && typeof reason === 'string') ? reason.trim() : 'Manually blocked');
        db.logAudit(`IP added to block list: ${ipTrim}`);
        console.log(`[API] IP blocked: ${ipTrim}`);
        res.json({ success: true, message: 'IP blocked successfully' });
    } catch (err) {
        console.error('[API] Error blocking IP:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * DELETE /api/blocked-ips/:id
 * Unblock an IP address by removing it from the blocked list.
 */
app.delete('/api/blocked-ips/:id', (req, res) => {
    try {
        const id = req.params.id;
        db.unblockIP(id);
        db.logAudit(`IP unblocked from the blocked list: ID ${id}`);
        console.log(`[API] IP unblocked: ID ${id}`);
        res.json({ success: true, message: 'IP unblocked successfully' });
    } catch (err) {
        console.error('[API] Error unblocking IP:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});


// ============================================================
// AI-NGFW API ENDPOINTS
// ============================================================

/**
 * GET /api/ai-threat-logs
 * Traffic log entries flagged by the AI engine (risk > 0.3).
 */
app.get('/api/ai-threat-logs', (req, res) => {
    try {
        const logs = db.getAIThreatLogs();
        res.json({ success: true, data: logs });
    } catch (err) {
        console.error('[API] Error fetching AI threat logs:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/risk-metrics
 * Aggregate AI risk metrics for the dashboard.
 */
app.get('/api/risk-metrics', (req, res) => {
    try {
        const metrics = db.getRiskMetrics();
        res.json({ success: true, data: metrics });
    } catch (err) {
        console.error('[API] Error fetching risk metrics:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/top-attackers
 * Top attacking IPs ranked by average risk score.
 */
app.get('/api/top-attackers', (req, res) => {
    try {
        const attackers = db.getTopAttackers();
        res.json({ success: true, data: attackers });
    } catch (err) {
        console.error('[API] Error fetching top attackers:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/threat-intel-stats
 * Stub for dashboard compatibility (LLM-only mode; no threat intel feed).
 */
app.get('/api/threat-intel-stats', (req, res) => {
    res.json({
        success: true,
        data: {
            totalMaliciousIPs: 0,
            totalMaliciousDomains: 0,
            totalTorExitNodes: 0,
            totalKnownScanners: 0,
            feeds: []
        }
    });
});

// ============================================================
// LLM-ONLY SECURITY PIPELINE
// ============================================================

/**
 * Pipeline: Blocked IP → Rate Limit → AI Security Engine (OpenAI) → Decision → Logger → Proxy
 */
app.use('/proxy/*', firewall.checkBlockedIP);
app.use('/proxy/*', firewall.rateLimiter);
app.use('/proxy/*', firewall.blockRestrictedPaths);
app.use('/proxy/*', firewall.aiSecurityEngineMiddleware);
app.use('/proxy/*', firewall.trafficLogger);


// ============================================================
// PROXY: FORWARD ALLOWED REQUESTS TO APP SERVER
// ============================================================

/**
 * After passing all firewall checks, forward the request
 * to the Application Server running on port 5000.
 * 
 * The proxy strips the /proxy prefix before forwarding.
 * Example: /proxy/api/data → http://127.0.0.1:5000/api/data
 */
app.use('/proxy', createProxyMiddleware({
    target: APP_SERVER_URL,
    changeOrigin: true,
    pathRewrite: { '^/proxy': '' },
    onError: (err, req, res) => {
        console.error('[PROXY] Error forwarding to app server:', err.message);
        res.status(502).json({
            error: 'Bad Gateway',
            message: 'Application server is not reachable. Make sure it is running on port 5000.'
        });
    }
}));


// ============================================================
// DIRECT FIREWALL ROUTES (for testing without /proxy prefix)
// ============================================================

/**
 * These routes apply firewall rules directly to common paths.
 * This allows testing the firewall by accessing port 3000 directly:
 *   http://localhost:3000/login
 *   http://localhost:3000/admin
 *   http://localhost:3000/api/data
 */

// Apply firewall middleware to direct test routes
const firewallChain = [
    firewall.checkBlockedIP,
    firewall.rateLimiter,
    firewall.blockRestrictedPaths,
    firewall.aiSecurityEngineMiddleware,
    firewall.trafficLogger
];

app.all('/login', ...firewallChain, (req, res) => {
    // Forward to app server
    const http = require('http');
    const options = {
        hostname: '127.0.0.1',
        port: 5000,
        path: req.originalUrl,
        method: req.method,
        headers: req.headers
    };
    const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    proxyReq.on('error', () => {
        res.status(502).json({ error: 'Application server unreachable' });
    });
    if (req.body && Object.keys(req.body).length > 0) {
        proxyReq.write(JSON.stringify(req.body));
    }
    proxyReq.end();
});

app.all('/admin', ...firewallChain, (req, res) => {
    const http = require('http');
    const options = {
        hostname: '127.0.0.1',
        port: 5000,
        path: req.originalUrl,
        method: req.method,
        headers: req.headers
    };
    const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    proxyReq.on('error', () => {
        res.status(502).json({ error: 'Application server unreachable' });
    });
    proxyReq.end();
});

app.all('/api/data', ...firewallChain, (req, res) => {
    const http = require('http');
    const options = {
        hostname: '127.0.0.1',
        port: 5000,
        path: req.originalUrl,
        method: req.method,
        headers: req.headers
    };
    const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    proxyReq.on('error', () => {
        res.status(502).json({ error: 'Application server unreachable' });
    });
    proxyReq.end();
});


// ============================================================
// START FIREWALL SERVER (async to await DB init)
// ============================================================

async function startServer() {
    // Wait for database to be ready before starting
    await db.initDatabase();
    const aiMode = process.env.OPENAI_API_KEY ? 'OPENAI' : 'FALLBACK';
    db.logAudit('AI-NGFW server started');
    db.logAudit('Database initialized');
    db.logAudit(`AI Engine: ${aiMode} (LLM-only pipeline)`);

    app.listen(PORT, '0.0.0.0', () => {
        console.log('');
        console.log('╔══════════════════════════════════════════════════════╗');
        console.log('║     AI-NGFW SECURITY COMMAND CENTER                  ║');
        console.log('║     LLM-Powered Security • Zero Trust Decisioning    ║');
        console.log('╠══════════════════════════════════════════════════════╣');
        console.log(`║  Firewall Server:  http://0.0.0.0:${PORT}                ║`);
        console.log(`║  Dashboard:        http://localhost:${PORT}/dashboard     ║`);
        console.log(`║  App Server:       http://127.0.0.1:5000             ║`);
        console.log(`║  AI Engine:        ${aiMode.padEnd(37)}║`);
        console.log('╠══════════════════════════════════════════════════════╣');
        console.log('║  Pipeline: Blocked IP → Rate Limit → AI Engine → Logger → Proxy');
        console.log('╚══════════════════════════════════════════════════════╝');
        console.log('');

        db.logAudit('AI-NGFW listening on port ' + PORT);
    });
}

startServer().catch(err => {
    console.error('[FATAL] Failed to start firewall server:', err);
    process.exit(1);
});
