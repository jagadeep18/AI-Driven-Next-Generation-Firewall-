/**
 * ============================================================
 * APPLICATION SERVER - appServer.js
 * ============================================================
 * 
 * This is the protected application server running on PORT 5000.
 * It sits behind the firewall and serves the actual application.
 * 
 * In a production scenario, this server would NOT be directly
 * accessible from the internet. All traffic should pass through
 * the firewall on port 3000 first.
 * 
 * Endpoints:
 *   GET  /          - Health check / welcome message
 *   GET  /api/data  - Sample JSON data endpoint
 *   POST /login     - Login endpoint (accepts username/password)
 *   GET  /admin     - Restricted admin endpoint
 * 
 * ============================================================
 */

const express = require('express');
const app = express();
const PORT = 5000;

// ── Parse request bodies ────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// ============================================================
// ENDPOINT: GET /
// ============================================================
/**
 * Root endpoint - Returns a simple status message.
 * Used to verify the application server is running.
 */
app.get('/', (req, res) => {
    res.json({
        message: 'Application Server Running',
        status: 'OK',
        timestamp: new Date().toISOString(),
        endpoints: [
            'GET  /          - This message',
            'GET  /api/data  - Sample data',
            'POST /login     - Login endpoint',
            'GET  /admin     - Admin panel (restricted)'
        ]
    });
});


// ============================================================
// ENDPOINT: GET /api/data
// ============================================================
/**
 * Sample data endpoint - Returns mock JSON data.
 * Simulates a typical API data response.
 */
app.get('/api/data', (req, res) => {
    res.json({
        success: true,
        data: {
            users: [
                { id: 1, name: 'Alice Johnson', role: 'admin', department: 'Security' },
                { id: 2, name: 'Bob Smith', role: 'analyst', department: 'Operations' },
                { id: 3, name: 'Charlie Brown', role: 'viewer', department: 'IT Support' }
            ],
            serverInfo: {
                hostname: 'app-server-01',
                uptime: process.uptime().toFixed(2) + ' seconds',
                nodeVersion: process.version,
                platform: process.platform
            },
            timestamp: new Date().toISOString()
        }
    });
});


// ============================================================
// ENDPOINT: POST /login
// ============================================================
/**
 * Login endpoint - Accepts username and password.
 * This is a simulation; it does NOT perform real authentication.
 * Used to test how the firewall handles POST requests and
 * detects SQL injection attempts in login forms.
 */
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    console.log(`[APP] Login attempt: username="${username}"`);

    // Simulated authentication (always succeeds for demo)
    if (username && password) {
        res.json({
            success: true,
            message: 'Login successful (simulated)',
            user: {
                username: username,
                role: 'user',
                token: 'sim-token-' + Date.now()
            }
        });
    } else {
        res.status(400).json({
            success: false,
            message: 'Username and password are required'
        });
    }
});

/**
 * Also handle GET /login for query-string based SQL injection testing
 */
app.get('/login', (req, res) => {
    const { user, username } = req.query;
    
    console.log(`[APP] Login page accessed via GET, params:`, req.query);

    res.json({
        success: true,
        message: 'Login page - Use POST method with username and password',
        hint: 'Send POST request with JSON body: { "username": "...", "password": "..." }'
    });
});


// ============================================================
// ENDPOINT: GET /admin
// ============================================================
/**
 * Admin endpoint - Simulates a restricted admin panel.
 * The firewall should block access to this endpoint.
 * If a request reaches here, it means the firewall was bypassed.
 */
app.get('/admin', (req, res) => {
    res.json({
        success: true,
        message: 'Admin Panel Access Granted',
        warning: 'If you see this, the request bypassed the firewall!',
        data: {
            systemStatus: 'operational',
            activeUsers: 42,
            serverLoad: '23%'
        }
    });
});


// ============================================================
// CATCH-ALL: Handle undefined routes
// ============================================================
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Endpoint ${req.method} ${req.originalUrl} does not exist`,
        availableEndpoints: ['GET /', 'GET /api/data', 'POST /login', 'GET /admin']
    });
});


// ============================================================
// START APPLICATION SERVER
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('┌──────────────────────────────────────────────┐');
    console.log('│          APPLICATION SERVER                   │');
    console.log('├──────────────────────────────────────────────┤');
    console.log(`│  Running on: http://0.0.0.0:${PORT}             │`);
    console.log('│  Status:     ONLINE                          │');
    console.log('├──────────────────────────────────────────────┤');
    console.log('│  Endpoints:                                  │');
    console.log('│    GET  /          - Server status            │');
    console.log('│    GET  /api/data  - Sample data              │');
    console.log('│    POST /login     - Login form               │');
    console.log('│    GET  /admin     - Admin panel (restricted) │');
    console.log('└──────────────────────────────────────────────┘');
    console.log('');
    console.log('[APP] Waiting for requests...');
});
