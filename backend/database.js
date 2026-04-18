/**
 * ============================================================
 * DATABASE MODULE - database.js
 * ============================================================
 *
 * SQLite database operations for the AI-NGFW system.
 * Uses sql.js (pure JavaScript SQLite).
 *
 * Tables:
 *   - traffic_logs:   HTTP request logs with AI risk data
 *   - intrusion_logs: Detected intrusion attempts
 *   - audit_logs:     Administrative / system actions
 *   - blocked_ips:    Blocked IP addresses
 *
 * Database file: database/logs.db
 * ============================================================
 */

const initSqlJs = require('sql.js');
const fs   = require('fs');
const path = require('path');

const DB_DIR  = path.join(__dirname, '..', 'database');
const DB_PATH = path.join(DB_DIR, 'logs.db');

let db = null;
const SAVE_INTERVAL_MS = 3000;

// ── Initialisation ──────────────────────────────────────────

async function initDatabase() {
    if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

    const SQL = await initSqlJs();

    if (fs.existsSync(DB_PATH)) {
        const buf = fs.readFileSync(DB_PATH);
        db = new SQL.Database(buf);
        console.log('[DATABASE] Loaded existing database from:', DB_PATH);
    } else {
        db = new SQL.Database();
        console.log('[DATABASE] Created new database');
    }

    // ── traffic_logs (includes AI-NGFW columns) ─────────────
    db.run(`
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            method      TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            action      TEXT NOT NULL,
            risk_score  REAL DEFAULT 0,
            attack_type TEXT DEFAULT '',
            severity    TEXT DEFAULT '',
            ai_reason   TEXT DEFAULT '',
            ai_decision TEXT DEFAULT '',
            timestamp   TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    `);

    // Migration for existing databases that lack AI columns
    const migrations = [
        "ALTER TABLE traffic_logs ADD COLUMN risk_score  REAL DEFAULT 0",
        "ALTER TABLE traffic_logs ADD COLUMN attack_type TEXT DEFAULT ''",
        "ALTER TABLE traffic_logs ADD COLUMN severity    TEXT DEFAULT ''",
        "ALTER TABLE traffic_logs ADD COLUMN ai_reason   TEXT DEFAULT ''",
        "ALTER TABLE traffic_logs ADD COLUMN ai_decision TEXT DEFAULT ''"
    ];
    for (const sql of migrations) {
        try { db.run(sql); } catch (_) { /* column already exists */ }
    }

    // ── intrusion_logs ──────────────────────────────────────
    db.run(`
        CREATE TABLE IF NOT EXISTS intrusion_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'HIGH',
            timestamp   TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    `);

    // ── audit_logs ──────────────────────────────────────────
    db.run(`
        CREATE TABLE IF NOT EXISTS audit_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            action    TEXT NOT NULL,
            timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    `);

    // ── blocked_ips ─────────────────────────────────────────
    db.run(`
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT NOT NULL,
            reason    TEXT NOT NULL,
            timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    `);

    saveDatabase();
    setInterval(saveDatabase, SAVE_INTERVAL_MS);

    console.log('[DATABASE] SQLite database initialised at:', DB_PATH);
    return db;
}

function saveDatabase() {
    if (!db) return;
    try {
        const data = db.export();
        fs.writeFileSync(DB_PATH, Buffer.from(data));
    } catch (err) {
        console.error('[DATABASE] Save error:', err.message);
    }
}

// ── Query helpers ───────────────────────────────────────────

function queryAll(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
}

function queryOne(sql, params = []) {
    const rows = queryAll(sql, params);
    return rows.length > 0 ? rows[0] : null;
}

function execute(sql, params = []) {
    db.run(sql, params);
    saveDatabase();
}

// ============================================================
// TRAFFIC LOG OPERATIONS
// ============================================================

function logTraffic(ip, method, endpoint, action, riskScore = 0, attackType = '', severity = '', aiReason = '', aiDecision = '') {
    execute(
        `INSERT INTO traffic_logs (ip, method, endpoint, action, risk_score, attack_type, severity, ai_reason, ai_decision)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [ip, method, endpoint, action, riskScore, attackType, severity, aiReason, aiDecision]
    );
}

function getTrafficLogs(limit = 200) {
    return queryAll('SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?', [limit]);
}

// ============================================================
// INTRUSION LOG OPERATIONS
// ============================================================

function logIntrusion(ip, attackType, endpoint, severity = 'HIGH') {
    execute(
        'INSERT INTO intrusion_logs (ip, attack_type, endpoint, severity) VALUES (?, ?, ?, ?)',
        [ip, attackType, endpoint, severity]
    );
}

function getIntrusionLogs(limit = 200) {
    return queryAll('SELECT * FROM intrusion_logs ORDER BY id DESC LIMIT ?', [limit]);
}

// ============================================================
// AUDIT LOG OPERATIONS
// ============================================================

function logAudit(action) {
    execute('INSERT INTO audit_logs (action) VALUES (?)', [action]);
}

function getAuditLogs(limit = 200) {
    return queryAll('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?', [limit]);
}

// ============================================================
// BLOCKED IP OPERATIONS
// ============================================================

function blockIP(ip, reason) {
    execute('INSERT INTO blocked_ips (ip, reason) VALUES (?, ?)', [ip, reason]);
}

function isIPBlocked(ip) {
    return queryOne('SELECT id FROM blocked_ips WHERE ip = ? LIMIT 1', [ip]) !== null;
}

function getBlockedIPs() {
    return queryAll('SELECT * FROM blocked_ips ORDER BY id DESC');
}

function unblockIP(ipOrId) {
    if (!isNaN(ipOrId)) {
        execute('DELETE FROM blocked_ips WHERE id = ?', [ipOrId]);
    } else {
        execute('DELETE FROM blocked_ips WHERE ip = ?', [ipOrId]);
    }
}

// ============================================================
// STATISTICS  (enhanced for AI-NGFW)
// ============================================================

function getStats() {
    const totalRequests    = queryOne('SELECT COUNT(*) as count FROM traffic_logs').count;
    const blockedRequests  = queryOne("SELECT COUNT(*) as count FROM traffic_logs WHERE action = 'BLOCK'").count;
    const intrusionAttempts= queryOne('SELECT COUNT(*) as count FROM intrusion_logs').count;
    const blockedIPs       = queryOne('SELECT COUNT(*) as count FROM blocked_ips').count;
    const aiThreats        = queryOne("SELECT COUNT(*) as count FROM traffic_logs WHERE risk_score > 0.5").count;
    const avgRow           = queryOne("SELECT COALESCE(AVG(risk_score),0) as avg FROM traffic_logs WHERE risk_score > 0");

    let aiBlocked = blockedRequests;
    try {
        const row = queryOne("SELECT COUNT(*) as count FROM traffic_logs WHERE action = 'BLOCK'");
        if (row) aiBlocked = row.count;
    } catch (_) {}

    return {
        totalRequests,
        blockedRequests,
        intrusionAttempts,
        blockedIPs,
        aiThreatsDetected: aiThreats  || 0,
        avgRiskScore:      Math.round((avgRow?.avg || 0) * 100) / 100,
        aiBlockedRequests: aiBlocked
    };
}

// ============================================================
// AI-NGFW QUERIES
// ============================================================

function getAIThreatLogs(limit = 200) {
    return queryAll(
        `SELECT * FROM traffic_logs
         WHERE risk_score > 0.3 OR (attack_type != '' AND attack_type != 'Normal')
         ORDER BY id DESC LIMIT ?`,
        [limit]
    );
}

function getRiskMetrics() {
    const avgRow   = queryOne("SELECT COALESCE(AVG(risk_score),0) as v FROM traffic_logs WHERE risk_score > 0") || { v: 0 };
    const maxRow   = queryOne("SELECT COALESCE(MAX(risk_score),0) as v FROM traffic_logs")                      || { v: 0 };
    const aiCount  = queryOne("SELECT COUNT(*) as v FROM traffic_logs WHERE risk_score > 0.5")                  || { v: 0 };
    const intelRow = queryOne("SELECT COUNT(*) as v FROM audit_logs WHERE action LIKE '%Threat Intel%'")        || { v: 0 };

    const riskTimeline = queryAll(
        "SELECT risk_score, timestamp FROM traffic_logs WHERE risk_score > 0 ORDER BY id DESC LIMIT 30"
    );

    const attackTypeDistribution = queryAll(
        `SELECT attack_type, COUNT(*) as count
         FROM traffic_logs
         WHERE attack_type != '' AND attack_type != 'Normal'
         GROUP BY attack_type ORDER BY count DESC`
    );

    return {
        avgRiskScore:            Math.round((avgRow.v  || 0) * 100) / 100,
        maxRiskScore:            maxRow.v  || 0,
        aiThreatsDetected:       aiCount.v || 0,
        threatIntelHits:         intelRow.v|| 0,
        riskTimeline,
        attackTypeDistribution
    };
}

function getTopAttackers(limit = 10) {
    return queryAll(
        `SELECT ip,
                COUNT(*)                                        AS total_requests,
                SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END) AS blocked_count,
                ROUND(AVG(risk_score),2)                        AS avg_risk,
                ROUND(MAX(risk_score),2)                        AS max_risk
         FROM traffic_logs
         WHERE risk_score > 0.2
         GROUP BY ip
         ORDER BY avg_risk DESC, blocked_count DESC
         LIMIT ?`,
        [limit]
    );
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
    initDatabase,
    saveDatabase,
    logTraffic,
    getTrafficLogs,
    logIntrusion,
    getIntrusionLogs,
    logAudit,
    getAuditLogs,
    blockIP,
    isIPBlocked,
    getBlockedIPs,
    unblockIP,
    getStats,
    getAIThreatLogs,
    getRiskMetrics,
    getTopAttackers
};
