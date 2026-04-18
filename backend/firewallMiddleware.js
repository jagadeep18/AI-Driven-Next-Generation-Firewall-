/**
 * ============================================================
 * FIREWALL MIDDLEWARE - firewallMiddleware.js
 * ============================================================
 *
 * LLM-only AI NGFW pipeline. No regex, no rule engine — the LLM is the brain.
 *
 * Pipeline (in order):
 *   1. checkBlockedIP     – Reject blocked IPs
 *   2. rateLimiter        – Enforce per-IP rate limits
 *   3. aiSecurityEngine   – OpenAI classifies request (allow / suspicious / block)
 *   4. trafficLogger      – Log request with AI decision and metrics
 *   5. (Proxy to app – in firewallServer.js)
 *
 * ============================================================
 */

const db               = require('./database');
const aiSecurityEngine = require('./aiSecurityEngine');

const rateLimitStore       = new Map();
const RATE_LIMIT_MAX       = 100;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

const AUTOBLOCK_EXEMPT = new Set(['127.0.0.1', '::1', '0.0.0.0', 'localhost']);
function canAutoBlock(ip) { return !AUTOBLOCK_EXEMPT.has(ip); }

function skipRoute(req) {
    const ep = req.originalUrl || req.url;
    return ep.startsWith('/dashboard')    ||
           ep === '/api/traffic-logs'     ||
           ep === '/api/intrusion-logs'   ||
           ep === '/api/audit-logs'       ||
           ep === '/api/stats'             ||
           ep === '/api/blocked-ips'       ||
           ep.startsWith('/api/ai-')      ||
           ep.startsWith('/api/risk-')    ||
           ep.startsWith('/api/top-')     ||
           ep.startsWith('/api/threat-intel');
}

function getClientIP(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return fwd.split(',')[0].trim();
    const ip = req.connection?.remoteAddress || req.socket?.remoteAddress || '0.0.0.0';
    return ip.replace('::ffff:', '');
}

// Allow localhost to list/unblock when blocked (so you can test and recover)
const UNBLOCK_BYPASS_IPS = new Set(['127.0.0.1', '::1']);
function canBypassBlockForUnblock(req, ip) {
    if (!UNBLOCK_BYPASS_IPS.has(ip)) return false;
    const path = (req.originalUrl || req.url || '').split('?')[0];
    if (req.method === 'GET' && path === '/api/blocked-ips') return true;
    if (req.method === 'DELETE' && /^\/api\/blocked-ips\/\d+$/.test(path)) return true;
    return false;
}

const BLOCKED_PAGE_HTML = (clientIp) => `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Access blocked</title>
<style>body{font-family:system-ui;max-width:420px;margin:3rem auto;padding:1.5rem;background:#0f1419;color:#e6edf3;}
h1{font-size:1.25rem;margin-bottom:0.5rem;}
p{color:#8b949e;margin-bottom:1rem;}
button{background:#58a6ff;color:#fff;border:none;padding:0.6rem 1.2rem;font-size:1rem;border-radius:6px;cursor:pointer;}
button:hover{opacity:0.9;}
#msg{margin-top:1rem;font-size:0.9rem;}</style></head>
<body>
<h1>Your IP is blocked</h1>
<p>IP <code>${clientIp}</code> has been blocked by the firewall. You cannot access the dashboard or the app until unblocked.</p>
<button type="button" id="unblockBtn">Unblock my IP</button>
<div id="msg"></div>
<script>
document.getElementById('unblockBtn').onclick = async function() {
  this.disabled = true;
  document.getElementById('msg').textContent = 'Unblocking...';
  try {
    const r = await fetch('/api/blocked-ips', { credentials: 'same-origin' });
    const d = await r.json();
    if (!d.success || !d.data) { document.getElementById('msg').textContent = 'Failed to load list'; this.disabled = false; return; }
    const me = d.data.find(function(x) { return x.ip === '127.0.0.1' || x.ip === '::1'; });
    if (!me) { document.getElementById('msg').textContent = 'Your IP not in list'; this.disabled = false; return; }
    const del = await fetch('/api/blocked-ips/' + me.id, { method: 'DELETE', credentials: 'same-origin' });
    const d2 = await del.json();
    if (d2.success) { document.getElementById('msg').textContent = 'Unblocked. Redirecting...'; window.location.href = '/dashboard'; }
    else { document.getElementById('msg').textContent = 'Unblock failed'; this.disabled = false; }
  } catch (e) { document.getElementById('msg').textContent = 'Error: ' + e.message; this.disabled = false; }
};
</script>
</body></html>`;

// ============================================================
// 1. BLOCKED IP CHECK
// ============================================================

function checkBlockedIP(req, res, next) {
    const ip = getClientIP(req);
    if (db.isIPBlocked(ip)) {
        if (canBypassBlockForUnblock(req, ip)) return next();
        console.log(`[AI-NGFW] BLOCKED IP: ${ip}`);
        db.logTraffic(ip, req.method, req.originalUrl || req.url, 'BLOCK', 0, '', '', '', 'block');
        const accept = (req.headers.accept || '');
        if (accept.includes('text/html')) {
            return res.status(403).set('Content-Type', 'text/html').send(BLOCKED_PAGE_HTML(ip));
        }
        return res.status(403).json({
            error:   'Forbidden',
            message: 'Your IP address has been blocked by the AI-NGFW.',
            ip
        });
    }
    next();
}

// ============================================================
// 2a. ACCESS POLICY – BLOCK RESTRICTED PATHS (e.g. /admin)
// ============================================================

const RESTRICTED_PATHS = ['/admin'];
function blockRestrictedPaths(req, res, next) {
    const path = (req.originalUrl || req.url || '').split('?')[0];
    if (!RESTRICTED_PATHS.some(p => path === p || path.startsWith(p + '/'))) return next();
    const ip = getClientIP(req);
    console.log(`[AI-NGFW] ACCESS POLICY: ${ip} blocked for ${path}`);
    db.logTraffic(ip, req.method, req.originalUrl || req.url, 'BLOCK', 0, '', '', 'Access policy: restricted path', 'block');
    db.logAudit(`Access policy: ${ip} blocked for ${path}`);
    return res.status(403).json({
        error:   'Forbidden',
        message: 'Access to this resource is not allowed by policy.',
        path
    });
}

// ============================================================
// 2. RATE LIMITER
// ============================================================

function rateLimiter(req, res, next) {
    const ip  = getClientIP(req);
    const now = Date.now();

    let entry = rateLimitStore.get(ip);
    if (!entry || (now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
        entry = { count: 1, windowStart: now };
        rateLimitStore.set(ip, entry);
    } else {
        entry.count++;
    }

    req.rateCount = entry.count;

    if (entry.count > RATE_LIMIT_MAX) {
        console.log(`[AI-NGFW] RATE LIMIT: ${ip} (${entry.count} req/min)`);
        db.logTraffic(ip, req.method, req.originalUrl || req.url, 'BLOCK', 0, '', '', 'Rate limit exceeded', 'block');
        db.logAudit(`Rate limit exceeded: ${ip} (${entry.count} req/min)`);

        if (entry.count > RATE_LIMIT_MAX + 50 && canAutoBlock(ip)) {
            db.blockIP(ip, 'Rate limit exceeded — automated block');
            db.logAudit(`Automated Response: IP ${ip} auto-blocked for rate limit violations`);
        }
        return res.status(429).json({
            error:       'Too Many Requests',
            message:     `Rate limit exceeded. Max ${RATE_LIMIT_MAX} requests/min.`,
            retryAfter:  Math.ceil((RATE_LIMIT_WINDOW_MS - (now - entry.windowStart)) / 1000)
        });
    }
    next();
}

// ============================================================
// 3. AI SECURITY ENGINE (LLM) + DECISION
// ============================================================

async function aiSecurityEngineMiddleware(req, res, next) {
    if (skipRoute(req)) return next();

    const ip       = getClientIP(req);
    const endpoint = req.originalUrl || req.url;

    try {
        const result = await aiSecurityEngine.analyzeRequest(req);
        req.aiDecision = result;
    } catch (err) {
        console.error('[AI-NGFW] AI engine error:', err.message);
        req.aiDecision = {
            decision:    'allow',
            attack_type: 'normal',
            risk_score:  0,
            severity:    'low',
            reason:      `Engine error: ${err.message} — fail-open`
        };
    }

    const d = req.aiDecision;

    if (d.decision === 'block') {
        console.log(`[AI-NGFW] BLOCK: ${ip} → ${endpoint} | ${d.attack_type} (risk ${d.risk_score})`);
        db.logIntrusion(ip, d.attack_type, endpoint, (d.severity || 'high').toUpperCase());
        db.logTraffic(ip, req.method, endpoint, 'BLOCK', d.risk_score, d.attack_type, d.severity, d.reason, 'block');
        db.logAudit(`AI Security Engine blocked: ${ip} → ${endpoint} (${d.attack_type}, risk ${d.risk_score})`);

        if (d.severity === 'high' && canAutoBlock(ip) && !db.isIPBlocked(ip)) {
            db.blockIP(ip, `AI auto-blocked: ${d.attack_type} (risk ${d.risk_score})`);
            db.logAudit(`Automated Response: ${ip} auto-blocked by AI decision`);
        }

        return res.status(403).json({
            error:       'Forbidden',
            message:     'Request blocked by AI Security Engine.',
            attack_type: d.attack_type,
            severity:    d.severity,
            risk_score:  d.risk_score,
            reason:      d.reason
        });
    }

    if (d.decision === 'suspicious') {
        console.log(`[AI-NGFW] SUSPICIOUS: ${ip} → ${endpoint} (risk ${d.risk_score})`);
        db.logAudit(`AI flagged suspicious: ${ip} → ${endpoint} (${d.attack_type}, risk ${d.risk_score})`);
    }

    next();
}

// ============================================================
// 4. TRAFFIC LOGGER
// ============================================================

function trafficLogger(req, res, next) {
    if (skipRoute(req)) return next();

    const ip       = getClientIP(req);
    const endpoint = req.originalUrl || req.url;
    const d        = req.aiDecision || {};

    console.log(`[AI-NGFW] ALLOWED: ${ip} → ${req.method} ${endpoint} (risk ${d.risk_score || 0})`);
    db.logTraffic(
        ip,
        req.method,
        endpoint,
        'ALLOW',
        d.risk_score ?? 0,
        d.attack_type ?? 'normal',
        d.severity ?? 'low',
        d.reason ?? '',
        d.decision ?? 'allow'
    );

    next();
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of rateLimitStore.entries()) {
        if ((now - entry.windowStart) > RATE_LIMIT_WINDOW_MS * 2) {
            rateLimitStore.delete(ip);
        }
    }
}, RATE_LIMIT_WINDOW_MS);

module.exports = {
    checkBlockedIP,
    blockRestrictedPaths,
    rateLimiter,
    aiSecurityEngineMiddleware,
    trafficLogger
};
