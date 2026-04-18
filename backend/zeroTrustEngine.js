/**
 * ============================================================
 * ZERO TRUST RISK ENGINE - zeroTrustEngine.js
 * ============================================================
 *
 * Implements risk-based access evaluation aligned with Zero
 * Trust Network Architecture principles.
 *
 * Combines multiple signals into a composite risk score:
 *   1. AI / LLM threat analysis score
 *   2. Threat intelligence reputation
 *   3. Request rate behaviour
 *   4. Endpoint sensitivity
 *   5. Login attempt frequency
 *
 * Decision thresholds:
 *   risk < 0.40  →  ALLOW
 *   0.40 – 0.75  →  SUSPICIOUS (logged, request allowed)
 *   risk > 0.75  →  BLOCK
 * ============================================================
 */

const threatIntel = require('./threatIntel');

const DECISION = Object.freeze({
    ALLOW:      'ALLOW',
    SUSPICIOUS: 'SUSPICIOUS',
    BLOCK:      'BLOCK'
});

// ── Login-attempt tracker (per IP, 5 min window) ────────────
const loginTracker = new Map();

function trackLogin(ip) {
    const now = Date.now();
    let attempts = loginTracker.get(ip) || [];
    attempts = attempts.filter(t => now - t < 300_000);
    attempts.push(now);
    loginTracker.set(ip, attempts);
    return attempts.length;
}

function getLoginAttempts(ip) {
    const now = Date.now();
    return (loginTracker.get(ip) || []).filter(t => now - t < 300_000).length;
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, arr] of loginTracker.entries()) {
        const valid = arr.filter(t => now - t < 300_000);
        if (valid.length === 0) loginTracker.delete(ip);
        else loginTracker.set(ip, valid);
    }
}, 60_000);

// ── Helpers ─────────────────────────────────────────────────

function getIP(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return fwd.split(',')[0].trim();
    const ip = req.connection?.remoteAddress || req.socket?.remoteAddress || '0.0.0.0';
    return ip.replace('::ffff:', '');
}

// ── Signal weights ──────────────────────────────────────────
const WEIGHTS = {
    ai:       0.40,
    intel:    0.25,
    rate:     0.15,
    endpoint: 0.10,
    login:    0.10
};

// ── Core evaluation ─────────────────────────────────────────

/**
 * @param {Object} req         Express request (+ req.threatIntel set by middleware)
 * @param {Object} aiResult    Output from llmThreatAnalyzer.analyzeRequest()
 * @param {number} rateCount   Current request count for this IP from rate limiter
 * @returns {{ risk_score, decision, factors, ai_result }}
 */
function evaluateRisk(req, aiResult, rateCount = 0) {
    const ip       = getIP(req);
    const endpoint = req.originalUrl || req.url || '';
    const factors  = [];

    // ── Factor 1: AI / LLM risk score ───────────────────────
    const aiRisk = aiResult ? aiResult.risk_score : 0;
    factors.push({
        factor: 'AI Threat Analysis',
        score:  aiRisk,
        detail: aiResult?.reason || 'No analysis performed'
    });

    // ── Factor 2: Threat intelligence reputation ────────────
    const intelResult = req.threatIntel || threatIntel.checkIP(ip);
    const intelRisk   = intelResult.reputation_score || 0;
    if (intelResult.malicious) {
        factors.push({
            factor: 'Threat Intelligence',
            score:  intelRisk,
            detail: `Known threat: ${intelResult.categories.join(', ')}`
        });
    }

    // ── Factor 3: Request rate ──────────────────────────────
    let rateRisk = 0;
    if      (rateCount > 80) rateRisk = 0.5;
    else if (rateCount > 50) rateRisk = 0.3;
    else if (rateCount > 30) rateRisk = 0.1;
    if (rateRisk > 0) {
        factors.push({
            factor: 'Request Rate',
            score:  rateRisk,
            detail: `${rateCount} requests in current window`
        });
    }

    // ── Factor 4: Endpoint sensitivity ──────────────────────
    let endpointRisk = 0;
    if      (endpoint.includes('/admin'))  endpointRisk = 0.4;
    else if (endpoint.includes('/login'))  endpointRisk = 0.15;
    else if (endpoint.includes('/api/'))   endpointRisk = 0.05;
    if (endpointRisk > 0.1) {
        factors.push({
            factor: 'Endpoint Sensitivity',
            score:  endpointRisk,
            detail: `Sensitive endpoint: ${endpoint}`
        });
    }

    // ── Factor 5: Login frequency ───────────────────────────
    let loginRisk = 0;
    if (endpoint.includes('/login')) {
        const count = trackLogin(ip);
        if      (count > 10) loginRisk = 0.6;
        else if (count > 5)  loginRisk = 0.3;
        else if (count > 3)  loginRisk = 0.1;
        if (loginRisk > 0) {
            factors.push({
                factor: 'Login Frequency',
                score:  loginRisk,
                detail: `${count} login attempts in last 5 min`
            });
        }
    }

    // ── Weighted composite ──────────────────────────────────
    const loginFactor = factors.find(f => f.factor === 'Login Frequency');
    const composite   = Math.min(1.0,
        aiRisk       * WEIGHTS.ai       +
        intelRisk    * WEIGHTS.intel     +
        rateRisk     * WEIGHTS.rate      +
        endpointRisk * WEIGHTS.endpoint  +
        (loginFactor ? loginFactor.score : 0) * WEIGHTS.login
    );

    // ── Decision ────────────────────────────────────────────
    let decision;
    if      (composite > 0.75) decision = DECISION.BLOCK;
    else if (composite > 0.40) decision = DECISION.SUSPICIOUS;
    else                       decision = DECISION.ALLOW;

    // Override: AI flagged a high-severity threat explicitly
    if (aiResult?.threat && aiResult?.severity === 'high' && decision !== DECISION.BLOCK) {
        decision = DECISION.BLOCK;
        factors.push({ factor: 'Override', score: 1.0, detail: 'AI detected high-severity threat — forced block' });
    }

    return {
        risk_score: Math.round(composite * 100) / 100,
        decision,
        factors,
        ai_result: aiResult
    };
}

module.exports = { evaluateRisk, DECISION, getLoginAttempts };
