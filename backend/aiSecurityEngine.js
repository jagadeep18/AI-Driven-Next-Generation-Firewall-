/**
 * ============================================================
 * AI SECURITY ENGINE - aiSecurityEngine.js
 * ============================================================
 *
 * LLM-powered security analysis. The firewall trusts the AI decision.
 *
 * Responsibilities:
 *   - Collect request context (IP, method, endpoint, query, headers, body, rate)
 *   - Decide when to call OpenAI (only for suspicious-looking requests)
 *   - Send context to OpenAI via openaiClient
 *   - Return security decision to the pipeline
 *
 * Performance: Do NOT send every request to OpenAI.
 * Only send when: payload exists, login attempt, high request rate, or query params present.
 * Otherwise allow directly.
 * ============================================================
 */

const openaiClient = require('./openaiClient');

function getClientIP(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return fwd.split(',')[0].trim();
    const ip = req.connection?.remoteAddress || req.socket?.remoteAddress || '0.0.0.0';
    return ip.replace('::ffff:', '');
}

/**
 * Build request context object for the LLM.
 */
function collectContext(req) {
    const ip   = getClientIP(req);
    const rate = req.rateCount != null ? req.rateCount : 0;

    const headers = {};
    if (req.headers['user-agent']) headers['user-agent'] = req.headers['user-agent'];
    if (req.headers['referer'])    headers['referer']    = req.headers['referer'];
    if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];

    return {
        ip:   ip,
        method: req.method || 'GET',
        endpoint: req.originalUrl || req.url || '',
        query: req.query || {},
        headers,
        body: req.body || {},
        request_rate_last_minute: rate
    };
}

const RATE_THRESHOLD = 20;

/**
 * Only send to LLM when at least one of:
 * - payload exists (body not empty)
 * - login attempt (endpoint contains /login)
 * - request rate high (e.g. >= 20/min)
 * - query parameters present
 */
function shouldSendToLLM(context) {
    const hasBody   = context.body && Object.keys(context.body).length > 0;
    const hasQuery  = context.query && Object.keys(context.query).length > 0;
    const isLogin   = (context.endpoint || '').toLowerCase().includes('/login');
    const highRate  = (context.request_rate_last_minute || 0) >= RATE_THRESHOLD;

    return hasBody || hasQuery || isLogin || highRate;
}

const ALLOW_DEFAULT = {
    decision:    'allow',
    attack_type: 'normal',
    risk_score:  0.05,
    severity:    'low',
    reason:      'No suspicious indicators — allowed without LLM analysis'
};

/**
 * Analyze request and return AI security decision.
 * @param {Object} req - Express request (with rateCount set by rate limiter)
 * @returns {Promise<{ decision, attack_type, risk_score, severity, reason }>}
 */
async function analyzeRequest(req) {
    const context = collectContext(req);

    if (!shouldSendToLLM(context)) {
        return ALLOW_DEFAULT;
    }

    const result = await openaiClient.getSecurityClassification(context);
    return result;
}

module.exports = { analyzeRequest, collectContext, shouldSendToLLM };
