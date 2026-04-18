/**
 * ============================================================
 * LLM THREAT DETECTION ENGINE - llmThreatAnalyzer.js
 * ============================================================
 *
 * AI-assisted threat analysis for the AI-NGFW pipeline.
 *
 * Modes:
 *   OPENAI  – Uses OpenAI GPT when OPENAI_API_KEY is set.
 *   LOCAL   – Sophisticated heuristic engine that produces
 *             AI-style risk scores, classifications, and
 *             human-readable reasons.  Works out of the box.
 *
 * Only suspicious requests are deeply analysed to optimise
 * API usage and latency.
 * ============================================================
 */

// ── Try to load OpenAI (optional dependency) ────────────────
let openaiClient = null;
try {
    const OpenAI = require('openai');
    if (process.env.OPENAI_API_KEY) {
        openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
        console.log('[AI ENGINE] OpenAI API connected');
    }
} catch (_) { /* openai package not installed – using local engine */ }

const AI_MODE = openaiClient ? 'OPENAI' : 'LOCAL';
console.log(`[AI ENGINE] Mode: ${AI_MODE}`);

// ── Helpers ─────────────────────────────────────────────────

function getIP(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return fwd.split(',')[0].trim();
    const ip = req.connection?.remoteAddress || req.socket?.remoteAddress || '0.0.0.0';
    return ip.replace('::ffff:', '');
}

/**
 * Decide whether a request warrants deep analysis.
 * Keeps the AI pipeline efficient by skipping obviously-benign traffic.
 */
function isSuspicious(req) {
    const url  = (req.originalUrl || req.url || '').toLowerCase();
    const body = req.body ? JSON.stringify(req.body) : '';
    const all  = url + ' ' + body;

    if (/['";<>|`]/.test(url))                     return true;
    if (url.includes('=') && /%[0-9a-f]{2}/i.test(url)) return true;
    if (url.includes('/login'))                     return true;
    if (req.method === 'POST' && body.length > 2)  return true;
    if (url.length > 200)                           return true;
    if (/(\.\.\/)|(etc\/passwd)|(cmd|exec)/i.test(url)) return true;
    if (/(select|union|drop|insert|update|delete|script|onerror|onload)/i.test(all)) return true;

    return false;
}

function buildRequestData(req) {
    return {
        ip:          getIP(req),
        method:      req.method,
        endpoint:    req.originalUrl || req.url,
        query:       req.query  || {},
        body:        req.body   || {},
        userAgent:   req.headers['user-agent']   || '',
        contentType: req.headers['content-type'] || '',
        referer:     req.headers['referer']      || ''
    };
}

// ── OpenAI Analysis ─────────────────────────────────────────

async function analyzeWithOpenAI(data) {
    const prompt = `You are a cybersecurity AI analysing an HTTP request for threats.

Request:
- IP: ${data.ip}
- Method: ${data.method}
- Endpoint: ${data.endpoint}
- Query: ${JSON.stringify(data.query)}
- Body: ${JSON.stringify(data.body)}
- User-Agent: ${data.userAgent}
- Referer: ${data.referer}

Respond ONLY with JSON (no markdown):
{
  "threat": true/false,
  "attack_type": "SQL_INJECTION"|"XSS"|"COMMAND_INJECTION"|"RECONNAISSANCE"|"Normal",
  "severity": "low"|"medium"|"high",
  "risk_score": 0.0-1.0,
  "reason": "short explanation"
}`;

    try {
        const res = await openaiClient.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.1,
            max_tokens: 200
        });
        const raw = res.choices[0].message.content.trim()
            .replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
        return JSON.parse(raw);
    } catch (err) {
        console.error('[AI ENGINE] OpenAI call failed, falling back to local:', err.message);
        return analyzeLocally(data);
    }
}

// ── Local Heuristic Engine ──────────────────────────────────

const PATTERNS = {
    SQL_INJECTION: [
        { re: /('|%27)\s*(or|and)\s+\d+\s*=\s*\d+/i,          w: 0.92, msg: 'Boolean-based SQL injection pattern detected' },
        { re: /union\s+(all\s+)?select/i,                       w: 0.95, msg: 'UNION-based SQL injection attempt identified' },
        { re: /(drop|delete|truncate)\s+(table|database)/i,     w: 0.95, msg: 'Destructive SQL statement detected in payload' },
        { re: /('|%27)\s*(--|#|\/\*)/i,                         w: 0.85, msg: 'SQL comment-based injection vector detected' },
        { re: /(;|%3b)\s*(drop|delete|insert|update|alter|create|exec)/i, w: 0.88, msg: 'Stacked SQL query injection attempt' },
        { re: /waitfor\s+delay/i,                               w: 0.90, msg: 'Time-based blind SQL injection detected' },
        { re: /('|"|;)\s*(select|insert|update|delete)/i,       w: 0.80, msg: 'Inline SQL statement injection attempt' },
        { re: /information_schema|sys\.tables|sysobjects/i,     w: 0.88, msg: 'Database schema enumeration attempt' }
    ],
    XSS: [
        { re: /<\s*script/i,                                    w: 0.92, msg: 'Script tag injection detected in request' },
        { re: /<\s*\/\s*script/i,                               w: 0.90, msg: 'Closing script tag found — potential XSS' },
        { re: /on(error|load|click|mouseover|focus)\s*=/i,      w: 0.88, msg: 'DOM event handler injection detected' },
        { re: /javascript\s*:/i,                                w: 0.87, msg: 'JavaScript URI scheme injection detected' },
        { re: /<\s*img[^>]+onerror/i,                           w: 0.85, msg: 'IMG tag XSS vector with error handler' },
        { re: /<\s*svg[^>]*onload/i,                            w: 0.88, msg: 'SVG-based XSS payload detected' },
        { re: /<\s*iframe/i,                                    w: 0.78, msg: 'IFrame injection attempt detected' },
        { re: /document\.(cookie|location|write)/i,             w: 0.85, msg: 'DOM manipulation attempt detected' }
    ],
    COMMAND_INJECTION: [
        { re: /(;|%3b)\s*(ls|cat|rm|wget|curl|bash|sh|whoami|id|pwd|echo|nc|ncat|python|perl|ruby|php)/i, w: 0.92, msg: 'Semicolon-based command injection detected' },
        { re: /(&&|%26%26)\s*(rm|cat|ls|wget|curl|bash|sh|whoami|id|pwd)/i, w: 0.92, msg: 'AND-chained command injection detected' },
        { re: /(\||%7c)\s*(cat|ls|rm|bash|sh|wget|curl|whoami|id|pwd|echo|grep)/i, w: 0.88, msg: 'Pipe-based command injection attempt' },
        { re: /`[^`]*(ls|cat|rm|wget|curl|bash|sh|id|whoami)[^`]*`/i, w: 0.90, msg: 'Backtick command execution detected' },
        { re: /\.\.\/(\.\.\/){1,}/i,                            w: 0.75, msg: 'Path traversal attempt detected in URL' },
        { re: /\/(etc|proc|sys)\/(passwd|shadow|hosts)/i,       w: 0.92, msg: 'Sensitive system file access attempt' }
    ]
};

function analyzeLocally(data) {
    const payload = [
        decodeURIComponent((data.endpoint || '').replace(/\+/g, ' ')),
        JSON.stringify(data.query),
        JSON.stringify(data.body),
        data.userAgent,
        data.referer
    ].join(' ');

    let bestScore  = 0;
    let bestType   = 'Normal';
    let bestReason = '';

    for (const [type, rules] of Object.entries(PATTERNS)) {
        for (const rule of rules) {
            if (rule.re.test(payload) && rule.w > bestScore) {
                bestScore  = rule.w;
                bestType   = type;
                bestReason = rule.msg;
            }
        }
    }

    // Additional heuristic signals
    const suspChars   = (payload.match(/['";<>|`\\{}]/g) || []).length;
    const encodedHits = (payload.match(/%[0-9a-f]{2}/gi)  || []).length;

    if (suspChars > 5 && bestScore < 0.6) {
        bestScore  = Math.max(bestScore, Math.min(0.3 + suspChars * 0.04, 0.65));
        bestReason = bestReason || 'Elevated density of suspicious characters in payload';
    }
    if (encodedHits > 6 && bestScore < 0.5) {
        bestScore  = Math.max(bestScore, 0.45);
        bestReason = bestReason || 'Heavy percent-encoding detected — possible evasion';
    }

    // Severity mapping
    let severity = 'low';
    if (bestScore >= 0.8) severity = 'high';
    else if (bestScore >= 0.5) severity = 'medium';

    if (!bestReason) bestReason = 'Request classified as benign by AI heuristic engine';

    return {
        threat:      bestScore >= 0.5,
        attack_type: bestType,
        severity,
        risk_score:  Math.round(bestScore * 100) / 100,
        reason:      bestReason
    };
}

// ── Public API ──────────────────────────────────────────────

async function analyzeRequest(req) {
    if (!isSuspicious(req)) {
        return {
            threat:      false,
            attack_type: 'Normal',
            severity:    'low',
            risk_score:  0.05,
            reason:      'Request classified as benign — no suspicious indicators'
        };
    }

    const data = buildRequestData(req);

    if (openaiClient) {
        return analyzeWithOpenAI(data);
    }
    return analyzeLocally(data);
}

function getEngineMode() { return AI_MODE; }

module.exports = { analyzeRequest, isSuspicious, getEngineMode };
