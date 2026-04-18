/**
 * ============================================================
 * OPENAI CLIENT - openaiClient.js
 * ============================================================
 *
 * Handles OpenAI API calls for the AI NGFW security engine.
 * Responsibilities:
 *   - Format request context into a prompt
 *   - Call OpenAI API (chat completion)
 *   - Parse JSON response into security classification
 *
 * Expected response shape:
 *   { decision, attack_type, risk_score, severity, reason }
 *
 * On API error or missing key: returns safe default (allow).
 * ============================================================
 */

let OpenAI;
let client = null;

try {
    OpenAI = require('openai');
    const rawKey = process.env.OPENAI_API_KEY;
    const apiKey = typeof rawKey === 'string' ? rawKey.trim() : '';
    if (apiKey) {
        client = new OpenAI({ apiKey });
        console.log('[OPENAI] Client initialized');
    }
} catch (_) {
    console.log('[OPENAI] Package not installed or no API key — AI engine will use fallback');
}

const DEFAULT_RESPONSE = {
    decision:    'allow',
    attack_type: 'normal',
    risk_score:  0,
    severity:    'low',
    reason:      'OpenAI not configured or request skipped'
};

// When API fails on a suspicious request, block instead of allow (fail closed)
const API_ERROR_RESPONSE = {
    decision:    'block',
    attack_type: 'anomaly',
    risk_score:  0.9,
    severity:    'high',
    reason:      'AI engine unavailable — request blocked for safety'
};

/**
 * Build the system + user prompt for the NGFW classifier.
 * @param {Object} context - Request context from aiSecurityEngine
 * @returns {{ role, content }[]} messages for chat completion
 */
function buildPrompt(context) {
    const userContent = `Analyze this HTTP request and determine if it is malicious.

Request context:
${JSON.stringify(context, null, 2)}

You are an AI Next Generation Firewall. Return JSON only, no markdown or explanation:

{
  "decision": "allow | suspicious | block",
  "attack_type": "normal | SQL injection | XSS | command injection | brute force | anomaly",
  "risk_score": 0.0 to 1.0,
  "severity": "low | medium | high",
  "reason": "short explanation"
}`;

    return [
        { role: 'system', content: 'You are an AI Next Generation Firewall analyzing HTTP traffic. Classify the request and return valid JSON only with keys: decision, attack_type, risk_score, severity, reason.' },
        { role: 'user', content: userContent }
    ];
}

/**
 * Extract JSON from model response (strip markdown code blocks if present).
 */
function parseJSON(raw) {
    if (!raw || typeof raw !== 'string') return null;
    let s = raw.trim();
    s = s.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/\s*```$/i, '');
    try {
        return JSON.parse(s);
    } catch (_) {
        return null;
    }
}

/**
 * Normalize and validate the model response.
 */
const MIN_LOW_RISK = 0.05; // Never show 0 for allowed traffic — use at least a small low risk.

function normalizeResponse(obj) {
    if (!obj || typeof obj !== 'object') return null;
    const decision = (obj.decision || 'allow').toLowerCase();
    const validDecisions = ['allow', 'suspicious', 'block'];
    const attackType = (obj.attack_type || 'normal').toLowerCase().replace(/\s+/g, ' ');
    const severity = (obj.severity || 'low').toLowerCase();
    let risk = Math.min(1, Math.max(0, Number(obj.risk_score) || 0));
    if (decision === 'allow' && risk === 0) risk = MIN_LOW_RISK;
    const reason = typeof obj.reason === 'string' ? obj.reason.trim() : 'No reason provided';

    return {
        decision:    validDecisions.includes(decision) ? decision : 'allow',
        attack_type: attackType,
        risk_score:  Math.round(risk * 100) / 100,
        severity:    ['low', 'medium', 'high'].includes(severity) ? severity : 'low',
        reason
    };
}

/**
 * Call OpenAI and return security classification.
 * @param {Object} context - Request context (ip, method, endpoint, query, headers, body, request_rate_last_minute)
 * @returns {Promise<{ decision, attack_type, risk_score, severity, reason }>}
 */
async function getSecurityClassification(context) {
    if (!client) {
        return { ...DEFAULT_RESPONSE, reason: 'OpenAI not configured' };
    }

    const messages = buildPrompt(context);

    try {
        const response = await client.chat.completions.create({
            model:      'gpt-4o-mini',
            messages,
            temperature: 0.1,
            max_tokens:  256
        });

        const raw = response.choices?.[0]?.message?.content;
        const parsed = parseJSON(raw);
        const result = normalizeResponse(parsed);

        if (result) return result;
        return { ...DEFAULT_RESPONSE, reason: 'Invalid model response' };
    } catch (err) {
        console.error('[OPENAI] API error:', err.message);
        // Fail closed: request was sent to AI (suspicious), so block on error
        return { ...API_ERROR_RESPONSE, reason: `AI unavailable: ${err.message}` };
    }
}

module.exports = { getSecurityClassification, buildPrompt };
