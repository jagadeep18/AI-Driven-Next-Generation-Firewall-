/**
 * ============================================================
 * INTRUSION DETECTION SYSTEM - intrusionDetector.js
 * ============================================================
 * 
 * This module implements regex-based intrusion detection.
 * It inspects incoming HTTP requests for common attack patterns:
 * 
 *   1. SQL Injection    – ' OR 1=1 --, UNION SELECT, DROP TABLE
 *   2. XSS (Cross-Site Scripting) – <script>, </script>, onerror=
 *   3. Command Injection – ; ls, && rm, | cat, ` backtick commands
 * 
 * How it works:
 *   - The detector scans the full request URL, query string,
 *     request body, and headers for malicious patterns.
 *   - Each pattern has a name, severity, and regex rule.
 *   - If a match is found, the request is flagged and blocked.
 * 
 * ============================================================
 */

// ============================================================
// ATTACK SIGNATURE DEFINITIONS
// ============================================================

/**
 * Each rule contains:
 *   name     - Human-readable attack name
 *   type     - Category of the attack
 *   severity - Threat level (HIGH, MEDIUM, LOW)
 *   pattern  - Regex to match the attack signature
 */
const ATTACK_SIGNATURES = [
    // ── SQL Injection Patterns ──────────────────────────────
    {
        name: "SQL Injection - OR bypass",
        type: "SQL_INJECTION",
        severity: "HIGH",
        pattern: /('|\%27|\\x27)\s*(OR|AND)\s+\d+\s*=\s*\d+/i
    },
    {
        name: "SQL Injection - UNION SELECT",
        type: "SQL_INJECTION",
        severity: "HIGH",
        pattern: /UNION\s+(ALL\s+)?SELECT/i
    },
    {
        name: "SQL Injection - DROP TABLE",
        type: "SQL_INJECTION",
        severity: "HIGH",
        pattern: /(DROP|DELETE|TRUNCATE)\s+(TABLE|DATABASE)/i
    },
    {
        name: "SQL Injection - Comment injection",
        type: "SQL_INJECTION",
        severity: "HIGH",
        pattern: /('|\%27|\\x27)\s*(--|#|\*\/)/i
    },
    {
        name: "SQL Injection - Semicolon termination",
        type: "SQL_INJECTION",
        severity: "HIGH",
        pattern: /(;|\%3b)\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC)/i
    },
    {
        name: "SQL Injection - WAITFOR DELAY",
        type: "SQL_INJECTION",
        severity: "HIGH",
        pattern: /WAITFOR\s+DELAY/i
    },

    // ── XSS (Cross-Site Scripting) Patterns ─────────────────
    {
        name: "XSS - Script tag",
        type: "XSS",
        severity: "HIGH",
        pattern: /<\s*script[^>]*>/i
    },
    {
        name: "XSS - Closing script tag",
        type: "XSS",
        severity: "HIGH",
        pattern: /<\s*\/\s*script\s*>/i
    },
    {
        name: "XSS - Event handler injection",
        type: "XSS",
        severity: "HIGH",
        pattern: /on(error|load|click|mouseover|focus)\s*=/i
    },
    {
        name: "XSS - JavaScript URI",
        type: "XSS",
        severity: "HIGH",
        pattern: /javascript\s*:/i
    },
    {
        name: "XSS - IMG tag injection",
        type: "XSS",
        severity: "MEDIUM",
        pattern: /<\s*img[^>]+src\s*=\s*['"]?\s*javascript/i
    },
    {
        name: "XSS - SVG onload",
        type: "XSS",
        severity: "HIGH",
        pattern: /<\s*svg[^>]*onload\s*=/i
    },

    // ── Command Injection Patterns ──────────────────────────
    {
        name: "Command Injection - Semicolon command",
        type: "COMMAND_INJECTION",
        severity: "HIGH",
        pattern: /(;|\%3b)\s*(ls|cat|rm|wget|curl|bash|sh|nc|ncat|python|perl|ruby|php|whoami|id|pwd|echo)/i
    },
    {
        name: "Command Injection - AND chaining",
        type: "COMMAND_INJECTION",
        severity: "HIGH",
        pattern: /(&&|\%26\%26)\s*(rm|cat|ls|wget|curl|bash|sh|nc|ncat|python|perl|whoami|id|pwd)/i
    },
    {
        name: "Command Injection - Pipe command",
        type: "COMMAND_INJECTION",
        severity: "HIGH",
        pattern: /(\||\%7c)\s*(cat|ls|rm|bash|sh|nc|ncat|wget|curl|whoami|id|pwd|echo|grep)/i
    },
    {
        name: "Command Injection - Backtick execution",
        type: "COMMAND_INJECTION",
        severity: "HIGH",
        pattern: /`[^`]*(ls|cat|rm|wget|curl|bash|sh|id|whoami)[^`]*`/i
    },
    {
        name: "Command Injection - Path traversal",
        type: "COMMAND_INJECTION",
        severity: "HIGH",
        pattern: /\.\.\/(\.\.\/){1,}/i
    },
    {
        name: "Command Injection - /etc/passwd access",
        type: "COMMAND_INJECTION",
        severity: "HIGH",
        pattern: /\/(etc|proc|sys)\/passwd/i
    }
];


// ============================================================
// INTRUSION DETECTION ENGINE
// ============================================================

/**
 * Inspects an HTTP request for attack patterns.
 * 
 * @param {Object} req - Express request object
 * @returns {Object|null} - Detection result or null if clean
 * 
 * The detector examines:
 *   1. The full URL (path + query string)
 *   2. The request body (for POST/PUT requests)
 *   3. Common headers (User-Agent, Referer, Cookie)
 * 
 * Returns:
 *   { detected: true, rule: {...}, matchedIn: "url"|"body"|"headers" }
 *   or null if no threats are found.
 */
function inspectRequest(req) {
    // ── Build the inspection payload ────────────────────────
    // Combine all parts of the request that could carry an attack
    // IMPORTANT: Properly decode URL-encoded data
    // - Replace + with spaces (URL encoding standard)
    // - Decode percent-encoded characters
    const rawUrl = req.originalUrl || req.url || '';
    const url = decodeURIComponent(rawUrl.replace(/\+/g, ' '));
    
    const body = req.body ? JSON.stringify(req.body) : '';
    const userAgent = req.headers['user-agent'] || '';
    const referer = req.headers['referer'] || '';
    const cookie = req.headers['cookie'] || '';

    // Areas to inspect, in order of priority
    const inspectionTargets = [
        { name: 'url', data: url },
        { name: 'body', data: body },
        { name: 'user-agent', data: userAgent },
        { name: 'referer', data: referer },
        { name: 'cookie', data: cookie }
    ];

    // ── Scan each target against every attack signature ─────
    for (const target of inspectionTargets) {
        if (!target.data || target.data.length === 0) continue;

        for (const rule of ATTACK_SIGNATURES) {
            if (rule.pattern.test(target.data)) {
                // ── Attack pattern detected! ────────────────
                console.log(`[IDS] ⚠ THREAT DETECTED: ${rule.name}`);
                console.log(`[IDS]   Type:     ${rule.type}`);
                console.log(`[IDS]   Severity: ${rule.severity}`);
                console.log(`[IDS]   Found in: ${target.name}`);
                console.log(`[IDS]   Data:     ${target.data.substring(0, 100)}...`);

                return {
                    detected: true,
                    rule: {
                        name: rule.name,
                        type: rule.type,
                        severity: rule.severity
                    },
                    matchedIn: target.name
                };
            }
        }
    }

    // ── No threats detected ─────────────────────────────────
    return null;
}


/**
 * Get all registered attack signatures.
 * Useful for displaying rules in the dashboard.
 */
function getSignatures() {
    return ATTACK_SIGNATURES.map(sig => ({
        name: sig.name,
        type: sig.type,
        severity: sig.severity
    }));
}


// ============================================================
// MODULE EXPORTS
// ============================================================

module.exports = {
    inspectRequest,
    getSignatures,
    ATTACK_SIGNATURES
};
