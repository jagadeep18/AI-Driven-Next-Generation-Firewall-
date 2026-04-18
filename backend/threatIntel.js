/**
 * ============================================================
 * THREAT INTELLIGENCE MODULE - threatIntel.js
 * ============================================================
 *
 * Loads and queries threat intelligence data (malicious IPs,
 * domains, Tor exit nodes, known scanners) from a local JSON
 * feed.  Provides reputation scoring for the Zero Trust engine.
 * ============================================================
 */

const fs   = require('fs');
const path = require('path');

const THREAT_DATA_PATH = path.join(__dirname, 'threatIntel.json');

let threatData = {
    malicious_ips:    [],
    malicious_domains:[],
    tor_exit_nodes:   [],
    known_scanners:   [],
    threat_feeds:     []
};

function loadThreatData() {
    try {
        const raw = fs.readFileSync(THREAT_DATA_PATH, 'utf-8');
        threatData = JSON.parse(raw);
        console.log(`[THREAT INTEL] Loaded ${threatData.malicious_ips.length} malicious IPs, ${threatData.malicious_domains.length} domains`);
    } catch (err) {
        console.error('[THREAT INTEL] Failed to load threat data:', err.message);
    }
}

/**
 * Check an IP address against all threat intelligence lists.
 * Returns a reputation object with a score from 0 (clean) to 1 (malicious).
 */
function checkIP(ip) {
    const isMalicious = threatData.malicious_ips.includes(ip);
    const isTorExit   = (threatData.tor_exit_nodes  || []).includes(ip);
    const isScanner   = (threatData.known_scanners   || []).includes(ip);

    let reputation_score = 0;
    const categories = [];

    if (isMalicious) { reputation_score += 0.5; categories.push('malicious_ip'); }
    if (isTorExit)   { reputation_score += 0.3; categories.push('tor_exit_node'); }
    if (isScanner)   { reputation_score += 0.2; categories.push('known_scanner'); }

    return {
        malicious: categories.length > 0,
        categories,
        reputation_score: Math.min(reputation_score, 1.0),
        ip
    };
}

function checkDomain(domain) {
    if (!domain) return { malicious: false, domain, reputation_score: 0 };
    const hit = threatData.malicious_domains.includes(domain.toLowerCase());
    return { malicious: hit, domain, reputation_score: hit ? 0.8 : 0 };
}

function getThreatStats() {
    return {
        totalMaliciousIPs:    threatData.malicious_ips.length,
        totalMaliciousDomains:threatData.malicious_domains.length,
        totalTorExitNodes:    (threatData.tor_exit_nodes || []).length,
        totalKnownScanners:   (threatData.known_scanners || []).length,
        feeds:                threatData.threat_feeds || []
    };
}

function getThreatData() { return threatData; }

// Auto-load on import
loadThreatData();

module.exports = { checkIP, checkDomain, getThreatStats, getThreatData, loadThreatData };
