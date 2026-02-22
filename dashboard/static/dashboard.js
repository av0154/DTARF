// =========================================================
// DTARF Dashboard - Frontend JavaScript
// =========================================================

const API_BASE = '';
let authToken = null;
let refreshInterval = null;

// =========== Authentication ===========

async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const btn = document.getElementById('login-btn');

    btn.textContent = 'Signing in...';
    btn.disabled = true;

    try {
        const resp = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await resp.json();

        if (resp.ok && data.token) {
            authToken = data.token;
            localStorage.setItem('dtarf_token', data.token);
            localStorage.setItem('dtarf_user', data.username);
            document.getElementById('user-name').textContent = data.username;
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('app').classList.remove('hidden');
            startDashboard();
        } else {
            alert(data.error || 'Login failed');
        }
    } catch (err) {
        alert('Connection error. Is the DTARF server running?');
    }

    btn.textContent = 'Sign In';
    btn.disabled = false;
}

function handleLogout() {
    authToken = null;
    localStorage.removeItem('dtarf_token');
    localStorage.removeItem('dtarf_user');
    if (refreshInterval) clearInterval(refreshInterval);
    document.getElementById('app').classList.add('hidden');
    document.getElementById('login-screen').classList.remove('hidden');
}

// =========== API Helper ===========

async function api(endpoint, method = 'GET', body = null) {
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
    };

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    try {
        const resp = await fetch(`${API_BASE}${endpoint}`, opts);
        if (resp.status === 401) {
            handleLogout();
            return null;
        }
        return await resp.json();
    } catch (err) {
        console.error(`API error: ${endpoint}`, err);
        return null;
    }
}

// =========== Page Navigation ===========

function switchPage(page) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    // Show selected page
    const pageEl = document.getElementById(`page-${page}`);
    if (pageEl) pageEl.classList.add('active');

    const navEl = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (navEl) navEl.classList.add('active');

    // Update header
    const titles = {
        'overview': ['Overview', 'Real-time security monitoring'],
        'alerts': ['Alerts', 'All security alerts and incidents'],
        'detection': ['Detection Engine', 'Entropy, anomaly & sliding-window analysis'],
        'threat-intel': ['Threat Intelligence', 'IOC correlation & feed management'],
        'response': ['Response Orchestration', 'Automated response actions & playbooks'],
        'forensics': ['Forensic Evidence', 'Chain of custody & evidence integrity'],
        'performance': ['Performance Metrics', 'Detection accuracy & benchmarking'],
        'network': ['Network Monitor', 'Packet capture & traffic analysis']
    };

    const [title, subtitle] = titles[page] || [page, ''];
    document.getElementById('page-title').textContent = title;
    document.getElementById('page-subtitle').textContent = subtitle;

    // Load page-specific data
    loadPageData(page);
}

// =========== Data Loading ===========

async function loadPageData(page) {
    switch (page) {
        case 'overview': await loadOverview(); break;
        case 'alerts': await loadAlerts(); break;
        case 'detection': await loadDetection(); break;
        case 'threat-intel': break;
        case 'response': await loadResponse(); break;
        case 'forensics': await loadForensics(); break;
        case 'performance': await loadPerformance(); break;
        case 'network': await loadNetwork(); break;
    }
}

async function loadOverview() {
    // Telemetry
    const telemetry = await api('/api/telemetry/current');
    if (telemetry) {
        updateGauge('cpu', telemetry.cpu_percent || 0, 100);
        updateGauge('mem', telemetry.memory_percent || 0, 100);
        updateGauge('net', telemetry.network_connections || 0, 500);
        updateGauge('proc', telemetry.active_processes || 0, 500);
    }

    // Performance
    const summary = await api('/api/dashboard/summary');
    if (summary) {
        const det = summary.performance?.detection || {};
        const resp = summary.performance?.response || {};
        const dist = summary.alerts?.by_severity || {};

        document.getElementById('stat-critical').textContent = dist.CRITICAL || 0;
        document.getElementById('stat-high').textContent = dist.HIGH || 0;
        document.getElementById('stat-medium').textContent = dist.MEDIUM || 0;
        document.getElementById('perf-accuracy-val').textContent = det.accuracy_pct || '100%';
        document.getElementById('perf-mttr').textContent = `${resp.mttr_ms || 0}ms`;
        document.getElementById('perf-fpr').textContent = `${((det.false_positive_rate || 0) * 100).toFixed(1)}%`;
        document.getElementById('perf-total').textContent = det.total_detections || 0;

        const accPct = (det.accuracy || 1) * 100;
        document.getElementById('perf-accuracy').style.width = `${accPct}%`;

        // Update badge from summary
        const badge = document.getElementById('alert-badge');
        const count = summary.alerts?.unacknowledged_count || 0;
        badge.textContent = count;
        if (count > 0) {
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    }

    // Response stats
    const respStats = await api('/api/response/stats');
    if (respStats) {
        document.getElementById('stat-blocked').textContent = respStats.blacklisted_ips || 0;
    }

    // TI stats
    const ti = await api('/api/ti/stats');
    if (ti) {
        const iocDb = ti.ioc_database || {};
        document.getElementById('ti-ips').textContent = iocDb.malicious_ips || 0;
        document.getElementById('ti-domains').textContent = iocDb.malicious_domains || 0;
        document.getElementById('ti-hashes').textContent = iocDb.malicious_hashes || 0;
        document.getElementById('ti-alerts').textContent = ti.total_ti_alerts || 0;
    }

    // Recent alerts
    const alerts = await api('/api/alerts?count=10');
    if (alerts && alerts.alerts) {
        const tbody = document.getElementById('recent-alerts-body');

        if (alerts.alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No alerts detected yet — system is monitoring</td></tr>';
        } else {
            tbody.innerHTML = alerts.alerts.reverse().map(a => `
                <tr>
                    <td style="font-family:var(--font-mono);font-size:0.78rem">${formatTime(a.timestamp)}</td>
                    <td>${sevBadge(a.severity_label)}</td>
                    <td>${a.type || 'unknown'}</td>
                    <td style="font-family:var(--font-mono)">${a.src_ip || '-'}</td>
                    <td>${statusBadge(a.status)}</td>
                    <td>
                        <button class="btn-sm" onclick="viewAlertDetails('${a.id}')">View</button>
                        <button class="btn-sm" onclick="acknowledgeAlert('${a.id}')">✓</button>
                    </td>
                </tr>
            `).join('');
        }
    }
}

async function loadAlerts() {
    const status = document.getElementById('alert-filter').value;
    const url = status ? `/api/alerts?status=${status}&count=200` : '/api/alerts?count=200';
    const data = await api(url);

    if (data && data.alerts) {
        const tbody = document.getElementById('all-alerts-body');
        if (data.alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="empty-row">No alerts</td></tr>';
        } else {
            tbody.innerHTML = data.alerts.reverse().map(a => `
                <tr>
                    <td style="font-family:var(--font-mono);font-size:0.7rem">${a.id || ''}</td>
                    <td style="font-size:0.78rem">${formatTime(a.timestamp)}</td>
                    <td>${sevBadge(a.severity_label)}</td>
                    <td>${a.type}</td>
                    <td>${a.source || '-'}</td>
                    <td style="font-family:var(--font-mono)">${a.src_ip || '-'}</td>
                    <td>${statusBadge(a.status)}</td>
                    <td style="font-family:var(--font-mono)">${a.response_time_ms != null ? a.response_time_ms + 'ms' : '-'}</td>
                    <td>
                        <button class="btn-sm" onclick="viewAlertDetails('${a.id}')" title="Details">View</button>
                        <button class="btn-sm" onclick="acknowledgeAlert('${a.id}')" title="Acknowledge">✓</button>
                        <button class="btn-danger" onclick="markFP('${a.id}')" title="False Positive">FP</button>
                    </td>
                </tr>
            `).join('');
        }
    }
}

async function loadDetection() {
    const stats = await api('/api/detection/stats');
    if (stats) {
        document.getElementById('det-total').textContent = stats.total_alerts || 0;
        document.getElementById('det-baselines').textContent =
            Object.keys(stats.baselines || {}).length;
    }

    const alerts = await api('/api/detection/alerts?count=50');
    if (alerts && alerts.alerts) {
        const tbody = document.getElementById('detection-alerts-body');
        if (alerts.alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-row">No detection alerts</td></tr>';
        } else {
            tbody.innerHTML = alerts.alerts.reverse().map(a => `
                <tr>
                    <td style="font-size:0.78rem">${formatTime(a.timestamp)}</td>
                    <td>${a.type}</td>
                    <td>${sevBadge(getSevLabel(a.severity))}</td>
                    <td style="font-size:0.78rem">${JSON.stringify(a.details || a).substring(0, 100)}...</td>
                </tr>
            `).join('');
        }
    }
}

async function loadResponse() {
    const stats = await api('/api/response/stats');
    if (stats) {
        document.getElementById('resp-auto').textContent = stats.total_auto_responded || 0;
        document.getElementById('resp-blocked').textContent = stats.blacklisted_ips || 0;
        document.getElementById('resp-playbooks').textContent = stats.active_playbooks || 0;
    }

    // Blacklist
    const bl = await api('/api/response/blacklist');
    if (bl) {
        const tbody = document.getElementById('blacklist-body');
        const entries = Object.entries(bl);
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-row">No blocked IPs</td></tr>';
        } else {
            tbody.innerHTML = entries.map(([ip, info]) => `
                <tr>
                    <td style="font-family:var(--font-mono)">${ip}</td>
                    <td>${info.reason || '-'}</td>
                    <td style="font-size:0.78rem">${formatTime(info.blocked_at)}</td>
                    <td><button class="btn-danger" onclick="unblockIP('${ip}')">Unblock</button></td>
                </tr>
            `).join('');
        }
    }

    // Action log
    const actionLog = await api('/api/response/action-log?count=50');
    if (actionLog && actionLog.actions) {
        const tbody = document.getElementById('action-log-body');
        if (actionLog.actions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-row">No actions recorded</td></tr>';
        } else {
            tbody.innerHTML = actionLog.actions.reverse().map(a => `
                <tr>
                    <td style="font-size:0.78rem">${formatTime(a.timestamp)}</td>
                    <td>${a.action || '-'}</td>
                    <td>${statusBadge(a.status)}</td>
                    <td style="font-size:0.75rem">${a.ip || a.reason || ''}</td>
                </tr>
            `).join('');
        }
    }
}

async function loadForensics() {
    const stats = await api('/api/forensics/stats');
    if (stats) {
        document.getElementById('for-entries').textContent = stats.total_entries || 0;
        document.getElementById('for-algo').textContent = (stats.hash_algorithm || 'sha256').toUpperCase();
    }

    const ledger = await api('/api/forensics/ledger?count=50');
    if (ledger && ledger.entries) {
        const tbody = document.getElementById('ledger-body');
        if (ledger.entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No evidence recorded</td></tr>';
        } else {
            tbody.innerHTML = ledger.entries.reverse().map(e => `
                <tr>
                    <td style="font-family:var(--font-mono);font-size:0.7rem">${e.entry_id}</td>
                    <td style="font-size:0.75rem">${e.alert_id}</td>
                    <td>${e.evidence_type}</td>
                    <td style="font-family:var(--font-mono);font-size:0.7rem" title="${e.hash_value}">${(e.hash_value || '').substring(0, 16)}...</td>
                    <td>${statusBadge(e.status)}</td>
                    <td><button class="btn-sm" onclick="verifyEvidence('${e.entry_id}')">Verify</button></td>
                </tr>
            `).join('');
        }
    }
}

async function loadPerformance() {
    const perf = await api('/api/performance/metrics');
    if (perf) {
        const det = perf.detection || {};
        const resp = perf.response || {};
        document.getElementById('pf-accuracy').textContent = det.accuracy_pct || '100%';
        document.getElementById('pf-mttr').textContent = `${resp.mttr_ms || 0}ms`;
        document.getElementById('pf-fpr').textContent = `${((det.false_positive_rate || 0) * 100).toFixed(1)}%`;
    }

    const comparison = await api('/api/performance/comparison');
    if (comparison && comparison.metrics) {
        const tbody = document.getElementById('comparison-body');
        const m = comparison.metrics;
        tbody.innerHTML = `
            <tr><td>Detection Accuracy</td><td>${m.detection_accuracy?.dtarf || '-'}</td>
                <td>${m.detection_accuracy?.multi_layered_sem || '-'}</td>
                <td>${m.detection_accuracy?.elk_siem || '-'}</td>
                <td>${m.detection_accuracy?.snort_nids || '-'}</td></tr>
            <tr><td>MTTR (ms)</td><td>${m.mttr_ms?.dtarf || '-'}</td>
                <td>${m.mttr_ms?.multi_layered_sem || '-'}</td>
                <td>${m.mttr_ms?.elk_siem || '-'}</td>
                <td>${m.mttr_ms?.snort_nids || '-'}</td></tr>
            <tr><td>False Positive Rate</td><td>${m.false_positive_rate?.dtarf || '-'}</td>
                <td>${m.false_positive_rate?.multi_layered_sem || '-'}</td>
                <td>${m.false_positive_rate?.elk_siem || '-'}</td>
                <td>${m.false_positive_rate?.snort_nids || '-'}</td></tr>
            <tr><td>Forensic Readiness</td><td>${m.forensic_readiness?.dtarf || '-'}</td>
                <td>${m.forensic_readiness?.multi_layered_sem || '-'}</td>
                <td>${m.forensic_readiness?.elk_siem || '-'}</td>
                <td>${m.forensic_readiness?.snort_nids || '-'}</td></tr>
            <tr><td>Threat Intelligence</td><td>${m.threat_intelligence?.dtarf || '-'}</td>
                <td>${m.threat_intelligence?.multi_layered_sem || '-'}</td>
                <td>${m.threat_intelligence?.elk_siem || '-'}</td>
                <td>${m.threat_intelligence?.snort_nids || '-'}</td></tr>
            <tr><td>Response Automation</td><td>${m.response_automation?.dtarf || '-'}</td>
                <td>${m.response_automation?.multi_layered_sem || '-'}</td>
                <td>${m.response_automation?.elk_siem || '-'}</td>
                <td>${m.response_automation?.snort_nids || '-'}</td></tr>
        `;
    }
}

async function loadNetwork() {
    const data = await api('/api/network/stats');
    if (data) {
        const ss = data.sniffer_stats || {};
        const ws = data.window_stats || {};
        document.getElementById('net-packets').textContent = ss.total_captured || 0;
        document.getElementById('net-pps').textContent = Math.round(ws.packets_per_sec || 0);
        document.getElementById('net-sources').textContent = ws.unique_sources || 0;

        // Protocol distribution
        const dist = ws.protocol_distribution || {};
        const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
        const container = document.getElementById('protocol-bars');

        if (Object.keys(dist).length === 0) {
            container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:2rem">No traffic captured yet</p>';
        } else {
            container.innerHTML = Object.entries(dist)
                .sort((a, b) => b[1] - a[1])
                .map(([proto, count]) => {
                    const pct = (count / total * 100).toFixed(1);
                    const cls = `proto-${proto.toLowerCase()}`;
                    return `
                        <div class="proto-row">
                            <span class="proto-name">${proto}</span>
                            <div class="proto-bar-track">
                                <div class="proto-bar-fill ${cls}" style="width:${pct}%">${count}</div>
                            </div>
                            <span style="font-family:var(--font-mono);font-size:0.8rem;min-width:45px;text-align:right">${pct}%</span>
                        </div>
                    `;
                }).join('');
        }
    }
}

// =========== Actions ===========

async function viewAlertDetails(alertId) {
    const data = await api(`/api/alerts/${alertId}`);
    if (!data) return;

    const content = document.getElementById('alert-detail-content');
    const modal = document.getElementById('alert-detail-modal');
    const ackBtn = document.getElementById('modal-ack-btn');
    const forensicBtn = document.getElementById('modal-forensic-btn');

    content.innerHTML = `
        <div class="detail-section">
            <h4>Basic Information</h4>
            <div class="stats-grid">
                <div class="ti-item">
                    <span class="ti-label">Alert ID</span>
                    <span class="ti-count" style="font-size:0.9rem">${data.id}</span>
                </div>
                <div class="ti-item">
                    <span class="ti-label">Priority</span>
                    <span>${sevBadge(data.severity_label)}</span>
                </div>
                <div class="ti-item">
                    <span class="ti-label">Status</span>
                    <span>${statusBadge(data.status)}</span>
                </div>
            </div>
        </div>
        <div class="detail-section">
            <h4>Metadata</h4>
            <table class="alert-table">
                <tr><td>Source</td><td>${data.source || 'Engine'}</td></tr>
                <tr><td>Source IP</td><td>${data.src_ip || '-'}</td></tr>
                <tr><td>Type</td><td>${data.type}</td></tr>
                <tr><td>Timestamp</td><td>${formatTime(data.timestamp)}</td></tr>
            </table>
        </div>
        <div class="detail-section">
            <h4>Raw Details</h4>
            <pre class="detail-json">${JSON.stringify(data.details || data, null, 2)}</pre>
        </div>
    `;

    ackBtn.onclick = async () => {
        await acknowledgeAlert(alertId);
        closeModal('alert-detail-modal');
    };

    forensicBtn.onclick = () => showForensicReport(alertId);

    modal.classList.remove('hidden');
}

async function showForensicReport(alertId) {
    const report = await api(`/api/forensics/report/${alertId}`, 'POST');
    if (!report) {
        alert("No forensic evidence found for this alert.");
        return;
    }

    const content = document.getElementById('forensic-report-content');
    const modal = document.getElementById('forensic-report-modal');

    let chainHtml = report.evidence_chain.map(e => `
        <div class="ti-item" style="margin-bottom:1rem; flex-direction:column; align-items:flex-start">
            <div style="display:flex; justify-content:space-between; width:100%">
                <strong>${e.entry_id}</strong>
                <span class="sev-badge ${e.integrity_status === 'INTACT' ? 'sev-low' : 'sev-critical'}">${e.integrity_status}</span>
            </div>
            <div style="font-size:0.8rem; color:var(--text-muted); margin:0.3rem 0">Path: ${e.evidence_path}</div>
            <div style="font-size:0.75rem; font-family:var(--font-mono); background:var(--bg-input); padding:0.4rem; border-radius:4px; width:100%">${e.hash_value}</div>
        </div>
    `).join('');

    let timelineHtml = report.timeline.map(t => `
        <div style="padding-left:1rem; border-left:2px solid var(--accent); margin-bottom:0.8rem">
            <div style="font-size:0.7rem; color:var(--text-muted)">${formatTime(t.timestamp)}</div>
            <div style="font-weight:600">${t.action}</div>
            <div style="font-size:0.8rem">${t.notes}</div>
        </div>
    `).join('');

    content.innerHTML = `
        <div class="detail-section">
            <h4>Report Overview</h4>
            <div class="stats-grid">
                <div class="ti-item"><span class="ti-label">Report ID</span><span class="ti-count">${report.report_id}</span></div>
                <div class="ti-item"><span class="ti-label">Integrity</span><span>${report.integrity_summary.all_intact ? '✅ VERIFIED' : '❌ COMPROMISED'}</span></div>
                <div class="ti-item"><span class="ti-label">Evidence Items</span><span class="ti-count">${report.evidence_count}</span></div>
            </div>
        </div>
        <div class="detail-section">
            <h4>Chain of Custody</h4>
            ${chainHtml || '<p>No evidence entries found in chain.</p>'}
        </div>
        <div class="detail-section">
            <h4>Investigation Timeline</h4>
            <div style="margin-top:1rem">${timelineHtml || '<p>No timeline events recorded.</p>'}</div>
        </div>
        <div class="detail-section">
            <h4>Compliance</h4>
            <div style="display:flex; gap:0.5rem">
                ${report.compliance.map(c => `<span class="sev-badge sev-info">${c}</span>`).join('')}
            </div>
        </div>
    `;

    modal.classList.remove('hidden');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.add('hidden');
}

async function acknowledgeAlert(alertId) {
    await api(`/api/alerts/${alertId}/acknowledge`, 'POST');
    loadOverview();
}

async function markFP(alertId) {
    await api(`/api/alerts/${alertId}/false-positive`, 'POST');
    loadAlerts();
}

async function unblockIP(ip) {
    if (confirm(`Unblock ${ip}?`)) {
        await api(`/api/response/blacklist/${ip}`, 'DELETE');
        loadResponse();
    }
}

async function performLookup() {
    const type = document.getElementById('lookup-type').value;
    const value = document.getElementById('lookup-value').value.trim();
    if (!value) return;

    const resultDiv = document.getElementById('lookup-result');
    resultDiv.classList.remove('hidden');
    resultDiv.textContent = 'Looking up...';

    const endpoint = type === 'ip' ? '/api/ti/check-ip' : '/api/ti/check-domain';
    const body = type === 'ip' ? { ip: value } : { domain: value };
    const data = await api(endpoint, 'POST', body);

    if (data) {
        resultDiv.textContent = JSON.stringify(data, null, 2);
    } else {
        resultDiv.textContent = 'Lookup failed';
    }
}

async function addIOC() {
    const type = document.getElementById('ioc-type').value;
    const indicator = document.getElementById('ioc-value').value.trim();
    const desc = document.getElementById('ioc-desc').value.trim();
    if (!indicator) return;

    const data = await api('/api/ti/ioc', 'POST', {
        type, indicator,
        metadata: { description: desc, source: 'manual', confidence: 90 }
    });

    if (data) {
        alert('IOC added successfully');
        document.getElementById('ioc-value').value = '';
        document.getElementById('ioc-desc').value = '';
    }
}

async function verifyEvidence(entryId) {
    const data = await api(`/api/forensics/verify/${entryId}`, 'POST');
    if (data) {
        const status = data.integrity === 'INTACT' ? '✅ INTACT' : '❌ ' + data.integrity;
        alert(`Evidence Verification:\n\nEntry: ${entryId}\nIntegrity: ${status}\nHash Match: ${data.hash_match}`);
    }
}

async function verifyLedger() {
    const result = await api('/api/forensics/verify-ledger', 'POST');
    const div = document.getElementById('ledger-verify-result');
    div.classList.remove('hidden');

    if (result) {
        if (result.chain_intact) {
            div.className = 'verify-success';
            div.innerHTML = `✅ Ledger chain is INTACT — ${result.total_entries} entries verified. No tampering detected.`;
        } else {
            div.className = 'verify-fail';
            div.innerHTML = `❌ Ledger chain BROKEN — ${result.broken_links?.length || 0} broken links detected! Possible tampering.`;
        }
    }
}

// =========== Helpers ===========

function updateGauge(id, value, max) {
    const ring = document.getElementById(`${id}-ring`);
    const label = document.getElementById(`${id}-value`);
    const circumference = 2 * Math.PI * 42; // r=42
    const pct = Math.min(value / max, 1);
    const offset = circumference * (1 - pct);
    ring.style.strokeDashoffset = offset;

    if (id === 'cpu' || id === 'mem') {
        label.textContent = `${Math.round(value)}%`;
    } else {
        label.textContent = Math.round(value);
    }
}

function sevBadge(label) {
    const cls = (label || 'info').toLowerCase();
    return `<span class="sev-badge sev-${cls}">${label || 'INFO'}</span>`;
}

function statusBadge(status) {
    return `<span class="status-badge status-${status || 'new'}">${status || 'new'}</span>`;
}

function getSevLabel(sev) {
    if (sev >= 90) return 'CRITICAL';
    if (sev >= 70) return 'HIGH';
    if (sev >= 40) return 'MEDIUM';
    if (sev >= 10) return 'LOW';
    return 'INFO';
}

function formatTime(ts) {
    if (!ts) return '-';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('en-US', { hour12: false }) + ' ' +
            d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
        return ts;
    }
}

// =========== Dashboard Lifecycle ===========

async function updateGlobalBadge() {
    const summary = await api('/api/dashboard/summary');
    if (summary && summary.alerts) {
        const badge = document.getElementById('alert-badge');
        const count = summary.alerts.unacknowledged_count || 0;
        badge.textContent = count;

        if (count > 0) {
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }

        // Visual indicator if new alert arrived
        if (count > parseInt(badge.dataset.lastCount || 0)) {
            badge.style.transform = 'scale(1.2)';
            setTimeout(() => badge.style.transform = 'scale(1)', 500);
        }
        badge.dataset.lastCount = count;
    }
}

function startDashboard() {
    loadOverview();
    updateGlobalBadge();

    // Update clock
    setInterval(() => {
        const now = new Date();
        document.getElementById('header-time').textContent =
            now.toLocaleTimeString('en-US', { hour12: false }) + ' — ' +
            now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    }, 1000);

    // Auto-refresh active page every 2 seconds for LIVE feel
    refreshInterval = setInterval(() => {
        const activePage = document.querySelector('.page.active');
        if (activePage) {
            const pageId = activePage.id.replace('page-', '');
            loadPageData(pageId);
        }
        updateGlobalBadge();
    }, 2000);
}

// =========== Auto-login check ===========
(function () {
    const savedToken = localStorage.getItem('dtarf_token');
    const savedUser = localStorage.getItem('dtarf_user');
    if (savedToken) {
        authToken = savedToken;
        document.getElementById('user-name').textContent = savedUser || 'admin';
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('app').classList.remove('hidden');
        startDashboard();
    }
})();
