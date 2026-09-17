/**
 * Main Application Navigation & 12-Screen Controller (SecurePaper)
 */

document.addEventListener('DOMContentLoaded', () => {
  // Bind form handlers
  document.getElementById('loginForm')?.addEventListener('submit', handleLogin);
  document.getElementById('otpForm')?.addEventListener('submit', handleVerifyOTP);
  document.getElementById('uploadPaperForm')?.addEventListener('submit', handleUploadPaper);

  // Default data fetch & navigation
  refreshAllData();
});

function navigateToScreen(screenId) {
  // Update sidebar active links
  document.querySelectorAll('.sidebar-link').forEach(link => {
    link.classList.toggle('active', link.dataset.screen === screenId);
  });

  // Update top nav active links
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('active', link.getAttribute('onclick')?.includes(screenId));
  });

  // Update active screen view
  document.querySelectorAll('.screen-view').forEach(view => {
    view.classList.toggle('active', view.id === `screen-${screenId}`);
  });

  refreshAllData();
}

async function refreshAllData() {
  await fetchPapers();
  await fetchAuditLogs();
}

let allPapers = [];

async function fetchPapers() {
  try {
    const res = await fetch('/api/papers');
    const data = await res.json();
    allPapers = data.papers || [];

    // Update Dashboard Metrics (Screens 4 & 8)
    const totalCount = allPapers.length;
    const pendingCount = allPapers.filter(p => p.status === 'PENDING_APPROVAL').length;
    const approvedCount = allPapers.filter(p => p.status === 'APPROVED_LOCKED' || p.status === 'RELEASED').length;

    if (document.getElementById('setTotalVal')) document.getElementById('setTotalVal').innerText = totalCount;
    if (document.getElementById('setPendingVal')) document.getElementById('setPendingVal').innerText = pendingCount;
    if (document.getElementById('setApprovedVal')) document.getElementById('setApprovedVal').innerText = approvedCount;

    if (document.getElementById('adminTotalPapersVal')) document.getElementById('adminTotalPapersVal').innerText = totalCount;
    if (document.getElementById('adminPendingVal')) document.getElementById('adminPendingVal').innerText = pendingCount;
    if (document.getElementById('adminApprovedVal')) document.getElementById('adminApprovedVal').innerText = approvedCount;

    renderSetterView();
    renderReviewerView();
    renderExamCenterView();
  } catch (err) {
    console.error('Error fetching papers:', err);
  }
}

/* --- Screen 4: Setter Dashboard View --- */
function renderSetterView() {
  const container = document.getElementById('setterPapersTableBody');
  if (!container) return;

  if (allPapers.length === 0) {
    container.innerHTML = `<tr><td colspan="5" style="color:var(--text-muted); text-align:center;">No question papers uploaded yet.</td></tr>`;
    return;
  }

  container.innerHTML = allPapers.map(p => `
    <tr>
      <td><strong>${p.title}</strong></td>
      <td><span class="paper-code">${p.paper_code}</span></td>
      <td>${new Date(p.created_at).toLocaleDateString()}</td>
      <td><span class="badge badge-${p.status === 'APPROVED_LOCKED' ? 'approved' : p.status.toLowerCase()}">${p.status}</span></td>
      <td><div class="hash-preview">SHA-256: ${p.sha256_hash.substring(0, 20)}...</div></td>
    </tr>
  `).join('');
}

/* --- Screen 5: Upload Paper Handler --- */
async function handleUploadPaper(e) {
  e.preventDefault();
  const alertBox = document.getElementById('uploadAlert');
  alertBox.style.display = 'none';

  const code = document.getElementById('upCode').value.trim();
  const title = document.getElementById('upTitle').value.trim();
  const subject = document.getElementById('upSubject').value.trim();
  const releaseTime = document.getElementById('upReleaseTime').value;
  const content = document.getElementById('upContent').value;

  if (!code || !title || !subject || !releaseTime || !content) {
    showAlert(alertBox, 'Please complete all required fields.');
    return;
  }

  try {
    const res = await fetch('/api/papers/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        paper_code: code,
        title: title,
        subject: subject,
        scheduled_release_time: new Date(releaseTime).toISOString(),
        content: content
      })
    });

    const data = await res.json();
    if (!res.ok) {
      showAlert(alertBox, data.detail || 'Upload failed.');
      return;
    }

    alert(`✅ Paper Encrypted with AES-256 and stored in Secure Vault!\nSHA-256 Fingerprint: ${data.sha256_fingerprint.substring(0, 24)}...`);
    document.getElementById('uploadPaperForm').reset();
    navigateToScreen('setter_dash');

  } catch (err) {
    showAlert(alertBox, 'Error: ' + err.message);
  }
}

/* --- Screen 6 & 7: Reviewer / Approver View --- */
function renderReviewerView() {
  const container = document.getElementById('reviewerTableBody');
  if (!container) return;

  if (allPapers.length === 0) {
    container.innerHTML = `<tr><td colspan="6" style="color:var(--text-muted); text-align:center;">No question papers available for review.</td></tr>`;
    return;
  }

  container.innerHTML = allPapers.map(p => `
    <tr>
      <td><strong>${p.title}</strong></td>
      <td><span class="paper-code">${p.paper_code}</span></td>
      <td>${p.setter_username}</td>
      <td><span class="badge badge-${p.status === 'APPROVED_LOCKED' ? 'approved' : p.status.toLowerCase()}">${p.status}</span></td>
      <td><div class="hash-preview">SHA-256: ${p.sha256_hash.substring(0, 16)}...</div></td>
      <td>
        ${p.status === 'PENDING_APPROVAL' ? `
          <button onclick="approvePaper(${p.id}, 'APPROVE')" class="btn btn-success btn-sm">🔒 Approve & Lock</button>
          <button onclick="approvePaper(${p.id}, 'REJECT')" class="btn btn-danger btn-sm">Reject</button>
        ` : `
          <button onclick="overrideReleaseTime('${p.paper_code}')" class="btn btn-secondary btn-sm" title="Fast Forward Lock for Demo">⚡ Override Schedule (Demo)</button>
        `}
      </td>
    </tr>
  `).join('');
}

async function approvePaper(paperId, action) {
  try {
    const res = await fetch('/api/papers/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paper_id: paperId, action: action })
    });
    const data = await res.json();
    if (res.ok) {
      alert(`Success: ${data.message}`);
      refreshAllData();
    } else {
      alert(`Error: ${data.detail}`);
    }
  } catch (err) {
    alert('Network error: ' + err.message);
  }
}

async function overrideReleaseTime(paperCode) {
  try {
    const res = await fetch('/api/papers/override-time', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paper_code: paperCode, new_release_time: 'NOW' })
    });
    const data = await res.json();
    if (res.ok) {
      alert(`⚡ Demo Override Applied: Paper ${paperCode} schedule updated to NOW! Exam Center can now unlock it.`);
      refreshAllData();
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

/* --- Screen 10: Exam Center Dashboard --- */
function renderExamCenterView() {
  const container = document.getElementById('examCenterTableBody');
  if (!container) return;

  const approvedPapers = allPapers.filter(p => p.status === 'APPROVED_LOCKED' || p.status === 'RELEASED');

  if (approvedPapers.length === 0) {
    container.innerHTML = `<tr><td colspan="5" style="color:var(--text-muted); text-align:center;">No approved question papers scheduled for release.</td></tr>`;
    return;
  }

  container.innerHTML = approvedPapers.map((p, idx) => {
    const timerId = `timer_clock_${idx}`;
    return `
      <tr>
        <td><strong>${p.title}</strong></td>
        <td><span class="paper-code">${p.paper_code}</span></td>
        <td>
          <div style="font-size:0.8rem; font-weight:600;">${new Date(p.scheduled_release_time).toLocaleString()}</div>
          <div id="${timerId}" style="font-family:var(--font-mono); font-size:0.78rem; color:var(--amber); font-weight:700;">Calculating...</div>
        </td>
        <td><span class="badge badge-${p.status === 'APPROVED_LOCKED' ? 'locked' : 'approved'}">${p.status}</span></td>
        <td>
          <button onclick="requestDecryption('${p.paper_code}')" class="btn btn-primary btn-sm">
            🔓 Request Decryption
          </button>
          <button onclick="overrideReleaseTime('${p.paper_code}')" class="btn btn-secondary btn-sm">
            ⚡ Override to NOW (Demo)
          </button>
        </td>
      </tr>
    `;
  }).join('');

  // Start countdown timers
  approvedPapers.forEach((p, idx) => {
    startCountdown(`timer_clock_${idx}`, p.scheduled_release_time, () => {
      console.log(`Paper ${p.paper_code} unlocked!`);
    });
  });
}

async function requestDecryption(paperCode) {
  const alertBox = document.getElementById('decryptionAlert');
  if (alertBox) alertBox.style.display = 'none';

  try {
    const res = await fetch('/api/papers/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paper_code: paperCode })
    });
    const data = await res.json();

    if (!res.ok) {
      if (alertBox) showAlert(alertBox, `⛔ SECURITY BLOCK (403 Forbidden): ${data.detail}`);
      alert(`⛔ SECURITY BLOCK:\n\n${data.detail}\n\nActivity has been logged to Security Audit Monitor.`);
      refreshAllData();
      return;
    }

    // Success! Show Canvas Reader
    document.getElementById('readerSection').style.display = 'block';
    renderWatermarkedDocument(
      'watermarkCanvas',
      data.title,
      data.paper_code,
      data.content,
      data.watermark_data
    );

    // Scroll smoothly to reader
    document.getElementById('readerSection').scrollIntoView({ behavior: 'smooth' });
    refreshAllData();

  } catch (err) {
    alert('Decryption Error: ' + err.message);
  }
}

/* --- Screen 8 & 11: Activity Logs (Admin & Recent) --- */
async function fetchAuditLogs() {
  try {
    const res = await fetch('/api/audit-logs');
    const data = await res.json();
    
    renderAuditLogs(data.logs || []);
    renderAnomalies(data.anomalies || []);
  } catch (err) {
    console.error('Error fetching audit logs:', err);
  }
}

function renderAuditLogs(logs) {
  const container = document.getElementById('auditLogTableBody');
  const recentContainer = document.getElementById('adminRecentActivityBody');

  if (container) {
    container.innerHTML = logs.map(l => `
      <tr>
        <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-light);">${new Date(l.timestamp).toLocaleString()}</td>
        <td><strong>${l.username}</strong></td>
        <td><span class="badge badge-pending" style="font-size:0.62rem; padding:0.1rem 0.35rem;">${l.role}</span></td>
        <td style="font-weight:600;">${l.action}</td>
        <td><span class="badge badge-approved" style="font-size:0.62rem;">${l.status_code}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${l.ip_address}</td>
        <td style="font-size:0.78rem; color:var(--text-muted);">${l.details}</td>
      </tr>
    `).join('');
  }

  if (recentContainer) {
    recentContainer.innerHTML = logs.slice(0, 5).map(l => `
      <tr>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${new Date(l.timestamp).toLocaleTimeString()}</td>
        <td><strong>${l.username}</strong></td>
        <td>${l.action}</td>
        <td><span class="badge badge-approved" style="font-size:0.62rem;">${l.status_code}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${l.ip_address}</td>
      </tr>
    `).join('');
  }
}

function renderAnomalies(anomalies) {
  const container = document.getElementById('anomalyAlertsContainer');
  const adminAlertsVal = document.getElementById('adminAlertsVal');

  if (adminAlertsVal) adminAlertsVal.innerText = anomalies.length;

  if (!container) return;

  if (anomalies.length === 0) {
    container.innerHTML = `
      <div style="background:var(--emerald-bg); border:1px solid var(--emerald-border); border-radius:var(--radius-md); padding:0.85rem; display:flex; align-items:center; gap:0.5rem;">
        <span style="font-size:1.1rem;">✅</span>
        <span style="color:var(--emerald); font-size:0.85rem; font-weight:600;">Zero active security threat alerts or unauthorized early access attempts detected.</span>
      </div>
    `;
    return;
  }

  container.innerHTML = anomalies.map(a => `
    <div style="background:var(--rose-bg); border:1px solid var(--rose-border); border-radius:var(--radius-md); padding:0.85rem; margin-bottom:0.75rem;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span class="badge badge-rejected">🚨 THREAT ANOMALY DETECTED</span>
        <span style="font-size:0.75rem; color:var(--text-muted);">${new Date(a.timestamp).toLocaleString()}</span>
      </div>
      <p style="font-size:0.85rem; font-weight:600; margin-top:0.3rem;">Action: ${a.action} (User: ${a.username})</p>
      <p style="font-size:0.8rem; color:var(--text-muted);">${a.details}</p>
    </div>
  `).join('');
}

async function triggerBackup() {
  try {
    const res = await fetch('/api/backup/create', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      alert(`✅ Encrypted Backup Created Successfully!\nBackup File: ${data.backup_name}\nChecksum SHA-256: ${data.sha256_checksum}`);
      refreshAllData();
    }
  } catch (err) {
    alert('Backup Error: ' + err.message);
  }
}


