let csrfToken = '';
let currentUser = null;
let alertSocket = null;
const byId = (id) => document.getElementById(id);
const workspaceStatus = byId('workspace-status');

document.addEventListener('DOMContentLoaded', initializeWorkspace);

async function initializeWorkspace() {
  byId('refresh-button').addEventListener('click', refreshWorkspace);
  byId('logout-button').addEventListener('click', logout);
  byId('incident-form').addEventListener('submit', createIncident);
  byId('settings-form').addEventListener('submit', saveSettings);
  byId('rotate-code-button').addEventListener('click', rotateJoiningCode);
  try {
    const session = await api('/auth/me');
    if (!session.authenticated) {
      showWorkspace(false);
      return;
    }
    currentUser = session.user;
    csrfToken = session.csrf_token || '';
    byId('workspace-identity').textContent = `${currentUser.full_name} · ${currentUser.role}`;
    byId('workspace-role').textContent = currentUser.role;
    byId('logout-button').classList.remove('hidden');
    byId('workspace-login-link').classList.add('hidden');
    const overview = await api('/company/overview');
    byId('workspace-company').textContent = overview.company.name;
    byId('workspace-description').textContent = `${overview.analysis_count} saved analyses · ${overview.pending_requests} pending access requests`;
    showWorkspace(true);
    if (currentUser.role === 'ADMIN') {
      byId('admin-panel').classList.remove('hidden');
      byId('audit-panel').classList.remove('hidden');
      await Promise.all([loadUsers(), loadSettings(), loadAudit()]);
    }
    if (currentUser.role === 'VIEWER/AUDITOR') byId('incident-form').classList.add('hidden');
    connectAlerts();
    await refreshWorkspace();
  } catch (error) {
    setStatus(error.message, true);
  }
}

function showWorkspace(authenticated) {
  byId('workspace-data').classList.toggle('hidden', !authenticated);
  byId('workspace-login-link').classList.toggle('hidden', authenticated);
  if (!authenticated) {
    byId('workspace-identity').textContent = 'Guest';
    setStatus('Sign in to a company account. Pending or suspended accounts cannot access this workspace.');
  }
}

async function refreshWorkspace() {
  await Promise.all([loadAnalyses(), loadIncidents()]);
}

async function loadAnalyses() {
  const rows = await api('/analyses');
  const body = byId('company-analyses');
  body.replaceChildren();
  if (!rows.length) {
    body.append(emptyRow(5, 'No company analyses yet.'));
    return;
  }
  rows.forEach((analysis) => {
    const row = document.createElement('tr');
    appendTextCell(row, analysis.filename);
    appendTextCell(row, analysis.packet_count);
    appendTextCell(row, `${analysis.threat_score}/100 · ${analysis.severity}`);
    appendTextCell(row, analysis.status);
    const actions = document.createElement('td');
    const report = makeLink(`/analyses/${analysis.id}/report`, 'PDF');
    actions.append(report, document.createTextNode(' '));
    const verify = document.createElement('button');
    verify.className = 'text-button';
    verify.type = 'button';
    verify.textContent = 'Verify evidence';
    verify.addEventListener('click', () => verifyEvidence(analysis.id, verify));
    actions.append(verify);
    if (currentUser.role !== 'VIEWER/AUDITOR') {
      actions.append(document.createTextNode(' '), makeLink(`/analyses/${analysis.id}/evidence/download`, 'Download PCAP'));
    }
    row.append(actions);
    body.append(row);
  });
}

async function verifyEvidence(analysisId, button) {
  button.disabled = true;
  try {
    const result = await api(`/analyses/${analysisId}/evidence/verify`, {
      method: 'POST',
      headers: csrfHeaders()
    });
    setStatus(`Evidence hash ${result.hash_valid ? 'matches' : 'does not match'}; signed manifest ${result.signature_valid === null ? 'not verified' : result.signature_valid ? 'valid' : 'invalid'}.`);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function loadIncidents() {
  const incidents = await api('/incidents');
  const body = byId('incident-list');
  body.replaceChildren();
  if (!incidents.length) {
    body.append(emptyRow(4, 'No incidents have been created.'));
    return;
  }
  incidents.forEach((incident) => {
    const row = document.createElement('tr');
    appendTextCell(row, `#${incident.id} ${incident.title}`);
    appendTextCell(row, incident.status);
    appendTextCell(row, incident.severity);
    const cell = document.createElement('td');
    if (currentUser.role === 'VIEWER/AUDITOR') {
      cell.textContent = 'Read only';
    } else {
      const select = document.createElement('select');
      ['NEW', 'UNDER_INVESTIGATION', 'ESCALATED', 'RESOLVED'].forEach((value) => select.add(new Option(value.replaceAll('_', ' '), value)));
      select.value = incident.status;
      select.addEventListener('change', async () => {
        try {
          await api(`/incidents/${incident.id}`, {
            method: 'PATCH',
            headers: csrfHeaders(),
            body: JSON.stringify({ status: select.value })
          });
          setStatus(`Incident #${incident.id} updated.`);
        } catch (error) {
          setStatus(error.message, true);
          select.value = incident.status;
        }
      });
      cell.append(select);
    }
    row.append(cell);
    body.append(row);
  });
}

async function createIncident(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  const body = { title: values.title };
  if (values.analysis_id) body.analysis_id = Number(values.analysis_id);
  try {
    const created = await api('/incidents', {
      method: 'POST',
      headers: csrfHeaders(),
      body: JSON.stringify(body)
    });
    form.reset();
    setStatus(`Incident #${created.id} created.`);
    await loadIncidents();
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function loadUsers() {
  const users = await api('/company/users');
  const body = byId('company-users');
  body.replaceChildren();
  users.forEach((account) => {
    const row = document.createElement('tr');
    const identity = document.createElement('td');
    identity.textContent = `${account.full_name} · ${account.username} · ${account.email}`;
    const status = document.createElement('td');
    status.textContent = account.status;
    const roleCell = document.createElement('td');
    roleCell.textContent = account.role;
    const actions = document.createElement('td');
    if (account.status === 'PENDING') {
      const role = roleSelect(account.role);
      const approve = document.createElement('button');
      approve.className = 'text-button';
      approve.textContent = 'Approve';
      approve.addEventListener('click', () => decideRequest(account.id, role.value, 'APPROVED'));
      const reject = document.createElement('button');
      reject.className = 'text-button';
      reject.textContent = 'Reject';
      reject.addEventListener('click', () => decideRequest(account.id, null, 'REJECTED'));
      actions.append(role, approve, reject);
    } else if (account.status === 'APPROVED') {
      const role = roleSelect(account.role);
      role.addEventListener('change', async () => {
        try {
          await api(`/company/users/${account.id}/role`, {
            method: 'PATCH',
            headers: csrfHeaders(),
            body: JSON.stringify({ role: role.value })
          });
          setStatus(`Role updated for ${account.username}.`);
        } catch (error) {
          setStatus(error.message, true);
          role.value = account.role;
        }
      });
      const suspend = document.createElement('button');
      suspend.className = 'text-button';
      suspend.textContent = 'Suspend';
      suspend.addEventListener('click', () => suspendUser(account.id));
      actions.append(role, suspend);
    } else {
      actions.textContent = 'No actions';
    }
    row.append(identity, status, roleCell, actions);
    body.append(row);
  });
  if (!users.length) body.append(emptyRow(4, 'No company users.'));
}

async function decideRequest(userId, role, status) {
  try {
    await api(`/company/requests/${userId}/decision`, {
      method: 'POST',
      headers: csrfHeaders(),
      body: JSON.stringify({ status, role })
    });
    setStatus(`Access request ${status.toLowerCase()}.`);
    await loadUsers();
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function suspendUser(userId) {
  try {
    await api(`/company/users/${userId}/suspend`, {
      method: 'POST',
      headers: csrfHeaders()
    });
    setStatus('Company account suspended.');
    await loadUsers();
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function loadSettings() {
  const result = await api('/company/settings');
  byId('settings-form').elements.settings.value = JSON.stringify(result.settings, null, 2);
}

async function saveSettings(event) {
  event.preventDefault();
  let settings;
  try {
    settings = JSON.parse(event.currentTarget.elements.settings.value);
  } catch {
    setStatus('Policy must be valid JSON.', true);
    return;
  }
  try {
    const result = await api('/company/settings', {
      method: 'PUT',
      headers: csrfHeaders(),
      body: JSON.stringify(settings)
    });
    event.currentTarget.elements.settings.value = JSON.stringify(result.settings, null, 2);
    setStatus(`Detection policy saved as version ${result.version}.`);
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function rotateJoiningCode() {
  try {
    const result = await api('/company/joining-code/rotate', {
      method: 'POST',
      headers: csrfHeaders()
    });
    const display = byId('joining-code-display');
    display.textContent = `Copy and share this new one-time code: ${result.joining_code}`;
    display.classList.remove('hidden');
    setStatus('Joining code rotated. The previous code is no longer valid.');
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function loadAudit() {
  const result = await api('/company/audit');
  byId('audit-chain-status').textContent = `Hash chain ${result.chain_valid ? 'valid' : 'FAILED'} · most recent 200 entries`;
  const body = byId('audit-list');
  body.replaceChildren();
  result.entries.forEach((entry) => {
    const row = document.createElement('tr');
    appendTextCell(row, new Date(entry.created_at).toLocaleString());
    appendTextCell(row, entry.action);
    appendTextCell(row, entry.outcome);
    appendTextCell(row, entry.actor_user_id ?? 'System/guest');
    appendTextCell(row, entry.resource_id ?? '—');
    body.append(row);
  });
}

function connectAlerts() {
  if (!window.WebSocket) return;
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  alertSocket = new WebSocket(`${scheme}//${window.location.host}/ws/alerts`);
  alertSocket.addEventListener('open', () => {
    byId('notification-state').textContent = 'Connected';
  });
  alertSocket.addEventListener('close', () => {
    byId('notification-state').textContent = 'Disconnected';
  });
  alertSocket.addEventListener('message', (event) => {
    const alert = JSON.parse(event.data);
    if (alert.type === 'heartbeat') return;
    const entry = document.createElement('p');
    entry.textContent = `${alert.timestamp || 'Now'} · ${alert.severity} · ${alert.alert_type} · ${alert.src_ip || '—'} → ${alert.dst_ip || '—'}`;
    byId('live-alerts').prepend(entry);
    while (byId('live-alerts').children.length > 10) byId('live-alerts').lastElementChild.remove();
  });
}

async function logout() {
  try {
    await api('/auth/logout', { method: 'POST', headers: csrfHeaders() });
    if (alertSocket) alertSocket.close();
    window.location.assign('/');
  } catch (error) {
    setStatus(error.message, true);
  }
}

function roleSelect(value) {
  const select = document.createElement('select');
  [
    ['ADMIN', 'Admin'],
    ['SECURITY_ANALYST', 'Security Analyst'],
    ['VIEWER/AUDITOR', 'Viewer/Auditor']
  ].forEach(([role, label]) => select.add(new Option(label, role)));
  select.value = value;
  return select;
}

function csrfHeaders() {
  return { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken };
}

async function api(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  let result;
  try {
    result = await response.json();
  } catch {
    result = null;
  }
  if (!response.ok) throw new Error(readDetail(result?.detail) || `Request failed (${response.status}).`);
  return result;
}

function readDetail(detail) {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((entry) => entry.msg).filter(Boolean).join(' ');
  return '';
}

function appendTextCell(row, value) {
  const cell = document.createElement('td');
  cell.textContent = value == null ? '—' : String(value);
  row.append(cell);
}

function emptyRow(columns, message) {
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = columns;
  cell.className = 'table-empty';
  cell.textContent = message;
  row.append(cell);
  return row;
}

function makeLink(href, label) {
  const link = document.createElement('a');
  link.href = href;
  link.textContent = label;
  link.className = 'text-button';
  return link;
}

function setStatus(message, failed = false) {
  workspaceStatus.textContent = message;
  workspaceStatus.classList.toggle('error', failed);
}
