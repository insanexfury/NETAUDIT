const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const chartInstances = new Map();
const palette = ['#22d3ee', '#38bdf8', '#818cf8', '#34d399', '#f59e0b', '#f87171', '#a78bfa', '#2dd4bf', '#fb7185', '#94a3b8'];
const byId = (id) => document.getElementById(id);
let currentAnalysisId = null;
let currentAnalysis = null;
let packetRows = [];
let packetRequestId = 0;
let historyRows = [];
let toastTimer;
let csrfToken = '';
let authContextError = null;
let authContextPromise;

document.addEventListener('DOMContentLoaded', initialize);

function initialize() {
  bindNavigation();
  bindUpload();
  bindComparison();
  bindPacketExplorer();
  bindHistory();
  bindReportLinks();
  renderIcons();
  authContextPromise = apiRequest('/auth/me').then((session) => {
    csrfToken = session.csrf_token || '';
  }).catch((error) => {
    authContextError = error;
  });
  checkBackendHealth();
  loadAnalyses();
}

function bindNavigation() {
  const sidebar = byId('sidebar');
  const toggle = byId('menu-toggle');
  const scrim = byId('sidebar-scrim');

  const closeMenu = () => {
    sidebar.classList.remove('open');
    scrim.classList.add('hidden');
    toggle.setAttribute('aria-expanded', 'false');
  };

  toggle.addEventListener('click', () => {
    const isOpen = sidebar.classList.toggle('open');
    scrim.classList.toggle('hidden', !isOpen);
    toggle.setAttribute('aria-expanded', String(isOpen));
  });
  scrim.addEventListener('click', closeMenu);

  document.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', () => {
      document.querySelectorAll('.nav-link').forEach((item) => item.classList.remove('active'));
      link.classList.add('active');
      byId('page-title').textContent = link.dataset.title;
      closeMenu();
    });
  });

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      const activeLink = document.querySelector(`.nav-link[href="#${visible.target.id}"]`);
      if (!activeLink) return;
      document.querySelectorAll('.nav-link').forEach((item) => item.classList.toggle('active', item === activeLink));
      byId('page-title').textContent = activeLink.dataset.title;
    }, { rootMargin: '-15% 0px -70% 0px', threshold: [0, 0.1, 0.5] });
    document.querySelectorAll('.page-section').forEach((section) => observer.observe(section));
  }
}

function bindUpload() {
  const input = byId('pcap-file');
  const dropzone = byId('upload-dropzone');

  input.addEventListener('change', () => updateFileLabel(input, 'chosen-file'));
  ['dragenter', 'dragover'].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add('dragging');
  }));
  ['dragleave', 'drop'].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove('dragging');
  }));
  dropzone.addEventListener('drop', (event) => {
    const [file] = event.dataTransfer.files;
    if (!file) return;
    try {
      input.files = event.dataTransfer.files;
      updateFileLabel(input, 'chosen-file');
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  byId('upload-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    await authContextPromise;
    if (authContextError) {
      setStatus(authContextError.message, true);
      return;
    }
    const [file] = input.files;
    const validationError = validatePcap(file);
    if (validationError) {
      setStatus(validationError, true);
      return;
    }

    const button = byId('upload-button');
    setBusy(button, true, 'Analyzing capture…');
    setStatus('Uploading capture and running the analysis pipeline…');
    const formData = new FormData();
    formData.append('file', file);

    try {
      const result = await apiRequest('/upload', { method: 'POST', body: formData });
      setStatus(`Analysis complete: ${formatNumber(result.packet_count)} packets processed.`);
      showToast('Capture analysis completed.');
      await loadAnalyses(result.analysis_id);
      input.value = '';
      updateFileLabel(input, 'chosen-file');
    } catch (error) {
      setStatus(error.message, true);
      showToast(error.message, true);
    } finally {
      setBusy(button, false);
    }
  });
}

function bindComparison() {
  const fileA = byId('compare-file-a');
  const fileB = byId('compare-file-b');
  fileA.addEventListener('change', () => updateFileLabel(fileA, 'compare-chosen-a', '.pcap · Maximum 50 MB'));
  fileB.addEventListener('change', () => updateFileLabel(fileB, 'compare-chosen-b', '.pcap · Maximum 50 MB'));

  byId('compare-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    await authContextPromise;
    if (authContextError) {
      setCompareStatus(authContextError.message, true);
      return;
    }
    const [captureA] = fileA.files;
    const [captureB] = fileB.files;
    const validationError = validatePcap(captureA) || validatePcap(captureB);
    if (validationError) {
      setCompareStatus(validationError, true);
      return;
    }

    const button = byId('compare-button');
    setBusy(button, true, 'Comparing captures…');
    setCompareStatus('Uploading both captures for comparison…');
    const formData = new FormData();
    formData.append('file_a', captureA);
    formData.append('file_b', captureB);

    try {
      const result = await apiRequest('/compare', { method: 'POST', body: formData });
      renderComparison(result);
      setCompareStatus('Comparison complete. Results below are based on the returned capture data.');
      showToast('Capture comparison completed.');
    } catch (error) {
      setCompareStatus(error.message, true);
      showToast(error.message, true);
    } finally {
      setBusy(button, false);
    }
  });
}

function bindPacketExplorer() {
  byId('packet-search').addEventListener('input', debounce(loadPackets, 250));
  ['packet-protocol-filter', 'packet-source-filter', 'packet-destination-filter', 'packet-port-filter'].forEach((id) => {
    byId(id).addEventListener('input', renderPackets);
    byId(id).addEventListener('change', renderPackets);
  });
  byId('packets-table').addEventListener('click', (event) => {
    const row = event.target.closest('[data-packet-index]');
    if (!row) return;
    showPacketDetails(packetRows[Number(row.dataset.packetIndex)]);
  });
}

function bindHistory() {
  byId('history-search').addEventListener('input', renderHistory);
  byId('history-table').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-analysis-id]');
    if (!button) return;
    await loadAnalyses(Number(button.dataset.analysisId));
    document.querySelector('#overview').scrollIntoView({ behavior: 'smooth' });
  });
  byId('analysis-select').addEventListener('change', async (event) => {
    if (event.target.value) await loadAnalysis(Number(event.target.value));
    else clearCurrentAnalysis();
  });
}

function bindReportLinks() {
  ['report-link', 'report-page-link'].forEach((id) => {
    byId(id).addEventListener('click', () => {
      if (currentAnalysisId) showToast('Generating the PDF report from saved analysis data…');
    });
  });
}

async function checkBackendHealth() {
  const indicators = [byId('sidebar-health'), byId('top-health')];
  const dots = [byId('sidebar-health-dot'), byId('top-health-dot')];
  try {
    const result = await apiRequest('/health');
    if (result.status !== 'ok') throw new Error('Backend health check returned an unexpected status.');
    indicators[0].textContent = 'Service online';
    indicators[1].textContent = 'Online';
    dots.forEach((dot) => dot.classList.add('online'));
  } catch {
    indicators[0].textContent = 'Service unavailable';
    indicators[1].textContent = 'Offline';
    dots.forEach((dot) => dot.classList.add('offline'));
  }
}

async function loadAnalyses(preferredId = null) {
  byId('history-status').textContent = 'Loading saved analyses…';
  try {
    historyRows = await apiRequest('/analyses');
    if (!Array.isArray(historyRows)) throw new Error('The analysis history response was not a list.');
    renderAnalysisOptions();
    renderHistory();
    byId('history-status').textContent = historyRows.length ? `${formatNumber(historyRows.length)} saved analyses` : 'No saved analyses yet.';

    const preferred = preferredId || currentAnalysisId;
    const selected = historyRows.find((analysis) => analysis.id === preferred)
      || historyRows.find((analysis) => analysis.status === 'complete');
    if (selected) await loadAnalysis(selected.id);
    else clearCurrentAnalysis();
  } catch (error) {
    byId('history-status').textContent = `Unable to load analysis history: ${error.message}`;
    showToast(`Analysis history unavailable: ${error.message}`, true);
  }
}

function renderAnalysisOptions() {
  const select = byId('analysis-select');
  const selectedId = currentAnalysisId ? String(currentAnalysisId) : '';
  select.innerHTML = '<option value="">No analysis selected</option>' + historyRows.map((analysis) =>
    `<option value="${escapeHtml(analysis.id)}">${escapeHtml(analysis.filename)} · ${escapeHtml(analysis.status)}</option>`).join('');
  select.value = historyRows.some((analysis) => String(analysis.id) === selectedId) ? selectedId : '';
}

function renderHistory() {
  const query = byId('history-search').value.trim().toLowerCase();
  const rows = historyRows.filter((analysis) => String(analysis.filename || '').toLowerCase().includes(query));
  byId('history-table').innerHTML = rows.length ? rows.map((analysis) => `
    <tr>
      <td class="filename-cell">${escapeHtml(analysis.filename || '—')}</td>
      <td>${formatDate(analysis.uploaded_at)}</td>
      <td>${formatNumber(analysis.packet_count)}</td>
      <td><span class="state-badge ${analysis.status === 'complete' ? 'complete' : ''}">${escapeHtml(analysis.status || 'Unknown')}</span></td>
      <td>${analysis.threat_score == null ? '—' : `${escapeHtml(analysis.threat_score)}/100`}</td>
      <td><span class="severity-badge severity-${severityKey(analysis.severity)}">${escapeHtml(analysis.severity || '—')}</span></td>
      <td><button class="text-button" type="button" data-analysis-id="${escapeHtml(analysis.id)}">View analysis</button></td>
    </tr>`).join('') : '<tr><td colspan="7" class="table-empty">No saved analyses match this search.</td></tr>';
}

async function loadAnalysis(id) {
  try {
    const data = await apiRequest(`/analyses/${encodeURIComponent(id)}`);
    currentAnalysisId = data.id;
    currentAnalysis = data;
    byId('analysis-select').value = String(data.id);
    byId('active-analysis-label').textContent = data.filename || `Analysis ${data.id}`;
    renderAnalysis(data);
    await loadPackets();
  } catch (error) {
    showToast(`Unable to load analysis: ${error.message}`, true);
    if (!currentAnalysis) clearCurrentAnalysis();
  }
}

function clearCurrentAnalysis() {
  currentAnalysisId = null;
  currentAnalysis = null;
  packetRows = [];
  byId('analysis-select').value = '';
  byId('active-analysis-label').textContent = 'Select or upload a capture to begin';
  byId('overview-empty').classList.remove('hidden');
  byId('dashboard-data').classList.add('hidden');
  byId('anomaly-empty').classList.remove('hidden');
  byId('anomaly-data').classList.add('hidden');
  byId('analytics-empty').classList.remove('hidden');
  byId('analytics-data').classList.add('hidden');
  byId('report-link').classList.add('hidden');
  byId('report-page-link').classList.add('hidden');
  byId('report-analysis-name').textContent = 'Select a completed analysis';
  byId('packets-table').innerHTML = '<tr><td colspan="7" class="table-empty">Select an analysis to inspect packets.</td></tr>';
  byId('packet-count').textContent = '';
  byId('packet-detail').classList.add('hidden');
  destroyCharts();
}

function renderAnalysis(data) {
  const stats = data.statistics || {};
  const alerts = Array.isArray(data.alerts) ? data.alerts : [];
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  byId('overview-empty').classList.add('hidden');
  byId('dashboard-data').classList.remove('hidden');
  byId('anomaly-empty').classList.add('hidden');
  byId('anomaly-data').classList.remove('hidden');
  byId('analytics-empty').classList.add('hidden');
  byId('analytics-data').classList.remove('hidden');

  byId('metric-packets').textContent = formatNumber(stats.total_packets);
  byId('metric-bytes').textContent = formatBytes(stats.total_bytes);
  byId('metric-ips').textContent = `${formatNumber(stats.unique_source_ips)} / ${formatNumber(stats.unique_destination_ips)}`;
  byId('metric-alerts').textContent = formatNumber(alerts.length);
  byId('metric-score').textContent = data.threat_score == null ? '—' : `${data.threat_score}/100`;
  byId('metric-severity').textContent = data.severity || 'Severity unavailable';
  setSeverityBadge(byId('overview-severity'), data.severity);

  byId('report-analysis-name').textContent = data.filename || `Analysis ${data.id}`;
  if (data.status === 'complete') {
    const reportUrl = `/analyses/${encodeURIComponent(data.id)}/report`;
    ['report-link', 'report-page-link'].forEach((id) => {
      byId(id).href = reportUrl;
      byId(id).classList.remove('hidden');
    });
  } else {
    byId('report-link').classList.add('hidden');
    byId('report-page-link').classList.add('hidden');
  }

  byId('threat-message').textContent = data.threat_score == null
    ? 'Threat score is unavailable for this analysis.'
    : `Heuristic score: ${data.threat_score}/100 — ${data.severity || 'severity unavailable'}. Findings identify suspicious patterns, not confirmed attacks.`;
  byId('reasons').innerHTML = reasons.length
    ? reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')
    : '<li>No configured anomaly rule was triggered.</li>';

  const statRows = [
    ['Analysis duration', `${formatNumber(stats.duration)} seconds`],
    ['Total traffic volume', formatBytes(stats.total_bytes)],
    ['Packets per second', formatNumber(stats.packets_per_second)],
    ['TCP / UDP / ICMP', `${formatNumber(stats.tcp_count)} / ${formatNumber(stats.udp_count)} / ${formatNumber(stats.icmp_count)}`],
    ['DNS queries', formatNumber(stats.dns_query_count)],
    ['HTTP requests', formatNumber(stats.http_request_count)],
    ['Unique destination ports', formatNumber(stats.unique_destination_ports)]
  ];
  byId('traffic-stats').innerHTML = statRows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`).join('');

  renderAlerts(alerts);
  renderAnalytics(stats, alerts);
}

function renderAlerts(alerts) {
  byId('finding-count').textContent = `${formatNumber(alerts.length)} ${alerts.length === 1 ? 'finding' : 'findings'}`;
  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  alerts.forEach((alert) => {
    const severity = Object.keys(severityCounts).find((key) => key.toLowerCase() === String(alert.severity).toLowerCase());
    if (severity) severityCounts[severity] += 1;
  });
  Object.entries(severityCounts).forEach(([severity, count]) => {
    byId(`severity-${severity.toLowerCase()}`).textContent = formatNumber(count);
  });

  byId('alerts-table').innerHTML = alerts.length ? alerts.map((alert) => `
    <tr>
      <td><span class="severity-badge severity-${severityKey(alert.severity)}">${escapeHtml(alert.severity || '—')}</span></td>
      <td class="filename-cell">${escapeHtml(alert.alert_type || 'Finding')}</td>
      <td>${escapeHtml(alert.src_ip || '—')}</td>
      <td>${escapeHtml(alert.dst_ip || '—')}</td>
      <td>${formatDate(alert.timestamp)}</td>
      <td class="evidence-cell"><details class="evidence-details"><summary>Inspect details</summary><p>${escapeHtml(alert.description || alert.evidence || 'No description returned.')}</p><small>Evidence: ${escapeHtml(alert.evidence || 'Unavailable')}</small><small>Score contribution: ${displayValue(alert.score)}</small></details></td>
    </tr>`).join('') : '<tr><td colspan="6" class="table-empty">No security alerts were generated by the configured rules.</td></tr>';

  const recentAlerts = alerts.slice(-5).reverse();
  byId('recent-alerts-table').innerHTML = recentAlerts.length ? recentAlerts.map((alert) => `
    <tr>
      <td><span class="severity-badge severity-${severityKey(alert.severity)}">${escapeHtml(alert.severity || '—')}</span></td>
      <td class="filename-cell">${escapeHtml(alert.alert_type || 'Finding')}</td>
      <td>${escapeHtml(alert.src_ip || '—')}</td>
      <td>${escapeHtml(alert.dst_ip || '—')}</td>
      <td>${formatDate(alert.timestamp)}</td>
    </tr>`).join('') : '<tr><td colspan="5" class="table-empty">No security alerts were generated by the configured rules.</td></tr>';
  byId('recent-alert-count').textContent = `${formatNumber(recentAlerts.length)} recent · ${formatNumber(alerts.length)} total`;
}

function renderAnalytics(stats, alerts) {
  const protocolEntries = Object.entries(stats.protocol_distribution || {});
  const trafficRows = Array.isArray(stats.traffic_over_time) ? stats.traffic_over_time : [];
  const trafficLabels = trafficRows.map(([timestamp]) => formatTime(timestamp));
  const trafficValues = trafficRows.map(([, count]) => Number(count) || 0);
  const protocolLabels = protocolEntries.map(([protocol]) => protocol);
  const protocolValues = protocolEntries.map(([, count]) => Number(count) || 0);

  drawChart('traffic-chart', 'line', trafficLabels, trafficValues, 'Packets');
  drawChart('analytics-traffic-chart', 'line', trafficLabels, trafficValues, 'Packets');
  drawChart('protocol-chart', 'doughnut', protocolLabels, protocolValues, 'Packets');
  drawChart('analytics-protocol-chart', 'doughnut', protocolLabels, protocolValues, 'Packets');
  drawEntryChart('source-chart', stats.top_sources, 'Packets', { horizontal: true });
  drawEntryChart('analytics-source-chart', stats.top_sources, 'Packets', { horizontal: true });
  drawEntryChart('destination-chart', stats.top_destinations, 'Packets', { horizontal: true });
  drawEntryChart('port-chart', stats.top_ports, 'Packets');
  drawEntryChart('analytics-port-chart', stats.top_ports, 'Packets');

  const severities = ['Critical', 'High', 'Medium', 'Low'];
  drawChart('severity-chart', 'doughnut', severities, severities.map((severity) =>
    alerts.filter((alert) => String(alert.severity).toLowerCase() === severity.toLowerCase()).length), 'Findings', {
    colors: ['#ef4444', '#f97316', '#f59e0b', '#38bdf8']
  });
  const timeline = new Map();
  alerts.forEach((alert) => {
    if (!alert.timestamp) return;
    const label = formatTime(alert.timestamp);
    timeline.set(label, (timeline.get(label) || 0) + 1);
  });
  drawChart('anomaly-timeline-chart', 'line', Array.from(timeline.keys()), Array.from(timeline.values()), 'Findings');

  const windows = Array.isArray(stats.window_statistics) ? stats.window_statistics : [];
  byId('windows-table').innerHTML = windows.length ? windows.map((window) => `
    <tr><td>${formatDate(window.start)}</td><td>${formatNumber(window.total_packets)}</td><td>${formatBytes(window.total_bytes)}</td>
    <td>${formatNumber(window.tcp_packets)}</td><td>${formatNumber(window.udp_packets)}</td><td>${formatNumber(window.icmp_packets)}</td>
    <td>${formatNumber(window.unique_source_ips)}</td><td>${formatNumber(window.unique_destination_ips)}</td><td>${formatNumber(window.unique_destination_ports)}</td></tr>`).join('')
    : '<tr><td colspan="9" class="table-empty">No 10-second window data is available.</td></tr>';
}

async function loadPackets() {
  if (!currentAnalysisId) return;
  const requestId = ++packetRequestId;
  const query = byId('packet-search').value.trim();
  byId('packets-table').innerHTML = '<tr><td colspan="7" class="table-empty">Loading packet records…</td></tr>';
  try {
    const rows = await apiRequest(`/analyses/${encodeURIComponent(currentAnalysisId)}/packets?limit=100&search=${encodeURIComponent(query)}`);
    if (requestId !== packetRequestId) return;
    if (!Array.isArray(rows)) throw new Error('The packet response was not a list.');
    packetRows = rows;
    populateProtocolFilter(rows);
    renderPackets();
  } catch (error) {
    if (requestId !== packetRequestId) return;
    byId('packets-table').innerHTML = `<tr><td colspan="7" class="table-empty">${escapeHtml(error.message)}</td></tr>`;
    byId('packet-count').textContent = '';
  }
}

function populateProtocolFilter(rows) {
  const select = byId('packet-protocol-filter');
  const selected = select.value;
  const protocols = Array.from(new Set(rows.map((packet) => packet.protocol).filter(Boolean))).sort();
  select.innerHTML = '<option value="">All protocols</option>' + protocols.map((protocol) =>
    `<option value="${escapeHtml(protocol)}">${escapeHtml(protocol)}</option>`).join('');
  select.value = protocols.includes(selected) ? selected : '';
}

function renderPackets() {
  const protocol = byId('packet-protocol-filter').value.toLowerCase();
  const source = byId('packet-source-filter').value.trim().toLowerCase();
  const destination = byId('packet-destination-filter').value.trim().toLowerCase();
  const port = byId('packet-port-filter').value.trim().toLowerCase();
  const rows = packetRows.map((packet, index) => ({ packet, index })).filter(({ packet }) =>
    (!protocol || String(packet.protocol || '').toLowerCase() === protocol)
    && (!source || String(packet.src_ip || '').toLowerCase().includes(source))
    && (!destination || String(packet.dst_ip || '').toLowerCase().includes(destination))
    && (!port || [packet.src_port, packet.dst_port].some((value) => String(value ?? '').includes(port))));

  byId('packets-table').innerHTML = rows.length ? rows.map(({ packet, index }) => `
    <tr class="packet-row" data-packet-index="${index}" tabindex="0" aria-label="Inspect packet ${escapeHtml(packet.packet_number)}">
      <td>${escapeHtml(packet.packet_number ?? '—')}</td><td>${formatTime(packet.timestamp)}</td>
      <td>${escapeHtml(packet.src_ip || '—')}</td><td>${escapeHtml(packet.dst_ip || '—')}</td>
      <td><span class="protocol-pill">${escapeHtml(packet.protocol || '—')}</span></td>
      <td>${escapeHtml(packet.src_port ?? '—')} <span class="port-arrow">→</span> ${escapeHtml(packet.dst_port ?? '—')}</td>
      <td>${formatNumber(packet.packet_length)} B</td>
    </tr>`).join('') : '<tr><td colspan="7" class="table-empty">No matching packets in the returned records.</td></tr>';
  byId('packet-count').textContent = `${formatNumber(rows.length)} shown · API returns at most 100 records`;
}

function showPacketDetails(packet) {
  if (!packet) return;
  const details = [
    ['Packet number', packet.packet_number],
    ['Timestamp', packet.timestamp ? formatDate(packet.timestamp) : null],
    ['Protocol', packet.protocol],
    ['Source', packet.src_ip],
    ['Source port', packet.src_port],
    ['Destination', packet.dst_ip],
    ['Destination port', packet.dst_port],
    ['Packet length', packet.packet_length == null ? null : `${formatNumber(packet.packet_length)} bytes`],
    ['TCP flags', packet.tcp_flags],
    ['DNS query', packet.dns_query],
    ['HTTP host', packet.http_host],
    ['HTTP method', packet.http_method],
    ['HTTP URI', packet.http_uri]
  ].filter(([, value]) => value != null && value !== '');
  const panel = byId('packet-detail');
  panel.innerHTML = `<div class="panel-heading"><div><p class="eyebrow">PACKET INSPECTION</p><h2>Packet ${escapeHtml(packet.packet_number ?? '—')}</h2></div><button class="icon-button" id="close-packet-detail" type="button" aria-label="Close packet details"><i data-lucide="x"></i></button></div><dl class="packet-detail-grid">${details.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`).join('')}</dl>`;
  panel.classList.remove('hidden');
  byId('close-packet-detail').addEventListener('click', () => panel.classList.add('hidden'));
  renderIcons();
}

function renderComparison(result) {
  const captureA = result.capture_a || {};
  const captureB = result.capture_b || {};
  const comparison = result.comparison || {};
  byId('compare-results').classList.remove('hidden');
  byId('compare-a-name').textContent = captureA.filename || 'Capture A';
  byId('compare-b-name').textContent = captureB.filename || 'Capture B';
  byId('compare-a-summary').textContent = `${formatNumber(captureA.packet_count)} packets · ${captureA.threat_score == null ? 'score unavailable' : `${captureA.threat_score}/100`}`;
  byId('compare-b-summary').textContent = `${formatNumber(captureB.packet_count)} packets · ${captureB.threat_score == null ? 'score unavailable' : `${captureB.threat_score}/100`}`;
  byId('compare-score-delta').textContent = comparison.score_delta == null ? 'Unavailable' : `${comparison.score_delta >= 0 ? '+' : ''}${comparison.score_delta}`;
  byId('compare-severity-shift').textContent = comparison.severity_shift ? `Capture B severity: ${comparison.severity_shift}` : 'Severity comparison unavailable';

  const protocols = Array.isArray(comparison.protocols) ? comparison.protocols : [];
  drawComparisonChart(protocols);
  renderIpOverlap('compare-source-ips', comparison.source_ips);
  renderIpOverlap('compare-destination-ips', comparison.destination_ips);

  const ports = comparison.port_summary;
  byId('compare-ports').innerHTML = ports ? [
    listItem(`Common destination ports: ${formatList(ports.common_destination_ports)}`),
    listItem(`Only in A: ${formatList(ports.only_in_a)}`),
    listItem(`Only in B: ${formatList(ports.only_in_b)}`),
    listItem(`Unique TCP ports: A ${displayValue(ports.tcp_unique_ports?.a)} · B ${displayValue(ports.tcp_unique_ports?.b)}`),
    listItem(`Unique UDP ports: A ${displayValue(ports.udp_unique_ports?.a)} · B ${displayValue(ports.udp_unique_ports?.b)}`)
  ].join('') : listItem('Port comparison data is unavailable.');

  const alerts = comparison.alerts;
  byId('compare-alerts').innerHTML = alerts ? [
    listItem(`Shared alert types: ${formatList(alerts.shared_types)}`),
    listItem(`Only in A: ${formatList(alerts.only_in_a)}`),
    listItem(`Only in B: ${formatList(alerts.only_in_b)}`),
    ...Object.entries(alerts.counts || {}).map(([type, counts]) =>
      listItem(`${escapeHtml(type)}: A ${displayValue(counts.a)} · B ${displayValue(counts.b)}`))
  ].join('') : listItem('Alert comparison data is unavailable.');
}

function renderIpOverlap(id, data) {
  byId(id).innerHTML = data ? [
    listItem(`Shared: ${formatList(data.common)}`),
    listItem(`Only in A: ${formatList(data.only_in_a)}`),
    listItem(`Only in B: ${formatList(data.only_in_b)}`)
  ].join('') : listItem('IP overlap data is unavailable.');
}

function drawComparisonChart(protocols) {
  const canvas = byId('compare-protocol-chart');
  if (!canvas) return;
  destroyChart('compare-protocol-chart');
  const emptyMessage = byId('compare-protocol-chart-empty');
  canvas.classList.toggle('hidden', protocols.length === 0);
  emptyMessage.classList.toggle('hidden', protocols.length > 0);
  if (protocols.length === 0) return;
  if (typeof Chart === 'undefined') {
    showToast('Chart library did not load; comparison values are still available.', true);
    return;
  }
  const labels = protocols.map((item) => item.label);
  chartInstances.set('compare-protocol-chart', new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'Capture A', data: protocols.map((item) => item.a_count), backgroundColor: '#22d3ee', borderRadius: 5 },
        { label: 'Capture B', data: protocols.map((item) => item.b_count), backgroundColor: '#818cf8', borderRadius: 5 }
      ]
    },
    options: chartOptions('bar', { legend: true })
  }));
}

function drawChart(id, type, labels, values, label, options = {}) {
  const canvas = byId(id);
  if (!canvas) return;
  const hasData = labels.length > 0;
  let emptyMessage = byId(`${id}-empty`);
  if (!emptyMessage && !hasData) {
    emptyMessage = document.createElement('p');
    emptyMessage.id = `${id}-empty`;
    emptyMessage.className = 'chart-empty';
    emptyMessage.textContent = 'No data is available for this chart.';
    canvas.parentElement.append(emptyMessage);
  }
  canvas.classList.toggle('hidden', !hasData);
  if (emptyMessage) emptyMessage.classList.toggle('hidden', hasData);
  destroyChart(id);
  if (!hasData || typeof Chart === 'undefined') {
    if (hasData && typeof Chart === 'undefined') showToast('Chart library did not load; numeric analysis data is still available.', true);
    return;
  }

  const isDonut = type === 'doughnut';
  const colors = options.colors || palette;
  chartInstances.set(id, new Chart(canvas, {
    type,
    data: {
      labels,
      datasets: [{
        label,
        data: values,
        backgroundColor: isDonut ? labels.map((_, index) => colors[index % colors.length]) : type === 'line' ? 'rgba(34, 211, 238, 0.1)' : colors[0],
        borderColor: isDonut ? undefined : colors[0],
        borderWidth: isDonut ? 0 : 2,
        borderRadius: type === 'bar' ? 5 : 0,
        fill: type === 'line',
        tension: 0.34,
        pointRadius: type === 'line' ? 3 : 0,
        pointHoverRadius: type === 'line' ? 5 : 0
      }]
    },
    options: chartOptions(type, options)
  }));
}

function drawEntryChart(id, entries, label, options = {}) {
  const [labels, values] = entriesToLabelsValues(entries);
  drawChart(id, 'bar', labels, values, label, options);
}

function chartOptions(type, options = {}) {
  const isDonut = type === 'doughnut';
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { intersect: false, mode: 'index' },
    plugins: {
      legend: {
        display: isDonut || Boolean(options.legend),
        position: 'bottom',
        labels: { color: '#94a3b8', usePointStyle: true, padding: 18, font: { family: 'Inter', size: 11 } }
      },
      tooltip: {
        backgroundColor: '#14243a',
        titleColor: '#e5edf7',
        bodyColor: '#cbd5e1',
        borderColor: '#243449',
        borderWidth: 1,
        padding: 12
      }
    },
    scales: isDonut ? {} : {
      x: {
        beginAtZero: Boolean(options.horizontal),
        grid: { display: Boolean(options.horizontal) },
        ticks: { color: '#94a3b8', maxRotation: 0, autoSkip: true, font: { family: 'Inter', size: 10 } },
      },
      y: {
        beginAtZero: !options.horizontal,
        grid: { color: options.horizontal ? 'transparent' : 'rgba(148, 163, 184, 0.1)' },
        ticks: { color: '#94a3b8', precision: 0, font: { family: 'Inter', size: 10 } }
      }
    },
    indexAxis: options.horizontal ? 'y' : 'x'
  };
}

function destroyChart(id) {
  const chart = chartInstances.get(id);
  if (chart) {
    chart.destroy();
    chartInstances.delete(id);
  }
}

function destroyCharts() {
  chartInstances.forEach((chart) => chart.destroy());
  chartInstances.clear();
}

async function apiRequest(url, options = {}) {
  let response;
  try {
    const method = (options.method || 'GET').toUpperCase();
    const headers = { ...(options.headers || {}) };
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) headers['X-CSRF-Token'] = csrfToken;
    response = await fetch(url, { credentials: 'same-origin', ...options, headers });
  } catch (error) {
    throw new Error(`Network request failed: ${error.message}`);
  }
  const responseText = await response.text();
  let result;
  try {
    result = responseText ? JSON.parse(responseText) : null;
  } catch {
    result = responseText;
  }
  if (!response.ok) {
    const message = result && typeof result === 'object' ? result.detail : null;
    throw new Error(message || `Request failed with status ${response.status}.`);
  }
  return result;
}

function validatePcap(file) {
  if (!file) return 'Choose a PCAP file before continuing.';
  if (!file.name.toLowerCase().endsWith('.pcap')) return 'Only .pcap files are supported.';
  if (file.size === 0) return 'The selected PCAP file is empty.';
  if (file.size > MAX_UPLOAD_BYTES) return 'The selected file exceeds the 50 MB upload limit.';
  return '';
}

function updateFileLabel(input, labelId, defaultText = 'Select a .pcap file · Maximum 50 MB') {
  const [file] = input.files;
  byId(labelId).textContent = file ? `${file.name} · ${formatBytes(file.size)}` : defaultText;
}

function setBusy(button, busy, label = '') {
  if (busy) {
    button.dataset.originalContent = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="spinner" aria-hidden="true"></span>${escapeHtml(label)}`;
  } else {
    button.disabled = false;
    if (button.dataset.originalContent) button.innerHTML = button.dataset.originalContent;
    delete button.dataset.originalContent;
    renderIcons();
  }
}

function setStatus(message, failed = false) {
  const status = byId('upload-status');
  status.textContent = message;
  status.classList.toggle('error', failed);
}

function setCompareStatus(message, failed = false) {
  const status = byId('compare-status');
  status.textContent = message;
  status.classList.toggle('error', failed);
}

function showToast(message, failed = false) {
  const region = byId('toast-region');
  region.innerHTML = `<div class="toast ${failed ? 'toast-error' : ''}"><i data-lucide="${failed ? 'circle-alert' : 'circle-check'}"></i><span>${escapeHtml(message)}</span></div>`;
  renderIcons();
  region.classList.add('visible');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => region.classList.remove('visible'), 4500);
}

function renderIcons() {
  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

function entriesToLabelsValues(entries) {
  const normalized = Array.isArray(entries) ? entries : [];
  return [normalized.map(([label]) => label), normalized.map(([, value]) => Number(value) || 0)];
}

function listItem(text) {
  return `<li>${text}</li>`;
}

function formatList(values) {
  if (!Array.isArray(values)) return 'Unavailable';
  if (!values.length) return 'None';
  const visible = values.slice(0, 8).map((value) => escapeHtml(value));
  if (values.length > visible.length) visible.push(`and ${formatNumber(values.length - visible.length)} more`);
  return visible.join(', ');
}

function displayValue(value) {
  return value == null ? 'Unavailable' : escapeHtml(value);
}

function setSeverityBadge(target, severity) {
  target.textContent = severity || 'Unavailable';
  target.className = `severity-badge severity-${severityKey(severity)}`;
}

function severityKey(severity) {
  const normalized = String(severity || '').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(normalized) ? normalized : 'unknown';
}

function formatNumber(value) {
  return value == null || !Number.isFinite(Number(value)) ? '—' : Number(value).toLocaleString();
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${formatNumber(bytes)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let size = bytes / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size < 10 ? 1 : 0)} ${units[unitIndex]}`;
}

function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function debounce(callback, wait) {
  let timeout;
  return (...args) => {
    window.clearTimeout(timeout);
    timeout = window.setTimeout(() => callback(...args), wait);
  };
}
