const form = document.querySelector('#upload-form');
const fileInput = document.querySelector('#apk-file');
const directoryInput = document.querySelector('#directory-files');
const dropzone = document.querySelector('#dropzone');
const directoryDropzone = document.querySelector('#directory-dropzone');
const results = document.querySelector('#results');
const errorBox = document.querySelector('#error');
const submitButton = form.querySelector('button[type="submit"]');
let latestReport = null;
let baselineReport = null;

fetch('/api/health')
  .then((response) => response.ok ? response.json() : Promise.reject(new Error('health check failed')))
  .then((status) => {
    const aiStatus = document.querySelector('#ai-status');
    if (aiStatus && status.ai_enabled) aiStatus.textContent = `AI active · ${status.ai_provider}`;
    const version = document.querySelector('#app-version');
    if (version && status.version) version.textContent = status.version;
  })
  .catch(() => {});

function selectFile(file) {
  if (!file) return;
  document.querySelector('#file-title').textContent = file.name;
  document.querySelector('#file-subtitle').textContent = `${(file.size / 1024 / 1024).toFixed(2)} MB · ready for analysis`;
}
function setAnalysisMode(mode) {
  form.dataset.mode = mode;
  const directoryMode = mode === 'directory';
  dropzone.hidden = directoryMode;
  directoryDropzone.hidden = !directoryMode;
  document.querySelector('#profile-select').hidden = !directoryMode;
  fileInput.disabled = directoryMode;
  fileInput.required = !directoryMode;
  directoryInput.disabled = !directoryMode;
  document.querySelectorAll('.mode-button').forEach((button) => {
    const selected = button.dataset.mode === mode;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-pressed', String(selected));
  });
  submitButton.querySelector('span').textContent = directoryMode ? 'Analyze project' : 'Start analysis';
}
document.querySelectorAll('.mode-button').forEach((button) => {
  button.addEventListener('click', () => setAnalysisMode(button.dataset.mode));
});
fileInput.addEventListener('change', () => selectFile(fileInput.files[0]));
// The platform profile targets huge trees (AOSP), so only the files it understands are uploaded.
const PLATFORM_FILE = /(^|\/)(build\.prop|default\.prop|system\.prop|vendor\.prop|product\.prop|odm\.prop|system_ext\.prop|prop\.default|Android\.bp|AndroidManifest\.xml|aaos\.toml)$|\.(prop|mk|te|rc)$|(^|\/)(privapp-permissions|default-permissions)[^/]*\.xml$/;
const PLATFORM_IGNORED = /(^|\/)(\.git|\.repo|out|prebuilts|node_modules)\//;
const platformProfileSelected = () => document.querySelector('#analysis-profile').value === 'platform';
function selectedDirectoryFiles() {
  const files = [...directoryInput.files];
  if (!platformProfileSelected()) return files;
  return files.filter((file) => {
    const path = file.webkitRelativePath || file.name;
    return PLATFORM_FILE.test(path) && !PLATFORM_IGNORED.test(path);
  });
}
function updateDirectorySummary() {
  const files = [...directoryInput.files];
  if (!files.length) return;
  const folderName = (files[0].webkitRelativePath || files[0].name).split('/')[0];
  const selected = selectedDirectoryFiles();
  const totalBytes = selected.reduce((total, file) => total + file.size, 0);
  document.querySelector('#directory-title').textContent = folderName;
  document.querySelector('#directory-subtitle').textContent = platformProfileSelected()
    ? `${selected.length} platform files of ${files.length} · ${(totalBytes / 1024 / 1024).toFixed(2)} MB · build properties, SELinux, init, permissions and Soong`
    : `${files.length} files selected · ${(totalBytes / 1024 / 1024).toFixed(2)} MB · only code/configuration is analyzed`;
}
directoryInput.addEventListener('change', updateDirectorySummary);
document.querySelector('#analysis-profile').addEventListener('change', updateDirectorySummary);
for (const eventName of ['dragenter', 'dragover']) dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.add('drag'); });
for (const eventName of ['dragleave', 'drop']) dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.remove('drag'); });
dropzone.addEventListener('drop', (event) => { if (event.dataTransfer.files.length) { fileInput.files = event.dataTransfer.files; selectFile(fileInput.files[0]); } });

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
function renderReport(report) {
  latestReport = report;
  const findings = report.findings || [];
  const count = findings.length;
  const severityCounts = report.severity_counts || {};
  const riskLabels = { elevated: 'elevated risk', review: 'needs review', informational: 'no high/medium findings' };
  const severitySummary = [
    ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info'],
  ].map(([key, label]) => `${label}: ${Number(severityCounts[key] || 0)}`).join(' · ');
  const contextSources = (report.ai_context_sources || []).map((source) => escapeHtml(source.title)).join(' · ');
  const ai = report.ai_advice
    ? `<div class="ai-box"><strong>✦ AI-assisted summary</strong><br>${escapeHtml(report.ai_advice)}${contextSources ? `<br><small>Context consulted: ${contextSources}</small>` : ''}</div>`
    : '';
  const findingCards = findings.map((item) => `<article class="finding finding-card" data-severity="${escapeHtml(item.severity)}"><div class="finding-title"><span class="badge ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>${escapeHtml(item.title)}</div><p>${escapeHtml(item.summary)} <b>Recommendation:</b> ${escapeHtml(item.recommendation)}</p><small>${escapeHtml(item.rule_id)} · Evidence: ${escapeHtml(item.evidence)}${item.masvs?.length ? ` · ${escapeHtml(item.masvs.join(', '))}` : ''}</small></article>`).join('');
  const components = report.components || [];
  const nativeLibraries = report.native_libraries || [];
  const pentestPlan = report.pentest_plan || { checks: [], notice: 'Checklist not available.', execution_status: 'not_executed' };
  const componentCount = Number(report.component_count ?? components.length);
  const libraryCount = nativeLibraries.length;
  const checkCount = pentestPlan.checks.length;
  const reportHash = report.apk_sha256 || report.source_sha256 || '';
  const isSourceReport = report.report_type === 'source_directory';
  const automotiveStatus = report.analysis_profile === 'platform' ? 'not applicable' : isSourceReport && report.analysis_profile !== 'aaos'
    ? 'AAOS not selected'
    : report.automotive_feature_declared ? 'declared' : 'not confirmed';
  const connectorNames = report.external_connectors || [];
  const noFindings = findings.length ? '' : '<p class="finding" id="no-findings">None of the static checks included in the MVP found a problem. This does not mean the application is secure.</p>';

  results.innerHTML = `<div class="result-header"><div><div class="eyebrow muted">${isSourceReport ? 'SOURCE CODE REPORT' : 'STATIC REPORT'}</div><h2>${escapeHtml(report.package_name)}</h2><div class="package">${escapeHtml(isSourceReport ? report.project_name : `${report.version_name} · version ${report.version_code}`)}</div></div><span class="score">${escapeHtml(riskLabels[report.risk_level] || 'level to be validated')}<br>${count} finding${count === 1 ? '' : 's'}</span></div><div class="meta"><span>Min SDK ${escapeHtml(report.min_sdk)}</span><span>Target SDK ${escapeHtml(report.target_sdk)}</span><span>${isSourceReport ? `${escapeHtml(report.source_file_count)} code/configuration files` : `${escapeHtml(report.permission_count)} permissions`}</span><span>Automotive ${escapeHtml(automotiveStatus)}</span><span>${escapeHtml(severitySummary)}</span><span>${componentCount} component${componentCount === 1 ? '' : 's'} · ${escapeHtml(report.exported_component_count ?? 0)} exported</span><span>${libraryCount} native librar${libraryCount === 1 ? 'y' : 'ies'}</span><span>SHA-256 ${escapeHtml(String(reportHash).slice(0, 16))}…</span>${isSourceReport ? `<span>Profile: ${escapeHtml(report.profile_label || report.analysis_profile)}</span>` : ''}${connectorNames.map((name) => `<span>Connector: ${escapeHtml(name)}</span>`).join('')}</div><div class="report-actions"><button class="secondary-button" type="button" data-action="download">Download JSON</button><button class="secondary-button" type="button" data-action="csv">Export findings CSV</button><button class="secondary-button" type="button" data-action="export-sarif">Export SARIF</button><button class="secondary-button" type="button" data-action="export-markdown">Export Markdown</button><button class="secondary-button" type="button" data-action="export-html">Export HTML</button><button class="secondary-button" type="button" data-action="export-ai-context">AI briefing</button>${isSourceReport ? '<button class="secondary-button" type="button" data-action="export-sbom">Export SBOM</button>' : ''}${isSourceReport ? '<button class="secondary-button" type="button" data-action="import-connector">Import external report</button><input id="connector-file" type="file" accept=".sarif,.json,.xml,application/json,application/xml,text/xml" hidden>' : ''}<button class="secondary-button" type="button" data-action="baseline">Set baseline</button><button class="secondary-button" type="button" data-action="compare" ${baselineReport ? '' : 'hidden'}>Compare with baseline</button><span id="baseline-status">${baselineReport ? `Baseline in memory: ${escapeHtml(baselineReport.version_name || baselineReport.project_name)} · ${escapeHtml(String(baselineReport.apk_sha256 || baselineReport.source_sha256 || '').slice(0, 12))}…` : 'Baseline kept only for this session.'}</span></div><section class="comparison-box" id="comparison-box" hidden></section>${ai}<details class="lazy-panel" data-lazy="inventory"><summary>${isSourceReport ? 'Analysis profiles and scope' : `Android inventory · ${componentCount} component${componentCount === 1 ? '' : 's'} · ${libraryCount} native librar${libraryCount === 1 ? 'y' : 'ies'}`}</summary><div class="lazy-content"><p>Open this section to load the detailed inventory.</p></div></details><details class="lazy-panel" data-lazy="pentest"><summary>Manual validation plan · ${checkCount} check${checkCount === 1 ? '' : 's'}</summary><div class="lazy-content"><p>Open this section to load the authorized checklist.</p></div></details><section class="findings-panel"><div class="findings-toolbar"><h3>Findings (${count})</h3><input id="finding-search" type="search" placeholder="Search findings…" aria-label="Search findings"><select id="severity-filter" aria-label="Filter by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Informational</option></select></div><div id="finding-list">${noFindings}${findingCards}</div><p class="filter-empty" id="filter-empty" hidden>No finding matches the filters.</p></section><div class="privacy-note">Analyzed at ${escapeHtml(report.analyzed_at || 'date not available')} · Scope: ${escapeHtml(report.analysis_scope)} · Heuristic classification, not a certification; validate the findings manually.</div>`;
  if (isSourceReport) {
    const sourceStats = `<span>${escapeHtml(report.source_bytes)} bytes of text analyzed</span><span>Profiles: ${(report.profiles_run || []).map(escapeHtml).join(' · ')}</span>`;
    results.querySelector('.meta')?.insertAdjacentHTML('beforeend', sourceStats);
  }
  const meterSegments = ['critical', 'high', 'medium', 'low', 'info']
    .filter((severity) => Number(severityCounts[severity] || 0) > 0)
    .map((severity) => `<span class="risk-meter-segment ${severity}" style="width:${(Number(severityCounts[severity]) / Math.max(count, 1)) * 100}%" title="${severity}: ${Number(severityCounts[severity])}"></span>`)
    .join('');
  results.querySelector('.meta')?.insertAdjacentHTML('afterend', `<div class="risk-meter"><span class="risk-meter-label">Findings distribution</span><span class="risk-meter-total">${count} total</span><div class="risk-meter-track" role="img" aria-label="Severity distribution: ${escapeHtml(severitySummary)}">${meterSegments}</div></div>`);
  const policy = report.policy;
  if (policy && (policy.suppressed || (policy.warnings || []).length || (policy.expired || []).length)) {
    const note = document.createElement('p');
    note.className = 'privacy-note';
    const parts = [`${policy.suppressed || 0} finding(s) suppressed with a recorded reason`];
    if ((policy.expired || []).length) parts.push(`${policy.expired.length} suppression(s) expired and active again`);
    if ((policy.unused || []).length) parts.push(`${policy.unused.length} stale`);
    if ((policy.warnings || []).length) parts.push(`warnings: ${policy.warnings.join(' | ')}`);
    note.textContent = `Policy ${policy.config || 'aaos.toml'}: ${parts.join(' · ')}.`;
    results.querySelector('.report-actions')?.after(note);
  }
  results.hidden = false;
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderLazyPanel(panel) {
  if (panel.dataset.loaded === 'true' || !latestReport) return;
  const content = panel.querySelector('.lazy-content');
  if (!content) return;

  if (panel.dataset.lazy === 'inventory') {
    if (latestReport.report_type === 'source_directory') {
      const profiles = latestReport.profiles_run || [];
      const platformKinds = Object.entries(latestReport.platform_files || {});
      const platformFiles = platformKinds.length
        ? `<h3>Platform files analyzed (${platformKinds.reduce((total, [, count]) => total + count, 0)})</h3><div class="library-list">${platformKinds.map(([kind, count]) => `<code>${escapeHtml(kind)}: ${escapeHtml(count)}</code>`).join('')}</div>`
        : '';
      const soongApps = latestReport.platform_apps || [];
      const soongRows = soongApps.map((app) => `<tr><td>${escapeHtml(app.name)}</td><td>${escapeHtml(app.certificate || '—')}</td><td>${app.privileged ? 'yes' : 'no'}</td><td>${escapeHtml(app.path)}:${escapeHtml(app.line)}</td></tr>`).join('');
      const platformApps = soongApps.length
        ? `<h3>Soong app modules (${soongApps.length})</h3><div class="table-wrap"><table><thead><tr><th>Name</th><th>Certificate</th><th>Privileged</th><th>Defined in</th></tr></thead><tbody>${soongRows}</tbody></table></div>`
        : '';
      const sourceComponents = latestReport.components || [];
      const sourceDeepLinks = latestReport.deep_links || [];
      const aaosApis = latestReport.aaos_api_references || [];
      const carAppApis = latestReport.car_app_library_references || [];
      const componentRows = sourceComponents.length
        ? sourceComponents.map((component) => `<tr><td>${escapeHtml(component.type)}</td><td>${escapeHtml(component.name)}</td><td>${escapeHtml(component.exported)}</td><td>${escapeHtml(component.permission || '—')}</td></tr>`).join('')
        : '<tr><td colspan="4">No components found in the selected manifests.</td></tr>';
      const deepLinkRows = sourceDeepLinks.length
        ? sourceDeepLinks.map((link) => `<tr><td>${escapeHtml(link.component)}</td><td>${escapeHtml(link.scheme || '—')}</td><td>${escapeHtml(link.host || '—')}</td><td>${escapeHtml(link.path || '—')}</td></tr>`).join('')
        : '<tr><td colspan="4">No browsable deep links found.</td></tr>';
      const renderReferences = (references) => references.length
        ? `<ul>${references.map((item) => `<li><code>${escapeHtml(item.api)}</code> · ${escapeHtml(item.path)}:${escapeHtml(item.line)}</li>`).join('')}</ul>`
        : '<p>No references found.</p>';
      content.innerHTML = `${platformFiles}${platformApps}<h3>Profiles executed (${profiles.length})</h3><div class="library-list">${profiles.map((profile) => `<code>${escapeHtml(profile)}</code>`).join('')}</div>${latestReport.analysis_profile === 'platform' ? '' : `<h3>Components in manifests (${sourceComponents.length})</h3><div class="table-wrap"><table><thead><tr><th>Type</th><th>Name</th><th>Exported</th><th>Permission</th></tr></thead><tbody>${componentRows}</tbody></table></div><h3>Deep links (${sourceDeepLinks.length})</h3><div class="table-wrap"><table><thead><tr><th>Component</th><th>Scheme</th><th>Host</th><th>Path</th></tr></thead><tbody>${deepLinkRows}</tbody></table></div><h3>android.car references (${aaosApis.length})</h3>${renderReferences(aaosApis)}<h3>AndroidX Car App references (${carAppApis.length})</h3>${renderReferences(carAppApis)}`}<p class="privacy-note">${escapeHtml(latestReport.source_file_count)} accepted files were analyzed. Binaries, downloaded dependencies and ignored directories are not inspected. The scanner does not compile or run the project.</p>`;
      panel.dataset.loaded = 'true';
      return;
    }
    const components = latestReport.components || [];
    const nativeLibraries = latestReport.native_libraries || [];
    const deepLinks = latestReport.deep_links || [];
    const componentRows = components.length
      ? components.map((component) => `<tr><td>${escapeHtml(component.type)}</td><td>${escapeHtml(component.name)}</td><td>${escapeHtml(component.exported)}</td><td>${escapeHtml(component.permission || '—')}</td></tr>`).join('')
      : '<tr><td colspan="4">No components recognized in the manifest.</td></tr>';
    const libraryList = nativeLibraries.length
      ? nativeLibraries.map((library) => `<code>${escapeHtml(library)}</code>`).join('')
      : '<span class="inventory-empty">No native libraries (.so) found.</span>';
    const deepLinkRows = deepLinks.length
      ? deepLinks.map((link) => `<tr><td>${escapeHtml(link.component)}</td><td>${escapeHtml(link.scheme || '—')}</td><td>${escapeHtml(link.host || '—')}</td><td>${escapeHtml(link.path || '—')}</td></tr>`).join('')
      : '<tr><td colspan="4">No browsable deep links found.</td></tr>';
    content.innerHTML = `<h3>Components (${components.length})</h3><div class="table-wrap"><table><thead><tr><th>Type</th><th>Name</th><th>Exported</th><th>Permission</th></tr></thead><tbody>${componentRows}</tbody></table></div><h3>Deep links (${deepLinks.length})</h3><div class="table-wrap"><table><thead><tr><th>Component</th><th>Scheme</th><th>Host</th><th>Path</th></tr></thead><tbody>${deepLinkRows}</tbody></table></div><h3>Native libraries (${nativeLibraries.length})</h3><div class="library-list">${libraryList}</div>`;
  } else if (panel.dataset.lazy === 'pentest') {
    const plan = latestReport.pentest_plan || { checks: [], notice: 'Checklist not available.', execution_status: 'not_executed' };
    const checklistKey = `aaos-checklist:${latestReport.package_name}:${latestReport.apk_sha256 || latestReport.source_sha256 || 'unknown'}`;
    let completedChecks = new Set();
    try {
      completedChecks = new Set(JSON.parse(sessionStorage.getItem(checklistKey) || '[]'));
    } catch (error) {
      console.warn('Could not restore the in-session checklist state.', error);
    }
    const checks = plan.checks.map((check, index) => `<article class="pentest-check"><label><input type="checkbox" data-check-index="${index}" ${completedChecks.has(index) ? 'checked' : ''}><span><b>${escapeHtml(check.id)} · ${escapeHtml(check.title)}</b><small>${escapeHtml(check.reason)}</small><small><strong>Safe validation:</strong> ${escapeHtml(check.method)}</small></span></label></article>`).join('');
    const checkLabel = plan.checks.length === 1 ? 'check completed' : 'checks completed';
    const model = latestReport.threat_model || { threats: [], validation_phases: [], not_assessed: [] };
    const threatItems = (model.threats || []).map((threat) => `<li><b>${escapeHtml(threat.id)}</b> ${escapeHtml(threat.title)} <small>${escapeHtml(threat.stride)} · ${escapeHtml((threat.matched_rules || []).slice(0, 3).join(', '))}</small></li>`).join('');
    const phaseItems = (model.validation_phases || []).map((phase) => `<li><b>${escapeHtml(phase.name)}</b> <small>${escapeHtml(phase.goal)} (${phase.checks.length})</small></li>`).join('');
    const notAssessed = (model.not_assessed || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
    const threatHtml = threatItems
      ? `<details class="threat-model"><summary>Derived threat model · ${model.threats.length}</summary><ul>${threatItems}</ul><p><b>Validation phases</b></p><ul>${phaseItems}</ul><p><b>Not covered</b></p><ul>${notAssessed}</ul><small>${escapeHtml(model.notice || '')}</small></details>`
      : '';
    content.innerHTML = `${threatHtml}<p class="pentest-notice">${escapeHtml(plan.notice)} Status: <b>not executed automatically</b>.</p><p class="pentest-progress" aria-live="polite">${completedChecks.size} of ${plan.checks.length} ${checkLabel} in this session.</p>${checks}`;
    panel.dataset.checklistKey = checklistKey;
  }
  panel.dataset.loaded = 'true';
}

function filterFindings() {
  const query = (results.querySelector('#finding-search')?.value || '').trim().toLocaleLowerCase();
  const severity = results.querySelector('#severity-filter')?.value || 'all';
  let visibleCount = 0;
  for (const card of results.querySelectorAll('.finding-card')) {
    const visible = (severity === 'all' || card.dataset.severity === severity)
      && card.textContent.toLocaleLowerCase().includes(query);
    card.hidden = !visible;
    if (visible) visibleCount += 1;
  }
  const empty = results.querySelector('#filter-empty');
  if (empty) empty.hidden = visibleCount > 0 || !latestReport?.findings?.length;
}

function downloadFindingsCsv() {
  const headers = ['rule_id', 'severity', 'title', 'summary', 'recommendation', 'evidence', 'masvs'];
  const quote = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
  const cell = (finding, key) => (Array.isArray(finding[key]) ? finding[key].join(', ') : finding[key] || '');
  const rows = [headers, ...(latestReport.findings || []).map((finding) => headers.map((key) => cell(finding, key)))];
  const csv = `\uFEFF${rows.map((row) => row.map(quote).join(';')).join('\r\n')}`;
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `${String(latestReport.package_name || 'aaos-report').replace(/[^a-zA-Z0-9._-]/g, '_')}-findings.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

async function exportReport(format) {
  // The server converts the in-memory report; nothing is stored server-side.
  const response = await fetch(`/api/export/${format}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(latestReport),
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    alert(detail.detail || 'Could not export the report.');
    return;
  }
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = `${String(latestReport.package_name || 'aaos-report').replace(/[^a-zA-Z0-9._-]/g, '_')}-report.${{ sarif: 'sarif', markdown: 'md', 'ai-context': 'ai-briefing.md', html: 'html', sbom: 'sbom.cdx.json' }[format] || 'txt'}`;
  link.click();
  URL.revokeObjectURL(url);
}

function renderComparison() {
  const box = results.querySelector('#comparison-box');
  if (!box || !latestReport || !baselineReport) return;
  box.hidden = false;
  if (latestReport.package_name !== baselineReport.package_name || latestReport.report_type !== baselineReport.report_type) {
    box.innerHTML = '<strong>Cannot compare:</strong> the package differs from the baseline.';
    return;
  }
  // Fingerprints survive line shifts; fall back to evidence when either report predates them.
  const allFingerprinted = [...(baselineReport.findings || []), ...(latestReport.findings || [])].every((finding) => finding.fingerprint);
  const keyFor = (finding) => `${finding.rule_id}::${allFingerprinted ? finding.fingerprint : finding.evidence}`;
  const before = new Map((baselineReport.findings || []).map((finding) => [keyFor(finding), finding]));
  const after = new Map((latestReport.findings || []).map((finding) => [keyFor(finding), finding]));
  const added = [...after].filter(([key]) => !before.has(key)).map(([, finding]) => finding);
  const resolved = [...before].filter(([key]) => !after.has(key)).map(([, finding]) => finding);
  const unchanged = [...after.keys()].filter((key) => before.has(key)).length;
  const renderList = (items) => items.length
    ? `<ul>${items.map((finding) => `<li><span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span> ${escapeHtml(finding.title)} <small>(${escapeHtml(finding.rule_id)})</small></li>`).join('')}</ul>`
    : '<p>None.</p>';
  box.innerHTML = `<strong>Comparison: ${escapeHtml(baselineReport.version_name || baselineReport.project_name)} → ${escapeHtml(latestReport.version_name || latestReport.project_name)}</strong><div class="comparison-grid"><div><b>New (${added.length})</b>${renderList(added)}</div><div><b>Resolved (${resolved.length})</b>${renderList(resolved)}</div><div><b>Unchanged (${unchanged})</b></div></div><small>Matched by rule and evidence. A fixed rule may reappear with different evidence.</small>`;
}

results.addEventListener('click', (event) => {
  if (!(event.target instanceof Element)) return;
  const button = event.target.closest('[data-action]');
  if (!button || !latestReport) return;
  if (button.dataset.action === 'download') {
    const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${String(latestReport.package_name || 'aaos-report').replace(/[^a-zA-Z0-9._-]/g, '_')}-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  } else if (button.dataset.action === 'csv') {
    downloadFindingsCsv();
  } else if (button.dataset.action === 'export-sarif') {
    exportReport('sarif');
  } else if (button.dataset.action === 'export-markdown') {
    exportReport('markdown');
  } else if (button.dataset.action === 'export-ai-context') {
    exportReport('ai-context');
  } else if (button.dataset.action === 'export-html') {
    exportReport('html');
  } else if (button.dataset.action === 'export-sbom') {
    exportReport('sbom');
  } else if (button.dataset.action === 'import-connector') {
    results.querySelector('#connector-file')?.click();
  } else if (button.dataset.action === 'baseline') {
    baselineReport = latestReport;
    const status = results.querySelector('#baseline-status');
    status.textContent = `Baseline kept for this session: ${baselineReport.version_name || baselineReport.project_name} · ${String(baselineReport.apk_sha256 || baselineReport.source_sha256 || '').slice(0, 12)}…`;
    results.querySelector('[data-action="compare"]').hidden = false;
  } else if (button.dataset.action === 'compare') {
    renderComparison();
  }
});

results.addEventListener('change', async (event) => {
  if (!(event.target instanceof HTMLInputElement) || event.target.id !== 'connector-file') return;
  const file = event.target.files?.[0];
  if (!file || !latestReport || !form.querySelector('input[name="authorized"]').checked) return;
  const payload = new FormData();
  payload.append('authorized', 'true');
  payload.append('file', file, file.name);
  try {
    const response = await fetch('/api/connectors/import-static-report', { method: 'POST', body: payload });
    const imported = await response.json();
    if (!response.ok) throw new Error(imported.detail || 'Could not import the external report.');
    const existing = new Map((latestReport.findings || []).map((finding) => [`${finding.rule_id}::${finding.evidence}`, finding]));
    for (const finding of imported.findings || []) existing.set(`${finding.rule_id}::${finding.evidence}`, finding);
    latestReport.findings = [...existing.values()];
    latestReport.external_connectors = [...new Set([...(latestReport.external_connectors || []), imported.connector])];
    latestReport.ai_advice = null;
    latestReport.ai_context_sources = [];
    const levels = ['critical', 'high', 'medium', 'low', 'info'];
    latestReport.severity_counts = Object.fromEntries(levels.map((level) => [level, latestReport.findings.filter((finding) => finding.severity === level).length]));
    latestReport.risk_level = latestReport.severity_counts.critical || latestReport.severity_counts.high ? 'elevated' : latestReport.severity_counts.medium ? 'review' : 'informational';
    try {
      const refreshed = await fetch('/api/threat-model', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(latestReport) });
      if (refreshed.ok) Object.assign(latestReport, await refreshed.json());
    } catch (error) {
      console.warn('Could not refresh the threat model after import.', error);
    }
    renderReport(latestReport);
    const stats = imported.stats || {};
    const status = document.createElement('p');
    status.className = 'privacy-note';
    status.textContent = `${imported.connector}: ${stats.imported ?? imported.findings.length} findings imported` +
      `${stats.skipped_suppressed ? ` · ${stats.skipped_suppressed} suppressed ignored` : ''}` +
      `${stats.skipped_noise ? ` · ${stats.skipped_noise} out of scope` : ''}` +
      `${stats.truncated ? ' · list truncated at the limit' : ''}. Messages and code excerpts are not imported.`;
    results.querySelector('.report-actions')?.after(status);
  } catch (error) {
    errorBox.textContent = error.message || 'Error importing the external report.';
    errorBox.hidden = false;
  } finally {
    event.target.value = '';
  }
});

results.addEventListener('input', (event) => {
  if (event.target instanceof Element && event.target.matches('#finding-search')) filterFindings();
});
results.addEventListener('change', (event) => {
  if (event.target instanceof Element && event.target.matches('#severity-filter')) filterFindings();
  if (event.target instanceof Element && event.target.matches('.pentest-check input[type="checkbox"]')) {
    const panel = event.target.closest('[data-lazy="pentest"]');
    const checkedInputs = panel?.querySelectorAll('.pentest-check input:checked') || [];
    const completed = checkedInputs.length;
    const total = panel?.querySelectorAll('.pentest-check input').length || 0;
    const progress = panel?.querySelector('.pentest-progress');
    if (progress) progress.textContent = `${completed} of ${total} ${total === 1 ? 'check completed' : 'checks completed'} in this session.`;
    try {
      sessionStorage.setItem(panel?.dataset.checklistKey || '', JSON.stringify([...checkedInputs].map((input) => Number(input.dataset.checkIndex))));
    } catch (error) {
      console.warn('Could not save the in-session checklist state.', error);
    }
  }
});
results.addEventListener('toggle', (event) => {
  if (event.target instanceof HTMLDetailsElement && event.target.matches('.lazy-panel') && event.target.open) {
    renderLazyPanel(event.target);
  }
}, true);

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  results.hidden = true;
  submitButton.disabled = true;
  const directoryMode = form.dataset.mode === 'directory';
  submitButton.querySelector('span').textContent = directoryMode ? 'Analyzing project…' : 'Analyzing APK…';
  try {
    const payload = directoryMode ? new FormData() : new FormData(form);
    if (directoryMode) {
      const files = selectedDirectoryFiles();
      if (!directoryInput.files.length) throw new Error('First select the Android project folder.');
      if (!files.length) throw new Error('No platform files found (build.prop, *.te, *.rc, privapp-permissions*.xml, Android.bp, *.mk) in that folder.');
      if (files.length > 500) throw new Error(`${files.length} platform files is too many for the web interface. Select a device or vendor folder, or use the command line (aaos-audit --profile platform).`);
      payload.append('authorized', 'true');
      payload.append('profile', document.querySelector('#analysis-profile').value);
      payload.append('paths', JSON.stringify(files.map((file) => file.webkitRelativePath || file.name)));
      files.forEach((file) => payload.append('files', file, file.name));
    }
    const endpoint = directoryMode ? '/api/analyze-directory' : '/api/analyze';
    const response = await fetch(endpoint, { method: 'POST', body: payload });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || 'Could not analyze the APK.');
    renderReport(body);
  } catch (error) {
    errorBox.textContent = error.message || 'Server connection error.';
    errorBox.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.querySelector('span').textContent = directoryMode ? 'Analyze project' : 'Start analysis';
  }
});
