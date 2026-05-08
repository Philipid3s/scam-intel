const form = document.querySelector("#investigation-form");
const input = document.querySelector("#target-input");
const statusLine = document.querySelector("#form-status");
const emptyState = document.querySelector("#empty-state");
const results = document.querySelector("#results");
const resultTitle = document.querySelector("#result-title");
const resultMeta = document.querySelector("#result-meta");
const signals = document.querySelector("#signals");
const identityList = document.querySelector("#identity-list");
const httpDetails = document.querySelector("#http-details");
const dnsDetails = document.querySelector("#dns-details");
const tlsDetails = document.querySelector("#tls-details");
const sourceDetails = document.querySelector("#source-details");
const rawJson = document.querySelector("#raw-json");
const copyJson = document.querySelector("#copy-json");
const exportCase = document.querySelector("#export-case");
const historyList = document.querySelector("#history-list");
const clearHistory = document.querySelector("#clear-history");
const caseForm = document.querySelector("#case-form");
const evidenceDetails = document.querySelector("#evidence-details");
const graphSummary = document.querySelector("#graph-summary");
const caseGraph = document.querySelector("#case-graph");
const graphNodeDetails = document.querySelector("#graph-node-details");
const globalGraphButton = document.querySelector("#global-graph-button");
const pivotList = document.querySelector("#pivot-list");

let currentResult = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") {
    return "Not available";
  }
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : "None";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

async function loadHistory() {
  const response = await fetch("/api/cases");
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Unable to load cases.");
  }
  return data.cases;
}

async function renderHistory() {
  let items = [];
  try {
    items = await loadHistory();
  } catch (error) {
    historyList.innerHTML = `<p class="status-line">${escapeHtml(error.message)}</p>`;
    return;
  }

  if (!items.length) {
    historyList.innerHTML = `<p class="status-line">No saved cases yet.</p>`;
    return;
  }

  historyList.innerHTML = items
    .map((item) => `
      <button class="history-item" type="button" data-id="${item.id}">
        <strong>${escapeHtml(item.caseNumber || `Case ${item.id}`)}</strong>
        <span>${escapeHtml(item.normalizedTarget)}</span>
        <span>${escapeHtml(item.riskLevel.toUpperCase())} | ${escapeHtml(item.status || "open")} | ${escapeHtml(new Date(item.scannedAt).toLocaleString())}</span>
      </button>
    `)
    .join("");
}

async function loadCase(id) {
  const response = await fetch(`/api/cases/${id}`);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Unable to load case.");
  }
  return data;
}

async function loadGraph(id) {
  const response = await fetch(`/api/cases/${id}/graph`);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Unable to load graph.");
  }
  return data;
}

async function loadGlobalGraph() {
  const response = await fetch("/api/graph");
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Unable to load global graph.");
  }
  return data;
}

async function loadPivots() {
  const response = await fetch("/api/pivots");
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Unable to load IOC pivots.");
  }
  return data.pivots;
}

async function loadPivotCases(nodeId) {
  const response = await fetch(`/api/pivots/${nodeId}/cases`);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Unable to load pivot cases.");
  }
  return data.cases;
}

function renderDefinitionList(node, entries) {
  node.innerHTML = entries
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(formatValue(value))}</dd>`)
    .join("");
}

function renderSignals(result) {
  signals.innerHTML = result.signals
    .map((signal) => `
      <article class="signal ${escapeHtml(signal.level)}">
        <strong>${escapeHtml(signal.title)}</strong>
        <p>${escapeHtml(signal.detail)}</p>
      </article>
    `)
    .join("");
}

function renderDns(result) {
  const records = Object.values(result.dns || {});
  if (!records.length) {
    dnsDetails.innerHTML = "<p>No DNS profile available.</p>";
    return;
  }

  dnsDetails.innerHTML = `
    <ul class="record-list">
      ${records.map((record) => `
        <li>
          <span class="record-title">${escapeHtml(record.label)}</span>
          <code>${escapeHtml(record.ok ? formatValue(record.value) : record.error)}</code>
        </li>
      `).join("")}
    </ul>
  `;
}

function renderHttp(result) {
  if (!result.http) {
    httpDetails.innerHTML = "<p>HTTP checks are only available for URLs.</p>";
    return;
  }

  httpDetails.innerHTML = `
    <ul class="redirect-list">
      ${result.http.chain.map((hop, index) => `
        <li>
          <span class="record-title">Hop ${index + 1}</span>
          <div><code>${escapeHtml(hop.url)}</code></div>
          <div>${escapeHtml(hop.ok ? `${hop.statusCode} ${hop.statusMessage || ""}` : hop.error)}</div>
          <div>${escapeHtml(`${hop.elapsedMs} ms`)}</div>
          ${hop.location ? `<div>Location: <code>${escapeHtml(hop.location)}</code></div>` : ""}
        </li>
      `).join("")}
    </ul>
  `;
}

function renderTls(result) {
  if (!result.tls) {
    tlsDetails.innerHTML = "<p>TLS checks are only available for HTTPS URLs.</p>";
    return;
  }
  if (!result.tls.ok) {
    tlsDetails.innerHTML = `<p>${escapeHtml(result.tls.error || "No certificate returned.")}</p>`;
    return;
  }

  tlsDetails.innerHTML = "<dl></dl>";
  renderDefinitionList(tlsDetails.querySelector("dl"), [
    ["Authorized", result.tls.authorized ? "Yes" : "No"],
    ["Auth issue", result.tls.authorizationError],
    ["Subject", result.tls.subject],
    ["Issuer", result.tls.issuer],
    ["Valid from", result.tls.validFrom],
    ["Valid to", result.tls.validTo],
    ["SHA-256", result.tls.fingerprint256],
    ["SAN", result.tls.subjectAltName],
  ]);
}

function renderIndicatorGroup(title, values) {
  if (!values?.length) {
    return "";
  }

  const renderValue = (item) => {
    const value = typeof item === "object" ? item.value : item;
    const text = escapeHtml(value);
    const chain = typeof item === "object" ? item.chain : null;
    const href = typeof item === "object" ? item.explorerUrl : (/^0x[a-fA-F0-9]{40}$/.test(value) ? `https://etherscan.io/address/${encodeURIComponent(value)}` : null);
    const label = chain === "bitcoin" ? "BTC" : chain === "ethereum" ? "ETH" : "Explorer";
    if (href) {
      return `<a class="indicator-link" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer"><code>${text}</code><span>${escapeHtml(label)}</span></a>`;
    }
    return `<code>${text}</code>`;
  };

  return `
    <li>
      <span class="record-title">${escapeHtml(title)} (${values.length})</span>
      <div class="indicator-list">
        ${values.map(renderValue).join("")}
      </div>
    </li>
  `;
}

function setCaseForm(result) {
  const data = result.case || {};
  for (const field of caseForm.elements) {
    if (!field.name) {
      continue;
    }
    field.value = data[field.name] || "";
  }
}

function renderSource(result) {
  if (!result.source) {
    sourceDetails.innerHTML = "<p>Page source extraction is only available for URLs.</p>";
    return;
  }
  if (!result.source.ok) {
    sourceDetails.innerHTML = `<p>${escapeHtml(result.source.error || "No page source was available.")}</p>`;
    return;
  }

  const groups = [
    renderIndicatorGroup("Emails", result.source.emails),
    renderIndicatorGroup("Links", result.source.links),
    renderIndicatorGroup("IP addresses", result.source.ips),
    renderIndicatorGroup("Phone numbers", result.source.phones),
    renderIndicatorGroup("Crypto wallets", result.source.cryptoWalletDetails || result.source.cryptoWallets),
    renderIndicatorGroup("Social handles", result.source.socialHandles),
    renderIndicatorGroup("Form actions", result.source.formActions),
  ].join("");

  sourceDetails.innerHTML = `
    <dl class="compact-list">
      <dt>URL</dt><dd>${escapeHtml(result.source.url)}</dd>
      <dt>Inspected</dt><dd>${escapeHtml(`${result.source.bytesInspected} bytes${result.source.truncated ? " (truncated)" : ""}`)}</dd>
    </dl>
    ${groups ? `<ul class="record-list source-list">${groups}</ul>` : "<p>No emails, links, or IP addresses were found in the inspected source.</p>"}
  `;
}

function renderEvidence(result) {
  const artifacts = result.evidence?.artifacts || {};
  const scans = result.scans || [];
  const auditLog = result.auditLog || [];
  evidenceDetails.innerHTML = `
    <div class="evidence-grid">
      <dl class="compact-list">
        <dt>Case</dt><dd>${escapeHtml(result.case?.caseNumber || result.caseId || "Not assigned")}</dd>
        <dt>Scan ID</dt><dd>${escapeHtml(result.scanId || scans[0]?.id || "Not available")}</dd>
        <dt>Tool</dt><dd>Sniffer ${escapeHtml(result.evidence?.collection?.toolVersion || "")}</dd>
        <dt>Collected UTC</dt><dd>${escapeHtml(result.evidence?.collection?.collectedAtUtc || result.scannedAt)}</dd>
      </dl>
      <dl class="compact-list">
        <dt>Result SHA-256</dt><dd><code>${escapeHtml(artifacts.result?.sha256 || scans[0]?.resultSha256)}</code></dd>
        <dt>Source SHA-256</dt><dd><code>${escapeHtml(artifacts.source?.sha256 || scans[0]?.sourceSha256)}</code></dd>
        <dt>Headers SHA-256</dt><dd><code>${escapeHtml(artifacts.httpHeaders?.sha256 || scans[0]?.headersSha256)}</code></dd>
      </dl>
    </div>
    ${scans.length ? `<h4>Scan Versions</h4><ul class="record-list">${scans.map((scan) => `
      <li><span class="record-title">Scan ${escapeHtml(scan.id)} | ${escapeHtml(scan.riskLevel)}</span><code>${escapeHtml(scan.scannedAt)}</code></li>
    `).join("")}</ul>` : ""}
    ${auditLog.length ? `<h4>Audit Log</h4><ul class="record-list">${auditLog.map((entry) => `
      <li><span class="record-title">${escapeHtml(entry.action)}</span><code>${escapeHtml(entry.createdAt)}</code></li>
    `).join("")}</ul>` : ""}
  `;
}

function nodeColor(node) {
  if (node.riskLevel === "high") {
    return "#b42318";
  }
  if (node.riskLevel === "medium") {
    return "#a65f00";
  }
  const colors = {
    case: "#17212b",
    url: "#255e9c",
    domain: "#0d6b71",
    ip: "#594a9a",
    email: "#26734d",
    phone: "#7a4b18",
    crypto_wallet: "#8a3ffc",
    social_handle: "#006d77",
    form_action: "#9a3412",
    tls_certificate: "#536471",
    nameserver: "#536471",
    mail_server: "#536471",
  };
  return colors[node.type] || "#536471";
}

function graphLayout(nodes, width, height) {
  const center = { x: width / 2, y: height / 2 };
  if (!nodes.length) {
    return new Map();
  }
  const byType = nodes.reduce((groups, node) => {
    groups[node.type] = groups[node.type] || [];
    groups[node.type].push(node);
    return groups;
  }, {});
  const ordered = Object.entries(byType).flatMap(([, group]) => group);
  const positions = new Map();
  const caseNode = nodes.find((node) => node.type === "case") || ordered[0];
  positions.set(caseNode.id, center);
  const others = ordered.filter((node) => node.id !== caseNode.id);
  const radius = Math.min(width, height) * 0.35;
  others.forEach((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(others.length, 1) - Math.PI / 2;
    const ring = radius + (index % 3) * 28;
    positions.set(node.id, {
      x: center.x + Math.cos(angle) * ring,
      y: center.y + Math.sin(angle) * ring,
    });
  });
  return positions;
}

function renderGraphDetails(node) {
  if (!node) {
    graphNodeDetails.innerHTML = "<p>Select a graph node to inspect its value and first/last seen timestamps.</p>";
    return;
  }
  graphNodeDetails.innerHTML = `
    <dl class="compact-list">
      <dt>Type</dt><dd>${escapeHtml(node.type)}</dd>
      <dt>Risk</dt><dd>${escapeHtml(node.riskLevel)}</dd>
      <dt>Value</dt><dd><code>${escapeHtml(node.value)}</code></dd>
      <dt>First seen</dt><dd>${escapeHtml(node.firstSeen)}</dd>
      <dt>Last seen</dt><dd>${escapeHtml(node.lastSeen)}</dd>
    </dl>
  `;
}

function renderGraph(graph, scope = "Case") {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  graphSummary.textContent = `${scope}: ${nodes.length} node(s), ${edges.length} relationship(s)`;
  if (!nodes.length) {
    caseGraph.innerHTML = "<p>No graph relationships have been recorded for this case yet.</p>";
    renderGraphDetails(null);
    return;
  }

  const width = 920;
  const height = 430;
  const positions = graphLayout(nodes, width, height);
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const edgeMarkup = edges.map((edge) => {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) {
      return "";
    }
    const midX = (source.x + target.x) / 2;
    const midY = (source.y + target.y) / 2;
    return `
      <g>
        <line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" class="graph-edge"></line>
        <text x="${midX}" y="${midY}" class="graph-edge-label">${escapeHtml(edge.relationship)}</text>
      </g>
    `;
  }).join("");

  const nodeMarkup = nodes.map((node) => {
    const position = positions.get(node.id);
    const radius = node.type === "case" ? 26 : 20;
    return `
      <g class="graph-node" data-node-id="${node.id}" transform="translate(${position.x} ${position.y})">
        <circle r="${radius}" fill="${nodeColor(node)}"></circle>
        <text y="${radius + 15}" text-anchor="middle">${escapeHtml(node.label)}</text>
        <title>${escapeHtml(`${node.type}: ${node.value}`)}</title>
      </g>
    `;
  }).join("");

  caseGraph.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Case relationship graph">
      ${edgeMarkup}
      ${nodeMarkup}
    </svg>
  `;
  renderGraphDetails(nodes.find((node) => node.type === "case") || nodes[0]);

  caseGraph.querySelectorAll(".graph-node").forEach((nodeElement) => {
    nodeElement.addEventListener("click", () => {
      const node = nodeById.get(Number(nodeElement.dataset.nodeId));
      renderGraphDetails(node);
    });
  });
}

async function renderPivots() {
  let pivots = [];
  try {
    pivots = await loadPivots();
  } catch (error) {
    pivotList.innerHTML = `<p class="status-line">${escapeHtml(error.message)}</p>`;
    return;
  }
  if (!pivots.length) {
    pivotList.innerHTML = `<p class="status-line">No reused indicators yet.</p>`;
    return;
  }
  pivotList.innerHTML = pivots.map((pivot) => `
    <button class="pivot-item" type="button" data-node-id="${pivot.nodeId}">
      <strong>${escapeHtml(pivot.label)}</strong>
      <span>${escapeHtml(pivot.type)} | ${pivot.caseCount} case(s) | ${pivot.edgeCount} link(s)</span>
    </button>
  `).join("");
}

function renderResult(result) {
  currentResult = result;
  emptyState.classList.add("hidden");
  results.classList.remove("hidden");
  resultTitle.textContent = result.target.normalized;
  resultMeta.textContent = `${result.case?.caseNumber || `Case ${result.caseId || "new"}`} | Scanned ${new Date(result.scannedAt).toLocaleString()} as ${result.target.type.toUpperCase()}`;

  setCaseForm(result);
  renderSignals(result);
  renderDefinitionList(identityList, [
    ["Input", result.target.input],
    ["Type", result.target.type],
    ["Host", result.target.host],
    ["Unicode host", result.domain?.unicode],
    ["Registered", result.domain?.registeredDomain],
    ["Subdomain", result.domain?.subdomain],
    ["Path", result.target.path],
    ["Protocol", result.target.protocol],
    ["Port", result.target.port],
    ["Primary IP", result.network?.primaryIp],
    ["IP network", result.ipRdap?.name],
    ["IP range", result.ipRdap?.startAddress && result.ipRdap?.endAddress ? `${result.ipRdap.startAddress} - ${result.ipRdap.endAddress}` : null],
    ["IP country", result.ipRdap?.country],
    ["IP entities", result.ipRdap?.entities],
  ]);
  renderHttp(result);
  renderDns(result);
  renderTls(result);
  renderSource(result);
  renderEvidence(result);
  rawJson.textContent = JSON.stringify(result, null, 2);
  if (result.caseId) {
    loadGraph(result.caseId)
      .then(renderGraph)
      .catch((error) => {
        graphSummary.textContent = "";
        caseGraph.innerHTML = `<p>${escapeHtml(error.message)}</p>`;
        renderGraphDetails(null);
      });
  } else {
    renderGraph({ nodes: [], edges: [] });
  }
}

async function investigate(target) {
  statusLine.textContent = "Investigating target...";
  const response = await fetch("/api/investigate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target }),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Investigation failed.");
  }
  return data;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = input.value.trim();
  if (!target) {
    return;
  }

  form.querySelector("button").disabled = true;
  try {
    const result = await investigate(target);
    renderResult(result);
    await renderHistory();
    await renderPivots();
    statusLine.textContent = "Investigation complete.";
  } catch (error) {
    statusLine.textContent = error.message;
  } finally {
    form.querySelector("button").disabled = false;
  }
});

historyList.addEventListener("click", async (event) => {
  const button = event.target.closest(".history-item");
  if (!button) {
    return;
  }
  try {
    const item = await loadCase(button.dataset.id);
    renderResult(item);
    statusLine.textContent = "Case loaded.";
  } catch (error) {
    statusLine.textContent = error.message;
  }
});

clearHistory.addEventListener("click", async () => {
  const response = await fetch("/api/cases", { method: "DELETE" });
  if (response.ok) {
    await renderHistory();
    await renderPivots();
    emptyState.classList.remove("hidden");
    results.classList.add("hidden");
    currentResult = null;
    statusLine.textContent = "Cases cleared.";
  } else {
    statusLine.textContent = "Unable to clear cases.";
  }
});

globalGraphButton.addEventListener("click", async () => {
  try {
    const graph = await loadGlobalGraph();
    emptyState.classList.add("hidden");
    results.classList.remove("hidden");
    resultTitle.textContent = "Global Intelligence Graph";
    resultMeta.textContent = "All stored case relationships";
    signals.innerHTML = "";
    caseForm.reset();
    identityList.innerHTML = "";
    httpDetails.innerHTML = "<p>Select a case to view HTTP evidence.</p>";
    dnsDetails.innerHTML = "<p>Select a case to view DNS evidence.</p>";
    tlsDetails.innerHTML = "<p>Select a case to view TLS evidence.</p>";
    sourceDetails.innerHTML = "<p>Select a case to view source extracts.</p>";
    evidenceDetails.innerHTML = "<p>Select a case to view scan hashes and audit entries.</p>";
    rawJson.textContent = JSON.stringify(graph, null, 2);
    renderGraph(graph, "Global");
    statusLine.textContent = "Global graph loaded.";
  } catch (error) {
    statusLine.textContent = error.message;
  }
});

pivotList.addEventListener("click", async (event) => {
  const button = event.target.closest(".pivot-item");
  if (!button) {
    return;
  }
  try {
    const cases = await loadPivotCases(button.dataset.nodeId);
    graphNodeDetails.innerHTML = `
      <h4>Seen In Cases</h4>
      <ul class="record-list">
        ${cases.map((item) => `
          <li>
            <span class="record-title">${escapeHtml(item.caseNumber || `Case ${item.id}`)} | ${escapeHtml(item.riskLevel)}</span>
            <button class="inline-case-link" type="button" data-case-id="${item.id}">${escapeHtml(item.normalizedTarget)}</button>
          </li>
        `).join("")}
      </ul>
    `;
    statusLine.textContent = "Pivot cases loaded.";
  } catch (error) {
    statusLine.textContent = error.message;
  }
});

graphNodeDetails.addEventListener("click", async (event) => {
  const button = event.target.closest(".inline-case-link");
  if (!button) {
    return;
  }
  try {
    const item = await loadCase(button.dataset.caseId);
    renderResult(item);
    statusLine.textContent = "Case loaded.";
  } catch (error) {
    statusLine.textContent = error.message;
  }
});

copyJson.addEventListener("click", async () => {
  if (!currentResult) {
    return;
  }
  await navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2));
  copyJson.textContent = "Copied";
  setTimeout(() => {
    copyJson.textContent = "Copy JSON";
  }, 1200);
});

exportCase.addEventListener("click", () => {
  if (!currentResult?.caseId) {
    return;
  }
  window.location.href = `/api/cases/${currentResult.caseId}/export`;
});

caseForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!currentResult?.caseId) {
    return;
  }
  const updates = Object.fromEntries(new FormData(caseForm).entries());
  const response = await fetch(`/api/cases/${currentResult.caseId}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(updates),
  });
  const data = await response.json();
  if (!response.ok) {
    statusLine.textContent = data.error || "Unable to save metadata.";
    return;
  }
  renderResult(data);
  await renderHistory();
  statusLine.textContent = "Case metadata saved.";
});

renderHistory();
renderPivots();
