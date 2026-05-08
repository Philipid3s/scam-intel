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
const caseForm = document.querySelector("#case-form");
const evidenceDetails = document.querySelector("#evidence-details");
const graphSummary = document.querySelector("#graph-summary");
const caseGraph = document.querySelector("#case-graph");
const graphNodeDetails = document.querySelector("#graph-node-details");

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

function truncateMiddle(value, start = 18, end = 12) {
  const text = String(value || "");
  if (text.length <= start + end + 3) {
    return text;
  }
  return `${text.slice(0, start)}...${text.slice(-end)}`;
}

function renderIndicatorGroup(title, values, options = {}) {
  if (!values?.length) {
    return "";
  }

  const renderValue = (item) => {
    const value = typeof item === "object" ? item.value : item;
    const text = escapeHtml(value);
    const chain = typeof item === "object" ? item.chain : null;
    const addressType = typeof item === "object" ? item.addressType : null;
    const href = typeof item === "object" ? item.explorerUrl : (/^0x[a-fA-F0-9]{40}$/.test(value) ? `https://etherscan.io/address/${encodeURIComponent(value)}` : null);
    const label = chain === "bitcoin" ? "BTC" : chain === "ethereum" ? "ETH" : "Explorer";
    const displayText = options.compact ? escapeHtml(truncateMiddle(value)) : text;
    const meta = [label, addressType].filter(Boolean).join(" | ");
    if (href) {
      return `<a class="indicator-link" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" title="${text}"><code>${displayText}</code><span>${escapeHtml(meta)}</span></a>`;
    }
    return `<code title="${text}">${displayText}</code>`;
  };

  const isLong = values.length > (options.openLimit || 8);
  const openAttribute = isLong ? "" : " open";
  const preview = values.slice(0, 3).map((item) => typeof item === "object" ? item.value : item).map((value) => truncateMiddle(value, 14, 8)).join(" | ");

  return `
    <li class="indicator-group ${options.kind ? `indicator-group-${escapeHtml(options.kind)}` : ""}">
      <details${openAttribute}>
        <summary>
          <span class="record-title">${escapeHtml(title)}</span>
          <span class="indicator-count">${values.length}</span>
          ${isLong ? `<span class="indicator-preview">${escapeHtml(preview)}</span>` : ""}
        </summary>
        <div class="indicator-list ${options.compact ? "indicator-list-compact" : ""}">
          ${values.map(renderValue).join("")}
        </div>
      </details>
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
    renderIndicatorGroup("Crypto wallets", result.source.cryptoWalletDetails || result.source.cryptoWallets, { compact: true, kind: "wallets", openLimit: 5 }),
    renderIndicatorGroup("Emails", result.source.emails, { compact: true }),
    renderIndicatorGroup("Phone numbers", result.source.phones, { compact: true }),
    renderIndicatorGroup("Social handles", result.source.socialHandles, { compact: true }),
    renderIndicatorGroup("IP addresses", result.source.ips, { compact: true }),
    renderIndicatorGroup("Form actions", result.source.formActions, { compact: true }),
    renderIndicatorGroup("Links", result.source.links, { compact: true, kind: "links", openLimit: 5 }),
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
        <dt>Case</dt><dd>${escapeHtml(result.case?.caseNumber || result.caseId || "Unsaved scan")}</dd>
        <dt>Scan ID</dt><dd>${escapeHtml(result.scanId || scans[0]?.id || "Not persisted")}</dd>
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

function renderResult(result) {
  currentResult = result;
  emptyState.classList.add("hidden");
  results.classList.remove("hidden");
  resultTitle.textContent = result.target.normalized;
  resultMeta.textContent = `Unsaved scan | Scanned ${new Date(result.scannedAt).toLocaleString()} as ${result.target.type.toUpperCase()}`;

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
  renderGraph({ nodes: [], edges: [] });
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
    statusLine.textContent = "Investigation complete.";
  } catch (error) {
    statusLine.textContent = error.message;
  } finally {
    form.querySelector("button").disabled = false;
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
  if (!currentResult) {
    return;
  }
  const blob = new Blob([JSON.stringify({
    exportedAt: new Date().toISOString(),
    tool: { name: "ScamIntel" },
    result: currentResult,
  }, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `scamintel-scan-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

caseForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!currentResult) {
    statusLine.textContent = "Run an investigation first.";
    return;
  }
  const updates = Object.fromEntries(new FormData(caseForm).entries());
  currentResult.case = { ...(currentResult.case || {}), ...updates };
  rawJson.textContent = JSON.stringify(currentResult, null, 2);
  statusLine.textContent = "Applied to the current scan.";
});
