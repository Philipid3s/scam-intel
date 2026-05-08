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
const copyIocs = document.querySelector("#copy-iocs");
const exportCase = document.querySelector("#export-case");
const caseForm = document.querySelector("#case-form");
const evidenceDetails = document.querySelector("#evidence-details");
const indicatorSummary = document.querySelector("#indicator-summary");
const indicatorSummaryList = document.querySelector("#indicator-summary-list");

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

function valuesOnly(values = []) {
  return values
    .map((item) => typeof item === "object" ? item.value : item)
    .filter(Boolean);
}

function uniqueValues(values = []) {
  return [...new Set(valuesOnly(values))].sort((a, b) => a.localeCompare(b));
}

function formatIocText(result) {
  const source = result?.source || {};
  const groups = [
    ["Target", [result?.target?.normalized]],
    ["Wallets", source.cryptoWalletDetails || source.cryptoWallets],
    ["Emails", source.emails],
    ["Phones", source.phones],
    ["IP Addresses", [...(source.ips || []), result?.network?.primaryIp]],
    ["URLs", source.links],
    ["Form Actions", source.formActions],
    ["Social Handles", source.socialHandles],
  ];

  return groups
    .map(([label, values]) => {
      const entries = uniqueValues(values);
      if (!entries.length) {
        return "";
      }
      return `${label}:\n${entries.map((value) => `- ${value}`).join("\n")}`;
    })
    .filter(Boolean)
    .join("\n\n");
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

function renderIndicatorSummary(result) {
  const source = result.source || {};
  const groups = [
    ["Wallets", source.cryptoWalletDetails || source.cryptoWallets || []],
    ["Emails", source.emails || []],
    ["Phones", source.phones || []],
    ["Form actions", source.formActions || []],
    ["IP addresses", source.ips || []],
    ["Links", source.links || []],
    ["Social handles", source.socialHandles || []],
  ];
  const total = groups.reduce((count, [, values]) => count + values.length, 0);
  indicatorSummary.textContent = `${total} extracted indicator(s)`;
  indicatorSummaryList.innerHTML = groups.map(([label, values]) => {
    const preview = values
      .slice(0, 4)
      .map((item) => typeof item === "object" ? item.value : item)
      .map((value) => truncateMiddle(value, 20, 12));
    return `
      <article class="indicator-summary-card">
        <span>${escapeHtml(label)}</span>
        <strong>${values.length}</strong>
        <p>${preview.length ? escapeHtml(preview.join(" | ")) : "None found"}</p>
      </article>
    `;
  }).join("");
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
  renderIndicatorSummary(result);
  rawJson.textContent = JSON.stringify(result, null, 2);
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

copyIocs.addEventListener("click", async () => {
  if (!currentResult) {
    return;
  }
  const text = formatIocText(currentResult);
  if (!text) {
    statusLine.textContent = "No IOCs available to copy.";
    return;
  }
  await navigator.clipboard.writeText(text);
  copyIocs.textContent = "Copied";
  setTimeout(() => {
    copyIocs.textContent = "Copy IOCs";
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
  statusLine.textContent = "Export notes applied to current JSON.";
});
