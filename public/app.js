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
const reportPreview = document.querySelector("#report-preview");
const indicatorSummary = document.querySelector("#indicator-summary");
const indicatorSummaryList = document.querySelector("#indicator-summary-list");
const riskSummary = document.querySelector("#risk-summary");
const submitButton = form.querySelector('button[type="submit"]');
const tabButtons = [...document.querySelectorAll(".tab-button")];
const tabPanels = [...document.querySelectorAll(".tab-panel")];
const reportExport = window.ScamIntelReportExport;

let currentResult = null;

function activateTab(button) {
  for (const tabButton of tabButtons) {
    const isActive = tabButton === button;
    tabButton.classList.toggle("active", isActive);
    tabButton.setAttribute("aria-selected", String(isActive));
  }

  for (const panel of tabPanels) {
    const isActive = panel.id === button.getAttribute("aria-controls");
    panel.classList.toggle("active", isActive);
    panel.hidden = !isActive;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

const SEVERITY = {
  high: { rank: 0, label: "High", icon: "i-high" },
  medium: { rank: 1, label: "Medium", icon: "i-medium" },
  info: { rank: 2, label: "Info", icon: "i-info" },
};
const NO_RECORD_ERRORS = ["ENODATA", "ENOTFOUND"];

function icon(name, className = "icon") {
  return `<svg class="${className}" aria-hidden="true"><use href="#${name}"/></svg>`;
}

function severityOf(level) {
  return SEVERITY[level] || SEVERITY.info;
}

function setButtonLabel(button, text) {
  const label = button.querySelector(".label");
  (label || button).textContent = text;
}

function flashButton(button, text) {
  const original = button.querySelector(".label")?.textContent || button.textContent;
  setButtonLabel(button, text);
  button.classList.add("is-done");
  setTimeout(() => {
    setButtonLabel(button, original);
    button.classList.remove("is-done");
  }, 1200);
}

// Certificate subject/issuer arrive as objects such as {"CN":"x","O":"y"}.
function formatDistinguishedName(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  return Object.entries(value).map(([key, part]) => `${key}=${Array.isArray(part) ? part.join(" + ") : part}`).join(", ");
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

function getReportOptions() {
  return {
    includeIndicators: caseForm.elements.includeIndicators?.checked ?? true,
    includeNetworkEvidence: caseForm.elements.includeNetworkEvidence?.checked ?? true,
    includeRawProfiles: caseForm.elements.includeRawProfiles?.checked ?? true,
    redactVictimDetails: caseForm.elements.redactVictimDetails?.checked ?? false,
  };
}

function getRawReportNotes() {
  const notes = Object.fromEntries(new FormData(caseForm).entries());
  delete notes.includeIndicators;
  delete notes.includeNetworkEvidence;
  delete notes.includeRawProfiles;
  delete notes.redactVictimDetails;
  return notes;
}

function buildExportPayload(result) {
  return reportExport.buildExportPayload({
    result,
    notes: getRawReportNotes(),
    options: getReportOptions(),
  });
}

function renderReportPreview(result) {
  const payload = buildExportPayload(result);
  const notes = payload.report.notes;
  const evidence = payload.report.evidence;
  const indicators = evidence.indicators;
  const network = evidence.network;
  const hashes = evidence.hashes || {};

  reportPreview.innerHTML = `
    <div class="section-title-block">
      <h4>Report Preview</h4>
      <p>${escapeHtml(notes.title || result?.target?.normalized || "Untitled report")}</p>
    </div>
    <div class="preview-grid">
      <article>
        <span>Summary</span>
        <p>${escapeHtml(reportExport.summarizeSignals(evidence.signals))}</p>
      </article>
      <article>
        <span>Target</span>
        <p>${escapeHtml(result?.target?.normalized || "Not available")}</p>
      </article>
      <article>
        <span>Report Notes</span>
        <p>${escapeHtml([notes.scamCategory, notes.status, notes.jurisdiction].filter(Boolean).join(" | ") || "No report metadata added.")}</p>
      </article>
      <article>
        <span>Redaction</span>
        <p>${payload.report.redactions.victimDetails ? "Victim details redacted from report notes and raw profile case metadata." : "No report redaction enabled."}</p>
      </article>
      <article>
        <span>Indicators</span>
        <p>${indicators ? escapeHtml(`${indicators.wallets.length} wallet(s), ${indicators.emails.length} email(s), ${indicators.phones.length} phone(s), ${indicators.links.length} link(s)`) : "Excluded from export package."}</p>
      </article>
      <article>
        <span>Network Evidence</span>
        <p>${network ? escapeHtml([network.primaryIp, network.httpFinalUrl, network.tlsFingerprint].filter(Boolean).map((value) => truncateMiddle(value, 24, 14)).join(" | ") || "No network evidence available.") : "Excluded from export package."}</p>
      </article>
      <article>
        <span>Evidence Hashes</span>
        <p>${escapeHtml([hashes.result?.sha256, hashes.source?.sha256, hashes.httpHeaders?.sha256].filter(Boolean).map((value) => truncateMiddle(value, 16, 12)).join(" | ") || "No hashes available.")}</p>
      </article>
      <article>
        <span>Raw Profiles</span>
        <p>${payload.result ? "Included in export package." : "Excluded from export package."}</p>
      </article>
    </div>
  `;
}

function refreshReportPackage() {
  if (!currentResult) {
    return;
  }
  renderReportPreview(currentResult);
  rawJson.textContent = JSON.stringify(buildExportPayload(currentResult), null, 2);
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
    ["Exfiltration Endpoints", source.exfilEndpoints],
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

function sortedSignals(result) {
  return [...(result.signals || [])].sort((a, b) => severityOf(a.level).rank - severityOf(b.level).rank);
}

function renderRiskSummary(result) {
  const counts = { high: 0, medium: 0, info: 0 };
  for (const signal of result.signals || []) {
    counts[signal.level in counts ? signal.level : "info"] += 1;
  }
  const verdict = counts.high ? "high" : counts.medium ? "medium" : "low";
  const copy = {
    high: ["High risk", "Strong indicators of scam or phishing infrastructure. Treat as hostile and preserve evidence."],
    medium: ["Elevated risk", "Suspicious characteristics found. Review the signals below before drawing conclusions."],
    low: ["No strong indicators", "Local checks found nothing alarming. Continue with content and reputation review."],
  }[verdict];
  const lead = sortedSignals(result).filter((signal) => signal.level === "high").slice(0, 3).map((signal) => signal.title);

  riskSummary.className = `risk-summary risk-${verdict}`;
  riskSummary.innerHTML = `
    <div class="risk-verdict">
      ${icon(verdict === "low" ? "i-check" : severityOf(verdict).icon, "risk-icon")}
      <div>
        <strong>${escapeHtml(copy[0])}</strong>
        <p>${escapeHtml(lead.length ? `${copy[1]} Key findings: ${lead.join(", ")}.` : copy[1])}</p>
      </div>
    </div>
    <ul class="risk-counts" aria-label="Signal counts">
      ${["high", "medium", "info"].map((level) => `
        <li class="count-${level}${counts[level] ? "" : " is-zero"}"><strong>${counts[level]}</strong><span>${severityOf(level).label}</span></li>
      `).join("")}
    </ul>
  `;
}

function renderSignals(result) {
  signals.innerHTML = sortedSignals(result)
    .map((signal) => {
      const severity = severityOf(signal.level);
      return `
        <article class="signal ${escapeHtml(signal.level)}">
          <div class="signal-head">
            ${icon(severity.icon, "signal-icon")}
            <span class="severity-chip">${escapeHtml(severity.label)}</span>
          </div>
          <strong>${escapeHtml(signal.title)}</strong>
          <p>${escapeHtml(signal.detail)}</p>
        </article>
      `;
    })
    .join("");
}

function formatMx(record) {
  if (!record.ok || !Array.isArray(record.value) || !record.value.length || typeof record.value[0] !== "object") {
    return record;
  }
  const value = record.value.map((mx) => (mx.exchange === "." || !mx.exchange ? "Null MX (accepts no mail)" : `${mx.priority} ${mx.exchange}`));
  return { ...record, value };
}

// Resolver codes such as ENODATA just mean "no records"; show them as such.
function renderDnsValue(record) {
  const shown = record.label.startsWith("MX") ? formatMx(record) : record;
  if (shown.ok && shown.value?.length) {
    return `<code>${escapeHtml(formatValue(shown.value))}</code>`;
  }
  const text = shown.ok || NO_RECORD_ERRORS.includes(shown.error) ? "No records" : `Lookup failed (${shown.error})`;
  return `<span class="muted-value">${escapeHtml(text)}</span>`;
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
          ${renderDnsValue(record)}
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
    ["Subject", formatDistinguishedName(result.tls.subject)],
    ["Issuer", formatDistinguishedName(result.tls.issuer)],
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
    const label = { bitcoin: "BTC", ethereum: "ETH", tron: "TRON" }[chain] || "Explorer";
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

function renderMetadata(metadata) {
  if (!metadata) {
    return "";
  }
  const rows = [
    ["Title", metadata.title],
    ["Description", metadata.description],
    ["Canonical", metadata.canonicalUrl],
    ["Language", metadata.language],
    ["Generator", metadata.generator],
    ["Open Graph", [metadata.openGraph?.title, metadata.openGraph?.siteName].filter(Boolean).join(" | ")],
    ["Twitter Card", [metadata.twitter?.card, metadata.twitter?.title].filter(Boolean).join(" | ")],
    ["Favicon", metadata.faviconUrl],
  ].filter(([, value]) => value);

  if (!rows.length) {
    return "";
  }

  return `
    <section class="source-subsection">
      <h4>Page Metadata</h4>
      <dl class="compact-list">
        ${rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}
      </dl>
    </section>
  `;
}

function renderForms(forms = []) {
  if (!forms.length) {
    return "";
  }

  return `
    <section class="source-subsection">
      <h4>Forms</h4>
      <ul class="record-list form-intel-list">
        ${forms.map((form, index) => {
          const flags = [
            form.hasPassword ? "password" : null,
            form.hasOtp ? "OTP/code" : null,
            form.hasWalletSecret ? "wallet secret" : null,
            form.hasPaymentField ? "payment" : null,
            form.hiddenFieldCount ? `${form.hiddenFieldCount} hidden` : null,
          ].filter(Boolean);
          const inputs = (form.inputs || []).slice(0, 12).map((input) => {
            const label = [input.type, input.name || input.id || input.placeholder || input.tag].filter(Boolean).join(" | ");
            return `<span>${escapeHtml(label)} <em>${escapeHtml(input.classification)}</em></span>`;
          }).join("");
          return `
            <li>
              <span class="record-title">Form ${index + 1} | ${escapeHtml(form.method || "GET")}</span>
              <div><code>${escapeHtml(form.action || "No action")}</code></div>
              <p>${escapeHtml(`${form.inputCount || 0} field(s)${flags.length ? ` | ${flags.join(", ")}` : ""}`)}</p>
              ${inputs ? `<div class="form-field-list">${inputs}</div>` : ""}
            </li>
          `;
        }).join("")}
      </ul>
    </section>
  `;
}

function setCaseForm(result) {
  const data = result.case || {};
  for (const field of caseForm.elements) {
    if (!field.name) {
      continue;
    }
    if (field.type === "checkbox") {
      field.checked = data[field.name] ?? field.defaultChecked;
    } else if (field.tagName === "SELECT") {
      // An empty value matches no option and leaves the select blank.
      field.value = data[field.name] || field.options[0]?.value || "";
    } else {
      field.value = data[field.name] || "";
    }
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

  const exfil = (result.source.exfilEndpoints || []).map((endpoint) => `${endpoint.platform}: ${endpoint.value}`);
  const obfuscation = (result.source.scriptObfuscation || []).map((entry) => `${entry.technique} (${entry.count})`);
  const groups = [
    renderIndicatorGroup("Exfiltration endpoints", exfil, { kind: "exfil" }),
    renderIndicatorGroup("Script obfuscation", obfuscation),
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
    ${renderMetadata(result.source.metadata)}
    ${renderForms(result.source.forms)}
    ${groups ? `<ul class="record-list source-list">${groups}</ul>` : "<p>No emails, links, or IP addresses were found in the inspected source.</p>"}
  `;
}

function renderEvidence(result) {
  const artifacts = result.evidence?.artifacts || {};
  const collection = result.evidence?.collection || {};
  evidenceDetails.innerHTML = `
    <div class="evidence-grid">
      <dl class="compact-list">
        <dt>Tool</dt><dd>ScamIntel ${escapeHtml(collection.toolVersion || "")}</dd>
        <dt>Collected UTC</dt><dd>${escapeHtml(collection.collectedAtUtc || result.scannedAt)}</dd>
        <dt>Complete</dt><dd>${collection.timedOut ? "No, scan time limit reached" : "Yes"}</dd>
      </dl>
      <dl class="compact-list">
        <dt>Result SHA-256</dt><dd><code>${escapeHtml(artifacts.result?.sha256)}</code></dd>
        <dt>Source SHA-256</dt><dd><code>${escapeHtml(artifacts.source?.sha256)}</code></dd>
        <dt>Headers SHA-256</dt><dd><code>${escapeHtml(artifacts.httpHeaders?.sha256)}</code></dd>
      </dl>
    </div>
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
    ["Exfil endpoints", source.exfilEndpoints || []],
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
  renderRiskSummary(result);
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
  refreshReportPackage();
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

  submitButton.disabled = true;
  submitButton.classList.add("is-loading");
  setButtonLabel(submitButton, "Investigating");
  try {
    const result = await investigate(target);
    renderResult(result);
    statusLine.textContent = "Investigation complete.";
  } catch (error) {
    statusLine.textContent = error.message;
  } finally {
    submitButton.disabled = false;
    submitButton.classList.remove("is-loading");
    setButtonLabel(submitButton, "Investigate");
  }
});

for (const chip of document.querySelectorAll("[data-example]")) {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.example;
    form.requestSubmit();
  });
}

for (const tabButton of tabButtons) {
  tabButton.addEventListener("click", () => activateTab(tabButton));
}

copyJson.addEventListener("click", async () => {
  if (!currentResult) {
    return;
  }
  await navigator.clipboard.writeText(JSON.stringify(buildExportPayload(currentResult), null, 2));
  flashButton(copyJson, "Copied");
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
  flashButton(copyIocs, "Copied");
});

exportCase.addEventListener("click", () => {
  if (!currentResult) {
    return;
  }
  const blob = new Blob([JSON.stringify(buildExportPayload(currentResult), null, 2)], { type: "application/json" });
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
  const updates = { ...getRawReportNotes(), ...getReportOptions() };
  currentResult.case = { ...(currentResult.case || {}), ...updates };
  refreshReportPackage();
  flashButton(caseForm.querySelector('button[type="submit"]'), "Applied");
  statusLine.textContent = "Report export package updated.";
});

caseForm.addEventListener("input", refreshReportPackage);
caseForm.addEventListener("change", refreshReportPackage);
