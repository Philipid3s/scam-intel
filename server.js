const dns = require("node:dns").promises;
const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const path = require("node:path");
const tls = require("node:tls");
const { URL, domainToUnicode } = require("node:url");
const fs = require("node:fs/promises");
const { DatabaseSync } = require("node:sqlite");
const psl = require("psl");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "sniffer.sqlite");
const MAX_REDIRECTS = 6;
const REQUEST_TIMEOUT_MS = 8000;
const MAX_SOURCE_BYTES = 512 * 1024;
const TOOL_VERSION = "0.4.0";
const RDAP_BOOTSTRAP_URLS = {
  dns: "https://data.iana.org/rdap/dns.json",
  ipv4: "https://data.iana.org/rdap/ipv4.json",
  ipv6: "https://data.iana.org/rdap/ipv6.json",
};
const rdapBootstrapCache = new Map();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

let db;

async function initDatabase() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  db = new DatabaseSync(DB_PATH);
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      normalized_target TEXT NOT NULL UNIQUE,
      target_type TEXT NOT NULL,
      risk_level TEXT NOT NULL,
      scanned_at TEXT NOT NULL,
      result_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cases_scanned_at ON cases(scanned_at DESC);
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL,
      scanned_at TEXT NOT NULL,
      risk_level TEXT NOT NULL,
      result_json TEXT NOT NULL,
      result_sha256 TEXT NOT NULL,
      source_sha256 TEXT,
      headers_sha256 TEXT,
      FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_scans_case_id ON scans(case_id, scanned_at DESC);
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER,
      scan_id INTEGER,
      action TEXT NOT NULL,
      created_at TEXT NOT NULL,
      detail_json TEXT,
      FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE,
      FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_audit_case_id ON audit_log(case_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS graph_nodes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      node_type TEXT NOT NULL,
      value TEXT NOT NULL,
      label TEXT NOT NULL,
      risk_level TEXT NOT NULL DEFAULT 'info',
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      UNIQUE(node_type, value)
    );
    CREATE INDEX IF NOT EXISTS idx_graph_nodes_type_value ON graph_nodes(node_type, value);
    CREATE TABLE IF NOT EXISTS graph_edges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_node_id INTEGER NOT NULL,
      target_node_id INTEGER NOT NULL,
      relationship TEXT NOT NULL,
      case_id INTEGER NOT NULL,
      scan_id INTEGER NOT NULL,
      evidence_ref TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(source_node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
      FOREIGN KEY(target_node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
      FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE,
      FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_graph_edges_case_id ON graph_edges(case_id, scan_id);
  `);
  ensureCaseColumns();
}

function ensureCaseColumns() {
  const existing = new Set(db.prepare("PRAGMA table_info(cases)").all().map((column) => column.name));
  const columns = [
    ["case_number", "TEXT"],
    ["title", "TEXT"],
    ["status", "TEXT NOT NULL DEFAULT 'open'"],
    ["scam_category", "TEXT"],
    ["examiner", "TEXT"],
    ["source_of_report", "TEXT"],
    ["victim", "TEXT"],
    ["loss_amount", "TEXT"],
    ["jurisdiction", "TEXT"],
    ["notes", "TEXT"],
    ["created_at", "TEXT"],
    ["updated_at", "TEXT"],
  ];

  for (const [name, definition] of columns) {
    if (!existing.has(name)) {
      db.exec(`ALTER TABLE cases ADD COLUMN ${name} ${definition}`);
    }
  }
  db.exec("UPDATE cases SET created_at = COALESCE(created_at, scanned_at), updated_at = COALESCE(updated_at, scanned_at), case_number = COALESCE(case_number, 'SNF-' || printf('%06d', id))");
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function httpsJson(urlText) {
  return new Promise((resolve) => {
    const url = new URL(urlText);
    const req = https.request(
      url,
      {
        method: "GET",
        timeout: REQUEST_TIMEOUT_MS,
        headers: {
          "user-agent": "ScamIntel/0.4 (+local investigation tool)",
          accept: "application/rdap+json, application/json;q=0.9, */*;q=0.1",
        },
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size <= 1024 * 1024) {
            chunks.push(chunk);
          } else {
            req.destroy(new Error("JSON response byte limit reached"));
          }
        });
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          try {
            resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, statusCode: res.statusCode, json: JSON.parse(text) });
          } catch (error) {
            resolve({ ok: false, statusCode: res.statusCode, error: error.message });
          }
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("RDAP request timed out")));
    req.on("error", (error) => resolve({ ok: false, error: error.code || error.message }));
    req.end();
  });
}

function getRiskLevel(signals) {
  if (signals.some((signal) => signal.level === "high")) {
    return "high";
  }
  if (signals.some((signal) => signal.level === "medium")) {
    return "medium";
  }
  return "info";
}

function sha256(value) {
  return crypto.createHash("sha256").update(value || "", "utf8").digest("hex");
}

function logAudit(caseId, scanId, action, detail = {}) {
  db.prepare("INSERT INTO audit_log (case_id, scan_id, action, created_at, detail_json) VALUES (?, ?, ?, ?, ?)")
    .run(caseId || null, scanId || null, action, new Date().toISOString(), JSON.stringify(detail));
}

function graphLabel(type, value) {
  if (type === "case") {
    return value;
  }
  if (value.length <= 54) {
    return value;
  }
  return `${value.slice(0, 26)}...${value.slice(-22)}`;
}

function upsertGraphNode(type, value, riskLevel = "info") {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return null;
  }
  const now = new Date().toISOString();
  const row = db.prepare(`
    INSERT INTO graph_nodes (node_type, value, label, risk_level, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(node_type, value) DO UPDATE SET
      label = excluded.label,
      risk_level = CASE
        WHEN graph_nodes.risk_level = 'high' OR excluded.risk_level = 'high' THEN 'high'
        WHEN graph_nodes.risk_level = 'medium' OR excluded.risk_level = 'medium' THEN 'medium'
        ELSE excluded.risk_level
      END,
      last_seen = excluded.last_seen
    RETURNING id
  `).get(type, normalized, graphLabel(type, normalized), riskLevel, now, now);
  return row.id;
}

function addGraphEdge(sourceId, targetId, relationship, caseId, scanId, evidenceRef = null) {
  if (!sourceId || !targetId) {
    return;
  }
  db.prepare(`
    INSERT INTO graph_edges (source_node_id, target_node_id, relationship, case_id, scan_id, evidence_ref, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(sourceId, targetId, relationship, caseId, scanId, evidenceRef, new Date().toISOString());
}

function dnsValues(record) {
  return record?.ok && Array.isArray(record.value) ? record.value : [];
}

function buildCaseGraph(result, caseId, scanId, riskLevel) {
  const caseNode = upsertGraphNode("case", result.case?.caseNumber || `Case ${caseId}`, riskLevel);
  const targetNode = upsertGraphNode(result.target.type, result.target.normalized, riskLevel);
  addGraphEdge(caseNode, targetNode, "targets", caseId, scanId, "target");

  const host = result.target.host;
  let domainNode = null;
  if (host && !net.isIP(host)) {
    domainNode = upsertGraphNode("domain", host, riskLevel);
    addGraphEdge(targetNode, domainNode, "uses domain", caseId, scanId, "target.host");
  }

  for (const ip of [...dnsValues(result.dns?.A), ...dnsValues(result.dns?.AAAA), ...dnsValues(result.dns?.IP)]) {
    const ipNode = upsertGraphNode("ip", ip, riskLevel);
    addGraphEdge(domainNode || targetNode, ipNode, "resolves to", caseId, scanId, "dns");
  }

  for (const ns of dnsValues(result.dns?.NS)) {
    const nsNode = upsertGraphNode("nameserver", ns, "info");
    addGraphEdge(domainNode || targetNode, nsNode, "uses nameserver", caseId, scanId, "dns.NS");
  }

  if (result.rdap?.ok) {
    const rdapNode = upsertGraphNode("rdap_domain", result.rdap.domain, result.rdap.ageDays !== null && result.rdap.ageDays < 30 ? "medium" : "info");
    addGraphEdge(domainNode || targetNode, rdapNode, "has rdap record", caseId, scanId, "rdap");
    if (result.rdap.registrar) {
      const registrarNode = upsertGraphNode("registrar", result.rdap.registrar, "info");
      addGraphEdge(rdapNode, registrarNode, "registered through", caseId, scanId, "rdap.registrar");
    }
    for (const ns of result.rdap.nameservers || []) {
      const nsNode = upsertGraphNode("nameserver", ns, "info");
      addGraphEdge(rdapNode, nsNode, "rdap nameserver", caseId, scanId, "rdap.nameservers");
    }
  }

  if (result.ipRdap?.ok) {
    const ipNode = upsertGraphNode("ip", result.ipRdap.ip, riskLevel);
    addGraphEdge(domainNode || targetNode, ipNode, "uses primary ip", caseId, scanId, "ipRdap.ip");
    const networkLabel = result.ipRdap.name || result.ipRdap.handle;
    if (networkLabel) {
      const networkNode = upsertGraphNode("network", networkLabel, "info");
      addGraphEdge(ipNode, networkNode, "allocated to", caseId, scanId, "ipRdap.name");
    }
    for (const entity of result.ipRdap.entities || []) {
      const orgNode = upsertGraphNode("organization", entity, "info");
      addGraphEdge(ipNode, orgNode, "rdap entity", caseId, scanId, "ipRdap.entities");
    }
  }

  for (const mx of dnsValues(result.dns?.MX)) {
    const mxNode = upsertGraphNode("mail_server", mx.exchange || JSON.stringify(mx), "info");
    addGraphEdge(domainNode || targetNode, mxNode, "uses mail server", caseId, scanId, "dns.MX");
  }

  for (const hop of result.http?.chain || []) {
    const hopNode = upsertGraphNode("url", hop.url, hop.ok && hop.statusCode >= 400 ? "medium" : "info");
    addGraphEdge(targetNode, hopNode, hop.url === result.target.normalized ? "requested as" : "redirect hop", caseId, scanId, "http.chain");
    if (hop.location) {
      const locationNode = upsertGraphNode("url", hop.location, "medium");
      addGraphEdge(hopNode, locationNode, "redirects to", caseId, scanId, "http.location");
    }
  }

  if (result.tls?.fingerprint256) {
    const certNode = upsertGraphNode("tls_certificate", result.tls.fingerprint256, result.tls.authorized ? "info" : "high");
    addGraphEdge(domainNode || targetNode, certNode, "presents certificate", caseId, scanId, "tls");
  }

  const source = result.source || {};
  const sourceGroups = [
    ["email", source.emails, "contains email"],
    ["url", source.links, "links to"],
    ["ip", source.ips, "contains ip"],
    ["phone", source.phones, "contains phone"],
    ["crypto_wallet", source.cryptoWallets, "contains wallet"],
    ["social_handle", source.socialHandles, "contains handle"],
    ["form_action", source.formActions, "submits to"],
  ];
  for (const [type, values, relationship] of sourceGroups) {
    for (const value of values || []) {
      const node = upsertGraphNode(type, value, type === "crypto_wallet" || type === "form_action" ? "medium" : "info");
      addGraphEdge(targetNode, node, relationship, caseId, scanId, "source");
    }
  }
}

function saveCase(result) {
  const riskLevel = getRiskLevel(result.signals || []);
  const statement = db.prepare(`
    INSERT INTO cases (normalized_target, target_type, risk_level, scanned_at, result_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(normalized_target) DO UPDATE SET
      target_type = excluded.target_type,
      risk_level = excluded.risk_level,
      scanned_at = excluded.scanned_at,
      result_json = excluded.result_json,
      updated_at = excluded.updated_at
    RETURNING id, case_number
  `);
  const now = new Date().toISOString();
  const resultJson = JSON.stringify(result);
  const row = statement.get(
    result.target.normalized,
    result.target.type,
    riskLevel,
    result.scannedAt,
    resultJson,
    now,
    now
  );
  if (!row.case_number) {
    db.prepare("UPDATE cases SET case_number = ? WHERE id = ?").run(`SNF-${String(row.id).padStart(6, "0")}`, row.id);
  }

  const finalResultJson = JSON.stringify({ ...result, caseId: row.id });
  const scan = db.prepare(`
    INSERT INTO scans (case_id, scanned_at, risk_level, result_json, result_sha256, source_sha256, headers_sha256)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    RETURNING id
  `).get(
    row.id,
    result.scannedAt,
    riskLevel,
    finalResultJson,
    sha256(finalResultJson),
    result.evidence?.artifacts?.source?.sha256 || null,
    result.evidence?.artifacts?.httpHeaders?.sha256 || null
  );
  logAudit(row.id, scan.id, "scan.created", { normalizedTarget: result.target.normalized, riskLevel });
  const savedResult = { ...result, caseId: row.id, scanId: scan.id };
  savedResult.case = { caseNumber: row.case_number || `SNF-${String(row.id).padStart(6, "0")}` };
  db.prepare("UPDATE cases SET result_json = ? WHERE id = ?").run(JSON.stringify(savedResult), row.id);
  db.prepare("UPDATE scans SET result_json = ?, result_sha256 = ? WHERE id = ?")
    .run(JSON.stringify(savedResult), sha256(JSON.stringify(savedResult)), scan.id);
  buildCaseGraph(savedResult, row.id, scan.id, riskLevel);
  return { caseId: row.id, scanId: scan.id };
}

function listCases() {
  const rows = db.prepare(`
    SELECT id, case_number, normalized_target, target_type, risk_level, scanned_at, status, scam_category, examiner
    FROM cases
    ORDER BY scanned_at DESC
    LIMIT 100
  `).all();

  return rows.map((row) => ({
    id: row.id,
    caseNumber: row.case_number,
    normalizedTarget: row.normalized_target,
    targetType: row.target_type,
    riskLevel: row.risk_level,
    scannedAt: row.scanned_at,
    status: row.status,
    scamCategory: row.scam_category,
    examiner: row.examiner,
  }));
}

function getCase(id) {
  const row = db.prepare("SELECT * FROM cases WHERE id = ?").get(id);
  if (!row) {
    return null;
  }
  const result = JSON.parse(row.result_json);
  result.case = mapCaseRow(row);
  result.scans = db.prepare("SELECT id, scanned_at, risk_level, result_sha256, source_sha256, headers_sha256 FROM scans WHERE case_id = ? ORDER BY scanned_at DESC").all(id)
    .map((scan) => ({
      id: scan.id,
      scannedAt: scan.scanned_at,
      riskLevel: scan.risk_level,
      resultSha256: scan.result_sha256,
      sourceSha256: scan.source_sha256,
      headersSha256: scan.headers_sha256,
    }));
  result.auditLog = db.prepare("SELECT action, created_at, detail_json FROM audit_log WHERE case_id = ? ORDER BY created_at DESC LIMIT 50").all(id)
    .map((entry) => ({
      action: entry.action,
      createdAt: entry.created_at,
      detail: entry.detail_json ? JSON.parse(entry.detail_json) : null,
    }));
  return result;
}

function mapCaseRow(row) {
  return {
    id: row.id,
    caseNumber: row.case_number,
    title: row.title,
    status: row.status,
    scamCategory: row.scam_category,
    examiner: row.examiner,
    sourceOfReport: row.source_of_report,
    victim: row.victim,
    lossAmount: row.loss_amount,
    jurisdiction: row.jurisdiction,
    notes: row.notes,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function updateCase(id, updates) {
  const allowed = {
    title: "title",
    status: "status",
    scamCategory: "scam_category",
    examiner: "examiner",
    sourceOfReport: "source_of_report",
    victim: "victim",
    lossAmount: "loss_amount",
    jurisdiction: "jurisdiction",
    notes: "notes",
  };
  const assignments = [];
  const values = [];
  for (const [key, column] of Object.entries(allowed)) {
    if (Object.hasOwn(updates, key)) {
      assignments.push(`${column} = ?`);
      values.push(String(updates[key] ?? "").slice(0, 5000));
    }
  }
  if (!assignments.length) {
    return getCase(id);
  }
  assignments.push("updated_at = ?");
  values.push(new Date().toISOString(), id);
  db.prepare(`UPDATE cases SET ${assignments.join(", ")} WHERE id = ?`).run(...values);
  logAudit(id, null, "case.updated", { fields: Object.keys(updates) });
  return getCase(id);
}

function exportCase(id) {
  const result = getCase(id);
  if (!result) {
    return null;
  }
  return {
    exportedAt: new Date().toISOString(),
    tool: { name: "ScamIntel", version: TOOL_VERSION },
    case: result.case,
    latestResult: result,
    scans: result.scans,
    auditLog: result.auditLog,
  };
}

function getCaseGraph(id) {
  const nodes = db.prepare(`
    SELECT DISTINCT n.id, n.node_type, n.value, n.label, n.risk_level, n.first_seen, n.last_seen
    FROM graph_nodes n
    JOIN graph_edges e ON e.source_node_id = n.id OR e.target_node_id = n.id
    WHERE e.case_id = ?
    ORDER BY n.node_type, n.label
  `).all(id).map((node) => ({
    id: node.id,
    type: node.node_type,
    value: node.value,
    label: node.label,
    riskLevel: node.risk_level,
    firstSeen: node.first_seen,
    lastSeen: node.last_seen,
  }));

  const edges = db.prepare(`
    SELECT e.id, e.source_node_id, e.target_node_id, e.relationship, e.scan_id, e.evidence_ref, e.created_at
    FROM graph_edges e
    WHERE e.case_id = ?
    ORDER BY e.created_at
  `).all(id).map((edge) => ({
    id: edge.id,
    source: edge.source_node_id,
    target: edge.target_node_id,
    relationship: edge.relationship,
    scanId: edge.scan_id,
    evidenceRef: edge.evidence_ref,
    createdAt: edge.created_at,
  }));

  return { nodes, edges };
}

function getGlobalGraph(limit = 500) {
  const edges = db.prepare(`
    SELECT e.id, e.source_node_id, e.target_node_id, e.relationship, e.case_id, e.scan_id, e.evidence_ref, e.created_at
    FROM graph_edges e
    ORDER BY e.created_at DESC
    LIMIT ?
  `).all(limit).map((edge) => ({
    id: edge.id,
    source: edge.source_node_id,
    target: edge.target_node_id,
    relationship: edge.relationship,
    caseId: edge.case_id,
    scanId: edge.scan_id,
    evidenceRef: edge.evidence_ref,
    createdAt: edge.created_at,
  }));

  const nodeIds = [...new Set(edges.flatMap((edge) => [edge.source, edge.target]))];
  if (!nodeIds.length) {
    return { nodes: [], edges: [] };
  }
  const placeholders = nodeIds.map(() => "?").join(",");
  const nodes = db.prepare(`
    SELECT id, node_type, value, label, risk_level, first_seen, last_seen
    FROM graph_nodes
    WHERE id IN (${placeholders})
    ORDER BY node_type, label
  `).all(...nodeIds).map((node) => ({
    id: node.id,
    type: node.node_type,
    value: node.value,
    label: node.label,
    riskLevel: node.risk_level,
    firstSeen: node.first_seen,
    lastSeen: node.last_seen,
  }));
  return { nodes, edges };
}

function getPivots() {
  const rows = db.prepare(`
    SELECT n.id, n.node_type, n.value, n.label, n.risk_level,
      COUNT(DISTINCT e.case_id) AS case_count,
      COUNT(e.id) AS edge_count,
      MIN(e.created_at) AS first_seen,
      MAX(e.created_at) AS last_seen
    FROM graph_nodes n
    JOIN graph_edges e ON e.source_node_id = n.id OR e.target_node_id = n.id
    WHERE n.node_type NOT IN ('case')
    GROUP BY n.id
    HAVING case_count > 1 OR edge_count > 1
    ORDER BY case_count DESC, edge_count DESC, n.node_type, n.label
    LIMIT 100
  `).all();

  return rows.map((row) => ({
    nodeId: row.id,
    type: row.node_type,
    value: row.value,
    label: row.label,
    riskLevel: row.risk_level,
    caseCount: row.case_count,
    edgeCount: row.edge_count,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
  }));
}

function getPivotCases(nodeId) {
  const rows = db.prepare(`
    SELECT DISTINCT c.id, c.case_number, c.normalized_target, c.risk_level, c.scanned_at, c.status
    FROM cases c
    JOIN graph_edges e ON e.case_id = c.id
    WHERE e.source_node_id = ? OR e.target_node_id = ?
    ORDER BY c.scanned_at DESC
  `).all(nodeId, nodeId);
  return rows.map((row) => ({
    id: row.id,
    caseNumber: row.case_number,
    normalizedTarget: row.normalized_target,
    riskLevel: row.risk_level,
    scannedAt: row.scanned_at,
    status: row.status,
  }));
}

function clearCases() {
  db.prepare("DELETE FROM graph_edges").run();
  db.prepare("DELETE FROM graph_nodes").run();
  db.prepare("DELETE FROM audit_log").run();
  db.prepare("DELETE FROM scans").run();
  db.prepare("DELETE FROM cases").run();
}

function normalizeTarget(raw) {
  const input = String(raw || "").trim();
  if (!input) {
    throw new Error("Enter an IP address, domain, or URL.");
  }

  if (net.isIP(input)) {
    return {
      input,
      type: "ip",
      ip: input,
      host: input,
      url: null,
      normalized: input,
    };
  }

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new Error("The target is not a valid IP, domain, or URL.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  return {
    input,
    type: "url",
    url: parsed.toString(),
    protocol: parsed.protocol.replace(":", ""),
    host: parsed.hostname,
    port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    path: `${parsed.pathname}${parsed.search}`,
    normalized: parsed.toString(),
  };
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const value = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    const inRange = (base, mask) => (value & mask) === (base & mask);
    return [
      [0x00000000, 0xff000000],
      [0x0a000000, 0xff000000],
      [0x64400000, 0xffc00000],
      [0x7f000000, 0xff000000],
      [0xa9fe0000, 0xffff0000],
      [0xac100000, 0xfff00000],
      [0xc0000000, 0xffffff00],
      [0xc0000200, 0xffffff00],
      [0xc0a80000, 0xffff0000],
      [0xc6120000, 0xfffe0000],
      [0xcb007100, 0xffffff00],
      [0xe0000000, 0xf0000000],
      [0xf0000000, 0xf0000000],
    ].some(([base, mask]) => inRange(base, mask));
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    return normalized === "::"
      || normalized === "::1"
      || normalized.startsWith("fc")
      || normalized.startsWith("fd")
      || normalized.startsWith("fe8")
      || normalized.startsWith("fe9")
      || normalized.startsWith("fea")
      || normalized.startsWith("feb")
      || normalized.startsWith("ff");
  }

  return false;
}

function normalizeIpHost(hostname) {
  return String(hostname || "").replace(/^\[/, "").replace(/\]$/, "");
}

function isLocalHostname(hostname) {
  const host = normalizeIpHost(hostname).toLowerCase().replace(/\.$/, "");
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local");
}

async function assertSafeOutboundUrl(urlText) {
  const url = new URL(urlText);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }
  if (isLocalHostname(url.hostname)) {
    throw new Error("Local hostnames are blocked for outbound investigation requests.");
  }
  const directIp = normalizeIpHost(url.hostname);
  if (net.isIP(directIp)) {
    if (isPrivateIp(directIp)) {
      throw new Error("Private, local, reserved, and multicast IP addresses are blocked for outbound investigation requests.");
    }
    return;
  }

  const records = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isPrivateIp(record.address))) {
    throw new Error("Hostnames resolving to private, local, reserved, or multicast IP addresses are blocked for outbound investigation requests.");
  }
}

function publicSuffixParts(host) {
  const parts = String(host || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (parts.length < 2) {
    return { registeredDomain: parts[0] || "", subdomain: "", tld: parts[0] || "" };
  }
  const parsed = psl.parse(parts.join("."));
  if (!parsed.error && parsed.domain) {
    return {
      registeredDomain: parsed.domain,
      subdomain: parsed.subdomain || "",
      tld: parsed.tld || parts.at(-1),
    };
  }
  return {
    registeredDomain: parts.slice(-2).join("."),
    subdomain: parts.slice(0, -2).join("."),
    tld: parts.at(-1),
  };
}

function eventDate(events, actions) {
  const wanted = new Set(actions);
  const event = (events || []).find((entry) => wanted.has(entry.eventAction));
  return event?.eventDate || null;
}

function entityNames(entities) {
  return (entities || [])
    .map((entity) => {
      const fn = (entity.vcardArray?.[1] || []).find((item) => item[0] === "fn");
      return fn?.[3];
    })
    .filter(Boolean);
}

function ipv4ToInt(ip) {
  return ip.split(".").reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n);
}

function ipv6ToInt(ip) {
  const [headText, tailText = ""] = ip.toLowerCase().split("::");
  const head = headText ? headText.split(":") : [];
  const tail = tailText ? tailText.split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) {
    return null;
  }
  const groups = [...head, ...Array(missing).fill("0"), ...tail];
  return groups.reduce((value, group) => {
    if (!/^[0-9a-f]{0,4}$/.test(group)) {
      return null;
    }
    return value === null ? null : (value << 16n) + BigInt(parseInt(group || "0", 16));
  }, 0n);
}

function ipToInt(ip) {
  if (net.isIPv4(ip)) {
    return { value: ipv4ToInt(ip), bits: 32 };
  }
  if (net.isIPv6(ip)) {
    const value = ipv6ToInt(ip);
    return value === null ? null : { value, bits: 128 };
  }
  return null;
}

function cidrContainsIp(cidr, ip) {
  const [rangeIp, prefixText] = String(cidr).split("/");
  const candidate = ipToInt(ip);
  const range = ipToInt(rangeIp);
  if (!candidate || !range || candidate.bits !== range.bits) {
    return false;
  }
  const prefix = Number(prefixText ?? range.bits);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > candidate.bits) {
    return false;
  }
  const shift = BigInt(candidate.bits - prefix);
  return (candidate.value >> shift) === (range.value >> shift);
}

async function getRdapServiceForIp(ip) {
  const type = net.isIPv4(ip) ? "ipv4" : "ipv6";
  const bootstrap = await getRdapBootstrap(type);
  const service = (bootstrap.services || []).find(([ranges]) => ranges.some((range) => cidrContainsIp(range, ip)));
  return service?.[1]?.[0] || null;
}

function primaryIpFromDns(target, dnsProfile) {
  if (target.type === "ip" || net.isIP(target.host)) {
    return target.ip || target.host;
  }
  const a = dnsProfile?.A?.ok ? dnsProfile.A.value?.[0] : null;
  const aaaa = dnsProfile?.AAAA?.ok ? dnsProfile.AAAA.value?.[0] : null;
  return a || aaaa || null;
}

async function getRdapBootstrap(type) {
  if (rdapBootstrapCache.has(type)) {
    return rdapBootstrapCache.get(type);
  }
  const response = await httpsJson(RDAP_BOOTSTRAP_URLS[type]);
  if (!response.ok) {
    throw new Error(response.error || `RDAP bootstrap failed with ${response.statusCode}`);
  }
  rdapBootstrapCache.set(type, response.json);
  return response.json;
}

async function getRdapProfile(target) {
  if (target.type !== "url" || net.isIP(target.host)) {
    return null;
  }
  const domainParts = publicSuffixParts(target.host);
  const domain = domainParts.registeredDomain;
  const tld = domainParts.tld;
  try {
    const bootstrap = await getRdapBootstrap("dns");
    const service = (bootstrap.services || []).find(([tlds]) => tlds.includes(tld));
    const base = service?.[1]?.[0];
    if (!base) {
      return { ok: false, domain, tld, error: `No RDAP service found for .${tld}` };
    }
    const response = await httpsJson(`${base.replace(/\/$/, "")}/domain/${encodeURIComponent(domain)}`);
    if (!response.ok) {
      return { ok: false, domain, tld, server: base, error: response.error || `RDAP lookup failed with ${response.statusCode}` };
    }
    const data = response.json;
    const registrationDate = eventDate(data.events, ["registration"]);
    const expirationDate = eventDate(data.events, ["expiration"]);
    const lastChangedDate = eventDate(data.events, ["last changed", "last update of RDAP database"]);
    const ageDays = registrationDate ? Math.floor((Date.now() - new Date(registrationDate).getTime()) / 86400000) : null;
    return {
      ok: true,
      domain,
      tld,
      server: base,
      handle: data.handle || null,
      registrar: entityNames(data.entities).at(0) || null,
      nameservers: (data.nameservers || []).map((ns) => ns.ldhName).filter(Boolean),
      statuses: data.status || [],
      registrationDate,
      expirationDate,
      lastChangedDate,
      ageDays,
      rawSha256: sha256(JSON.stringify(data)),
    };
  } catch (error) {
    return { ok: false, domain, tld, error: error.message };
  }
}

async function getIpRdapProfile(target, dnsProfile) {
  const ip = primaryIpFromDns(target, dnsProfile);
  if (!ip || !net.isIP(ip)) {
    return null;
  }
  try {
    const server = await getRdapServiceForIp(ip);
    if (!server) {
      return { ok: false, ip, error: "No RDAP service found for IP address." };
    }
    const response = await httpsJson(`${server.replace(/\/$/, "")}/ip/${encodeURIComponent(ip)}`);
    if (!response.ok) {
      return { ok: false, ip, server, error: response.error || `IP RDAP lookup failed with ${response.statusCode}` };
    }
    const data = response.json;
    const registrationDate = eventDate(data.events, ["registration"]);
    const lastChangedDate = eventDate(data.events, ["last changed", "last update of RDAP database"]);
    return {
      ok: true,
      ip,
      server,
      handle: data.handle || null,
      name: data.name || null,
      type: data.type || null,
      country: data.country || null,
      startAddress: data.startAddress || null,
      endAddress: data.endAddress || null,
      parentHandle: data.parentHandle || null,
      entities: entityNames(data.entities).slice(0, 8),
      registrationDate,
      lastChangedDate,
      rawSha256: sha256(JSON.stringify(data)),
    };
  } catch (error) {
    return { ok: false, ip, error: error.message };
  }
}

async function resolveRecord(label, resolver) {
  try {
    const value = await resolver();
    return { label, ok: true, value };
  } catch (error) {
    return { label, ok: false, error: error.code || error.message };
  }
}

async function getDnsProfile(target) {
  const records = {};
  if (target.type === "ip") {
    const reverse = await resolveRecord("PTR", () => dns.reverse(target.ip));
    records.PTR = reverse;
    return records;
  }

  const host = target.host;
  if (net.isIP(host)) {
    records.IP = { label: "IP", ok: true, value: [host] };
    records.PTR = await resolveRecord("PTR", () => dns.reverse(host));
    return records;
  }

  const lookups = await Promise.all([
    resolveRecord("A", () => dns.resolve4(host)),
    resolveRecord("AAAA", () => dns.resolve6(host)),
    resolveRecord("MX", () => dns.resolveMx(host)),
    resolveRecord("NS", () => dns.resolveNs(host)),
    resolveRecord("TXT", () => dns.resolveTxt(host)),
    resolveRecord("CAA", () => dns.resolveCaa(host)),
  ]);

  for (const record of lookups) {
    records[record.label] = record;
  }
  return records;
}

async function requestOnce(urlText, method = "HEAD") {
  try {
    await assertSafeOutboundUrl(urlText);
  } catch (error) {
    return { ok: false, url: urlText, error: error.message, elapsedMs: 0 };
  }

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const url = new URL(urlText);
    const client = url.protocol === "https:" ? https : http;
    const req = client.request(
      url,
      {
        method,
        timeout: REQUEST_TIMEOUT_MS,
        headers: {
          "user-agent": "SnifferInvestigator/0.1 (+local investigation tool)",
          accept: "*/*",
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => {
          resolve({
            ok: true,
            url: urlText,
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            elapsedMs: Date.now() - startedAt,
            location: res.headers.location ? new URL(res.headers.location, url).toString() : null,
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        ok: false,
        url: urlText,
        error: error.code || error.message,
        elapsedMs: Date.now() - startedAt,
      });
    });
    req.end();
  });
}

async function fetchPageSource(urlText) {
  try {
    await assertSafeOutboundUrl(urlText);
  } catch (error) {
    return { ok: false, url: urlText, error: error.message, elapsedMs: 0, truncated: false, source: "" };
  }

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const url = new URL(urlText);
    const client = url.protocol === "https:" ? https : http;
    let size = 0;
    const chunks = [];

    const req = client.request(
      url,
      {
        method: "GET",
        timeout: REQUEST_TIMEOUT_MS,
        headers: {
          "user-agent": "SnifferInvestigator/0.1 (+local investigation tool)",
          accept: "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.2",
        },
      },
      (res) => {
        const contentType = String(res.headers["content-type"] || "");
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size <= MAX_SOURCE_BYTES) {
            chunks.push(chunk);
          } else {
            req.destroy(new Error("Source byte limit reached"));
          }
        });
        res.on("end", () => {
          resolve({
            ok: true,
            url: urlText,
            statusCode: res.statusCode,
            contentType,
            elapsedMs: Date.now() - startedAt,
            truncated: size > MAX_SOURCE_BYTES,
            source: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error("Source request timed out"));
    });
    req.on("error", (error) => {
      const source = chunks.length ? Buffer.concat(chunks).toString("utf8") : "";
      resolve({
        ok: Boolean(source),
        url: urlText,
        error: error.message,
        elapsedMs: Date.now() - startedAt,
        truncated: size > MAX_SOURCE_BYTES,
        source,
      });
    });
    req.end();
  });
}

async function getHttpProfile(target) {
  if (target.type !== "url") {
    return null;
  }

  const chain = [];
  let current = target.url;
  for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
    let result = await requestOnce(current, "HEAD");
    if (!result.ok && ["ECONNRESET", "EPIPE", "HPE_INVALID_CONSTANT"].includes(result.error)) {
      result = await requestOnce(current, "GET");
    }
    chain.push(result);

    if (!result.ok || !result.location || ![301, 302, 303, 307, 308].includes(result.statusCode)) {
      break;
    }
    current = result.location;
  }

  return {
    chain,
    finalUrl: chain.at(-1)?.url || target.url,
    redirected: chain.length > 1,
    redirectLimitHit: chain.length > MAX_REDIRECTS,
  };
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function normalizePhone(value) {
  return value.replace(/\s+/g, " ").trim();
}

function isLikelyPhone(value) {
  const normalized = normalizePhone(value);
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(normalized)) {
    return false;
  }
  const digits = normalized.replace(/\D/g, "");
  return digits.length >= 8 && digits.length <= 15;
}

function doubleSha256(buffer) {
  return crypto.createHash("sha256").update(crypto.createHash("sha256").update(buffer).digest()).digest();
}

function decodeBase58(value) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let decoded = 0n;
  for (const char of value) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      return null;
    }
    decoded = decoded * 58n + BigInt(index);
  }

  let hex = decoded.toString(16);
  if (hex.length % 2) {
    hex = `0${hex}`;
  }
  const bytes = hex === "00" ? [] : [...Buffer.from(hex, "hex")];
  for (const char of value) {
    if (char !== "1") {
      break;
    }
    bytes.unshift(0);
  }
  return Buffer.from(bytes);
}

function isValidBase58CheckBitcoinAddress(value) {
  const decoded = decodeBase58(value);
  if (!decoded || decoded.length !== 25 || ![0x00, 0x05].includes(decoded[0])) {
    return false;
  }
  const payload = decoded.subarray(0, -4);
  const checksum = decoded.subarray(-4);
  return checksum.equals(doubleSha256(payload).subarray(0, 4));
}

function bech32Polymod(values) {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) {
      if ((top >> index) & 1) {
        checksum ^= generators[index];
      }
    }
  }
  return checksum;
}

function bech32HrpExpand(hrp) {
  return [
    ...[...hrp].map((char) => char.charCodeAt(0) >> 5),
    0,
    ...[...hrp].map((char) => char.charCodeAt(0) & 31),
  ];
}

function isValidBech32BitcoinAddress(value) {
  if (value !== value.toLowerCase() && value !== value.toUpperCase()) {
    return false;
  }
  const address = value.toLowerCase();
  const separator = address.lastIndexOf("1");
  if (separator < 1 || separator + 7 > address.length || address.length > 90) {
    return false;
  }
  const hrp = address.slice(0, separator);
  if (hrp !== "bc") {
    return false;
  }
  const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const data = [...address.slice(separator + 1)].map((char) => charset.indexOf(char));
  if (data.some((index) => index === -1) || data.length < 7) {
    return false;
  }
  const version = data[0];
  if (version > 16) {
    return false;
  }
  const checksum = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
  return version === 0 ? checksum === 1 : checksum === 0x2bc830a3;
}

function isValidEthereumAddress(value) {
  if (!/^0x[a-fA-F0-9]{40}$/.test(value)) {
    return false;
  }
  const body = value.slice(2);
  return body === body.toLowerCase() || body === body.toUpperCase() || /[a-f]/.test(body) && /[A-F]/.test(body);
}

function walletExplorerUrl(chain, value) {
  if (chain === "bitcoin") {
    return `https://mempool.space/address/${encodeURIComponent(value)}`;
  }
  if (chain === "ethereum") {
    return `https://etherscan.io/address/${encodeURIComponent(value)}`;
  }
  return null;
}

function extractCryptoWalletDetails(source) {
  const base58Candidates = source.match(/\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b/g) || [];
  const bech32Candidates = source.match(/\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71}\b/gi) || [];
  const ethCandidates = source.match(/\b0x[a-fA-F0-9]{40}\b/g) || [];
  const details = [
    ...base58Candidates.filter(isValidBase58CheckBitcoinAddress).map((value) => ({
      value,
      chain: "bitcoin",
      network: "mainnet",
      addressType: value.startsWith("1") ? "p2pkh" : "p2sh",
      explorerUrl: walletExplorerUrl("bitcoin", value),
    })),
    ...bech32Candidates.filter(isValidBech32BitcoinAddress).map((value) => ({
      value,
      chain: "bitcoin",
      network: "mainnet",
      addressType: "bech32",
      explorerUrl: walletExplorerUrl("bitcoin", value),
    })),
    ...ethCandidates.filter(isValidEthereumAddress).map((value) => ({
      value,
      chain: "ethereum",
      network: "mainnet",
      addressType: "evm",
      explorerUrl: walletExplorerUrl("ethereum", value),
    })),
  ];
  const byValue = new Map();
  for (const detail of details) {
    if (!byValue.has(detail.value)) {
      byValue.set(detail.value, detail);
    }
  }
  return [...byValue.values()].sort((a, b) => a.value.localeCompare(b.value)).slice(0, 100);
}

function extractCryptoWallets(source) {
  return extractCryptoWalletDetails(source).map((wallet) => wallet.value);
}

function extractSourceIndicators(source, baseUrl) {
  const emails = uniqueSorted(source.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []);
  const ips = uniqueSorted(
    (source.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || [])
      .filter((ip) => net.isIP(ip))
  );
  const links = [];
  const formActions = [];
  const attrPattern = /\b(?:href|src|action|data-url)=["']([^"'#\s][^"']*)["']/gi;
  const formPattern = /<form\b[^>]*\baction=["']([^"']+)["']/gi;
  const plainUrlPattern = /\bhttps?:\/\/[^\s"'<>]+/gi;
  const phonePattern = /(?:\+?\d[\d ().-]{7,}\d)/g;
  const handlePattern = /(?:telegram|whatsapp|signal|wechat|instagram|facebook|x\.com|twitter)[^<>"']{0,80}?[@:]\s*([a-zA-Z0-9_.-]{3,40})/gi;
  const socialHandles = [];
  let match;

  while ((match = attrPattern.exec(source))) {
    try {
      links.push(new URL(match[1].trim(), baseUrl).toString());
    } catch {
      // Ignore malformed source values.
    }
  }

  while ((match = formPattern.exec(source))) {
    try {
      const action = new URL(match[1].trim(), baseUrl).toString();
      formActions.push(action);
      links.push(action);
    } catch {
      // Ignore malformed form actions.
    }
  }

  while ((match = plainUrlPattern.exec(source))) {
    try {
      links.push(new URL(match[0].replace(/[),.;]+$/, "")).toString());
    } catch {
      // Ignore malformed inline URLs.
    }
  }

  while ((match = handlePattern.exec(source))) {
    socialHandles.push(match[1]);
  }

  const cryptoWalletDetails = extractCryptoWalletDetails(source);
  return {
    emails,
    ips,
    links: uniqueSorted(links).slice(0, 250),
    phones: uniqueSorted((source.match(phonePattern) || []).filter(isLikelyPhone).map(normalizePhone)).slice(0, 100),
    cryptoWallets: cryptoWalletDetails.map((wallet) => wallet.value),
    cryptoWalletDetails,
    socialHandles: uniqueSorted(socialHandles).slice(0, 100),
    formActions: uniqueSorted(formActions).slice(0, 100),
  };
}

async function getSourceProfile(target, httpProfile) {
  if (target.type !== "url") {
    return null;
  }

  const finalUrl = httpProfile?.finalUrl || target.url;
  const fetched = await fetchPageSource(finalUrl);
  if (!fetched.ok && !fetched.source) {
    return {
      ok: false,
      url: finalUrl,
      error: fetched.error || "Unable to fetch page source.",
      elapsedMs: fetched.elapsedMs,
      emails: [],
      links: [],
      ips: [],
      phones: [],
      cryptoWallets: [],
      cryptoWalletDetails: [],
      socialHandles: [],
      formActions: [],
    };
  }

  const indicators = extractSourceIndicators(fetched.source, finalUrl);
  return {
    ok: true,
    url: finalUrl,
    statusCode: fetched.statusCode || null,
    contentType: fetched.contentType || null,
    elapsedMs: fetched.elapsedMs,
    truncated: fetched.truncated,
    bytesInspected: Buffer.byteLength(fetched.source, "utf8"),
    sha256: sha256(fetched.source),
    rawHtml: fetched.source,
    ...indicators,
  };
}

function getTlsCertificate(host, port) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: Number(port || 443),
        servername: net.isIP(host) ? undefined : host,
        timeout: REQUEST_TIMEOUT_MS,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        resolve({
          ok: Boolean(cert && Object.keys(cert).length),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
          subject: cert.subject || null,
          issuer: cert.issuer || null,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          serialNumber: cert.serialNumber || null,
          fingerprint256: cert.fingerprint256 || null,
          subjectAltName: cert.subjectaltname || null,
        });
        socket.end();
      }
    );

    socket.on("timeout", () => {
      socket.destroy(new Error("TLS connection timed out"));
    });
    socket.on("error", (error) => {
      resolve({ ok: false, error: error.code || error.message });
    });
  });
}

async function getTlsProfile(target) {
  if (target.type !== "url" || target.protocol !== "https") {
    return null;
  }
  try {
    await assertSafeOutboundUrl(target.url);
  } catch (error) {
    return { ok: false, error: error.message };
  }
  return getTlsCertificate(target.host, target.port);
}

function flattenTxt(records) {
  return records?.TXT?.ok ? records.TXT.value.map((entry) => entry.join("")) : [];
}

function buildSignals(target, dnsProfile, httpProfile, tlsProfile, sourceProfile, rdapProfile, ipRdapProfile) {
  const signals = [];
  const host = target.host || "";
  const unicodeHost = domainToUnicode(host) || host;
  const txt = flattenTxt(dnsProfile);
  const parts = target.type === "url" ? publicSuffixParts(host) : null;

  const add = (level, title, detail) => signals.push({ level, title, detail });

  if (target.type === "url" && target.protocol === "http") {
    add("high", "Plain HTTP", "The target is not using HTTPS, so traffic and content integrity are exposed.");
  }
  if (target.type === "url" && host.startsWith("xn--")) {
    add("medium", "Punycode hostname", `Decoded form: ${unicodeHost}. Check for brand impersonation or lookalike characters.`);
  }
  if (target.type === "url" && net.isIP(host)) {
    add("medium", "IP literal URL", "URLs using raw IP addresses are common in disposable infrastructure and phishing kits.");
  }
  if (target.type === "url" && parts?.subdomain.split(".").filter(Boolean).length >= 3) {
    add("medium", "Deep subdomain chain", "Long subdomain chains can hide the registered domain from casual readers.");
  }
  if (target.type === "url" && target.port && !["80", "443"].includes(String(target.port))) {
    add("medium", "Non-standard port", `The URL uses port ${target.port}. Verify the service is expected.`);
  }
  if (httpProfile?.redirected) {
    add("info", "Redirect chain", `The target redirects ${httpProfile.chain.length - 1} time(s). Review every hop.`);
  }
  const final = httpProfile?.chain?.at(-1);
  if (final?.ok && final.statusCode >= 400) {
    add("medium", "Error response", `Final HTTP response was ${final.statusCode} ${final.statusMessage || ""}.`);
  }
  if (tlsProfile && !tlsProfile.ok) {
    add("medium", "TLS probe failed", tlsProfile.error || "No certificate was returned.");
  }
  if (tlsProfile?.ok && !tlsProfile.authorized) {
    add("high", "Certificate validation issue", tlsProfile.authorizationError || "The certificate could not be validated.");
  }
  if (tlsProfile?.validTo && new Date(tlsProfile.validTo).getTime() < Date.now()) {
    add("high", "Expired certificate", `Certificate expired on ${tlsProfile.validTo}.`);
  }
  if (txt.some((record) => /v=spf1/i.test(record))) {
    add("info", "SPF record found", "Mail sender policy is published. Check whether it matches the claimed organization.");
  }
  if (sourceProfile?.ok) {
    const count = sourceProfile.emails.length
      + sourceProfile.links.length
      + sourceProfile.ips.length
      + sourceProfile.phones.length
      + sourceProfile.cryptoWallets.length
      + sourceProfile.socialHandles.length;
    if (count > 0) {
      add("info", "Page indicators found", `Source scan found ${sourceProfile.emails.length} email(s), ${sourceProfile.links.length} link(s), ${sourceProfile.ips.length} IP address(es), ${sourceProfile.phones.length} phone number(s), ${sourceProfile.cryptoWallets.length} wallet(s), and ${sourceProfile.socialHandles.length} social handle(s).`);
    }
  }
  if (sourceProfile && !sourceProfile.ok) {
    add("info", "Page source unavailable", sourceProfile.error || "The page source could not be fetched for extraction.");
  }
  if (rdapProfile?.ok && rdapProfile.ageDays !== null) {
    if (rdapProfile.ageDays < 30) {
      add("medium", "Recently registered domain", `RDAP shows ${rdapProfile.domain} was registered ${rdapProfile.ageDays} day(s) ago.`);
    } else {
      add("info", "Domain age found", `RDAP shows ${rdapProfile.domain} is approximately ${rdapProfile.ageDays} day(s) old.`);
    }
  }
  if (rdapProfile && !rdapProfile.ok) {
    add("info", "RDAP unavailable", rdapProfile.error || "Domain registration details could not be retrieved.");
  }
  if (ipRdapProfile?.ok) {
    add("info", "IP allocation found", `Primary IP ${ipRdapProfile.ip} is allocated to ${ipRdapProfile.name || ipRdapProfile.handle || "an RDAP network record"}.`);
  }
  if (ipRdapProfile && !ipRdapProfile.ok) {
    add("info", "IP RDAP unavailable", ipRdapProfile.error || "IP allocation details could not be retrieved.");
  }

  if (!signals.length) {
    add("info", "No obvious local indicators", "No high-confidence issue was found by local checks. Continue with content and reputation review.");
  }

  return signals;
}

async function investigate(rawTarget) {
  const target = normalizeTarget(rawTarget);
  const [dnsProfile, httpProfile, tlsProfile] = await Promise.all([
    getDnsProfile(target),
    getHttpProfile(target),
    getTlsProfile(target),
  ]);
  const [sourceProfile, rdapProfile] = await Promise.all([
    getSourceProfile(target, httpProfile),
    getRdapProfile(target),
  ]);
  const ipRdapProfile = await getIpRdapProfile(target, dnsProfile);
  const headerEvidence = httpProfile ? JSON.stringify(httpProfile.chain.map((hop) => ({
    url: hop.url,
    statusCode: hop.statusCode || null,
    headers: hop.headers || null,
    error: hop.error || null,
  }))) : "";
  const evidence = {
    collection: {
      collectedAtUtc: new Date().toISOString(),
      toolName: "ScamIntel",
      toolVersion: TOOL_VERSION,
      operator: null,
      method: "Local HTTP/DNS/TLS collection",
    },
    artifacts: {
      httpHeaders: httpProfile ? {
        sha256: sha256(headerEvidence),
        bytes: Buffer.byteLength(headerEvidence, "utf8"),
      } : null,
      source: sourceProfile?.ok ? {
        sha256: sourceProfile.sha256,
        bytes: sourceProfile.bytesInspected,
        truncated: sourceProfile.truncated,
        url: sourceProfile.url,
      } : null,
      rdap: rdapProfile?.ok ? {
        sha256: rdapProfile.rawSha256,
        domain: rdapProfile.domain,
        server: rdapProfile.server,
      } : null,
      ipRdap: ipRdapProfile?.ok ? {
        sha256: ipRdapProfile.rawSha256,
        ip: ipRdapProfile.ip,
        server: ipRdapProfile.server,
      } : null,
    },
  };

  const result = {
    scannedAt: new Date().toISOString(),
    target,
    domain: target.type === "url" ? {
      ascii: target.host,
      unicode: domainToUnicode(target.host) || target.host,
      ...publicSuffixParts(target.host),
    } : null,
    dns: dnsProfile,
    http: httpProfile,
    tls: tlsProfile,
    source: sourceProfile,
    rdap: rdapProfile,
    ipRdap: ipRdapProfile,
    network: {
      primaryIp: primaryIpFromDns(target, dnsProfile),
      ipRdap: ipRdapProfile,
    },
    evidence,
    signals: buildSignals(target, dnsProfile, httpProfile, tlsProfile, sourceProfile, rdapProfile, ipRdapProfile),
  };

  result.evidence.artifacts.result = {
    sha256: sha256(JSON.stringify(result)),
    bytes: Buffer.byteLength(JSON.stringify(result), "utf8"),
  };
  const saved = saveCase(result);
  result.caseId = saved.caseId;
  result.scanId = saved.scanId;
  return result;
}

async function readRequestBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024 * 32) {
      throw new Error("Request body is too large.");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function serveStatic(req, res) {
  const requested = req.url === "/" ? "/index.html" : new URL(req.url, "http://localhost").pathname;
  const safePath = path.normalize(decodeURIComponent(requested)).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  try {
    const data = await fs.readFile(filePath);
    res.writeHead(200, {
      "content-type": MIME_TYPES[path.extname(filePath)] || "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(data);
  } catch {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const requestUrl = new URL(req.url, "http://localhost");

    if (req.method === "POST" && requestUrl.pathname === "/api/investigate") {
      const body = JSON.parse(await readRequestBody(req));
      const result = await investigate(body.target);
      sendJson(res, 200, result);
      return;
    }

    if (req.method === "GET" && requestUrl.pathname === "/api/cases") {
      sendJson(res, 200, { cases: listCases() });
      return;
    }

    if (req.method === "GET" && requestUrl.pathname === "/api/graph") {
      sendJson(res, 200, getGlobalGraph(Number(requestUrl.searchParams.get("limit") || 500)));
      return;
    }

    if (req.method === "GET" && requestUrl.pathname === "/api/pivots") {
      sendJson(res, 200, { pivots: getPivots() });
      return;
    }

    if (req.method === "GET" && /^\/api\/pivots\/\d+\/cases$/.test(requestUrl.pathname)) {
      const nodeId = Number(requestUrl.pathname.split("/").at(-2));
      sendJson(res, 200, { cases: getPivotCases(nodeId) });
      return;
    }

    if (req.method === "GET" && /^\/api\/cases\/\d+\/export$/.test(requestUrl.pathname)) {
      const id = Number(requestUrl.pathname.split("/").at(-2));
      const exported = exportCase(id);
      if (!exported) {
        sendJson(res, 404, { error: "Case not found" });
        return;
      }
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "content-disposition": `attachment; filename="sniffer-case-${id}.json"`,
        "cache-control": "no-store",
      });
      res.end(JSON.stringify(exported, null, 2));
      return;
    }

    if (req.method === "GET" && /^\/api\/cases\/\d+\/graph$/.test(requestUrl.pathname)) {
      const id = Number(requestUrl.pathname.split("/").at(-2));
      const result = getCase(id);
      if (!result) {
        sendJson(res, 404, { error: "Case not found" });
        return;
      }
      sendJson(res, 200, getCaseGraph(id));
      return;
    }

    if (req.method === "GET" && /^\/api\/cases\/\d+$/.test(requestUrl.pathname)) {
      const id = Number(requestUrl.pathname.split("/").at(-1));
      const result = getCase(id);
      if (!result) {
        sendJson(res, 404, { error: "Case not found" });
        return;
      }
      sendJson(res, 200, result);
      return;
    }

    if (req.method === "PATCH" && /^\/api\/cases\/\d+$/.test(requestUrl.pathname)) {
      const id = Number(requestUrl.pathname.split("/").at(-1));
      const updates = JSON.parse(await readRequestBody(req));
      const result = updateCase(id, updates);
      if (!result) {
        sendJson(res, 404, { error: "Case not found" });
        return;
      }
      sendJson(res, 200, result);
      return;
    }

    if (req.method === "DELETE" && requestUrl.pathname === "/api/cases") {
      clearCases();
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === "GET") {
      await serveStatic(req, res);
      return;
    }

    sendJson(res, 405, { error: "Method not allowed" });
  } catch (error) {
    sendJson(res, 400, { error: error.message || "Investigation failed" });
  }
});

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use. Stop the existing server or start with another port, for example: $env:PORT=3001; node server.js`);
    process.exit(1);
  }

  throw error;
});

if (require.main === module) {
  initDatabase()
    .then(() => {
      server.listen(PORT, () => {
        console.log(`ScamIntel investigation platform running at http://localhost:${PORT}`);
        console.log(`Cases database: ${DB_PATH}`);
      });
    })
    .catch((error) => {
      console.error(`Unable to initialize database: ${error.message}`);
      process.exit(1);
    });
}

module.exports = {
  assertSafeOutboundUrl,
  buildSignals,
  extractCryptoWalletDetails,
  extractSourceIndicators,
  extractCryptoWallets,
  isPrivateIp,
  normalizeTarget,
  publicSuffixParts,
};
