const dns = require("node:dns").promises;
const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const path = require("node:path");
const tls = require("node:tls");
const { URL, domainToUnicode } = require("node:url");
const fs = require("node:fs/promises");
const psl = require("psl");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
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

function listCases() {
  return [];
}

function getCase(id) {
  return null;
}

function updateCase(id, updates) {
  return null;
}

function exportCase(id) {
  return null;
}

function getCaseGraph(id) {
  return { nodes: [], edges: [] };
}

function getGlobalGraph(limit = 500) {
  return { nodes: [], edges: [] };
}

function getPivots() {
  return [];
}

function getPivotCases(nodeId) {
  return [];
}

function clearCases() {
  return true;
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

function decodeHtmlEntities(value) {
  return String(value || "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#039;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    .replace(/&#x([a-f0-9]+);/gi, (_, code) => String.fromCharCode(parseInt(code, 16)))
    .replace(/\s+/g, " ")
    .trim();
}

function stripTags(value) {
  return decodeHtmlEntities(String(value || "").replace(/<[^>]*>/g, " "));
}

function parseHtmlAttributes(markup) {
  const attrs = {};
  const attrPattern = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let match;
  while ((match = attrPattern.exec(markup))) {
    attrs[match[1].toLowerCase()] = decodeHtmlEntities(match[2] ?? match[3] ?? match[4] ?? "");
  }
  return attrs;
}

function metaValue(source, names) {
  const wanted = new Set(names.map((name) => name.toLowerCase()));
  const metaPattern = /<meta\b([^>]*)>/gi;
  let match;
  while ((match = metaPattern.exec(source))) {
    const attrs = parseHtmlAttributes(match[1]);
    const key = (attrs.name || attrs.property || attrs["http-equiv"] || "").toLowerCase();
    if (wanted.has(key) && attrs.content) {
      return attrs.content;
    }
  }
  return null;
}

function linkHref(source, relNames, baseUrl) {
  const wanted = new Set(relNames.map((name) => name.toLowerCase()));
  const linkPattern = /<link\b([^>]*)>/gi;
  let match;
  while ((match = linkPattern.exec(source))) {
    const attrs = parseHtmlAttributes(match[1]);
    const rel = String(attrs.rel || "").toLowerCase().split(/\s+/);
    if (rel.some((name) => wanted.has(name)) && attrs.href) {
      try {
        return new URL(attrs.href, baseUrl).toString();
      } catch {
        return attrs.href;
      }
    }
  }
  return null;
}

function extractHtmlMetadata(source, baseUrl) {
  const titleMatch = source.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const htmlMatch = source.match(/<html\b([^>]*)>/i);
  const htmlAttrs = htmlMatch ? parseHtmlAttributes(htmlMatch[1]) : {};
  const generator = metaValue(source, ["generator"]);
  return {
    title: titleMatch ? stripTags(titleMatch[1]) : null,
    description: metaValue(source, ["description"]),
    canonicalUrl: linkHref(source, ["canonical"], baseUrl),
    faviconUrl: linkHref(source, ["icon", "shortcut icon", "apple-touch-icon"], baseUrl),
    language: htmlAttrs.lang || metaValue(source, ["language", "content-language"]),
    generator,
    openGraph: {
      title: metaValue(source, ["og:title"]),
      description: metaValue(source, ["og:description"]),
      siteName: metaValue(source, ["og:site_name"]),
      image: metaValue(source, ["og:image"]),
    },
    twitter: {
      title: metaValue(source, ["twitter:title"]),
      description: metaValue(source, ["twitter:description"]),
      card: metaValue(source, ["twitter:card"]),
    },
  };
}

function classifyFormInput(attrs) {
  const haystack = [attrs.name, attrs.id, attrs.type, attrs.placeholder, attrs.autocomplete, attrs.value]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/password|passwd|passcode|pin\b|otp|2fa|mfa|verification|code/.test(haystack)) {
    return "credential";
  }
  if (/seed|recovery phrase|mnemonic|private.?key|wallet/.test(haystack)) {
    return "wallet_secret";
  }
  if (/card|cc-|credit|cvv|cvc|expiry|iban|routing|account/.test(haystack)) {
    return "payment";
  }
  if (/email|user|login|phone|mobile|name/.test(haystack)) {
    return "identity";
  }
  return "other";
}

function extractForms(source, baseUrl) {
  const forms = [];
  const formPattern = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch;
  while ((formMatch = formPattern.exec(source)) && forms.length < 25) {
    const attrs = parseHtmlAttributes(formMatch[1]);
    const body = formMatch[2] || "";
    const inputs = [];
    const inputPattern = /<(input|textarea|select|button)\b([^>]*)>/gi;
    let inputMatch;
    while ((inputMatch = inputPattern.exec(body)) && inputs.length < 80) {
      const inputAttrs = parseHtmlAttributes(inputMatch[2]);
      const type = inputMatch[1].toLowerCase() === "input" ? (inputAttrs.type || "text").toLowerCase() : inputMatch[1].toLowerCase();
      inputs.push({
        tag: inputMatch[1].toLowerCase(),
        type,
        name: inputAttrs.name || null,
        id: inputAttrs.id || null,
        placeholder: inputAttrs.placeholder || null,
        autocomplete: inputAttrs.autocomplete || null,
        classification: classifyFormInput({ ...inputAttrs, type }),
      });
    }
    const classifications = new Set(inputs.map((input) => input.classification));
    let action = attrs.action || "";
    if (action) {
      try {
        action = new URL(action, baseUrl).toString();
      } catch {
        // Keep the original action for analyst review.
      }
    }
    forms.push({
      action: action || baseUrl,
      method: (attrs.method || "get").toUpperCase(),
      id: attrs.id || null,
      name: attrs.name || null,
      inputCount: inputs.length,
      hasPassword: inputs.some((input) => input.type === "password" || input.classification === "credential"),
      hasOtp: inputs.some((input) => /otp|2fa|mfa|verification|code/i.test([input.name, input.id, input.placeholder].filter(Boolean).join(" "))),
      hasWalletSecret: classifications.has("wallet_secret"),
      hasPaymentField: classifications.has("payment"),
      hiddenFieldCount: inputs.filter((input) => input.type === "hidden").length,
      inputs,
    });
  }
  return forms;
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
    metadata: extractHtmlMetadata(source, baseUrl),
    forms: extractForms(source, baseUrl),
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
      metadata: null,
      forms: [],
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
    const sensitiveForms = (sourceProfile.forms || []).filter((form) => form.hasPassword || form.hasOtp || form.hasWalletSecret || form.hasPaymentField);
    if (sensitiveForms.length) {
      add("medium", "Sensitive form fields", `Source scan found ${sensitiveForms.length} form(s) requesting credentials, OTP codes, wallet secrets, or payment details.`);
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
  server.listen(PORT, () => {
    console.log(`ScamIntel investigation platform running at http://localhost:${PORT}`);
    console.log("Persistence disabled: investigations are not saved to a database.");
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
