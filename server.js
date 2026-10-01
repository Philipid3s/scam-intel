const dnsCallback = require("node:dns");
const dns = dnsCallback.promises;
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
const REQUEST_DEADLINE_MS = 15000;
const SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS || 60000);
const MAX_SOURCE_BYTES = 512 * 1024;
const TOOL_VERSION = require("./package.json").version;
const USER_AGENT = `ScamIntel/${TOOL_VERSION} (+local investigation tool)`;
const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
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

const DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"];
const ALLOWED_HOSTS = new Set([
  ...DEFAULT_ALLOWED_HOSTS,
  ...String(process.env.ALLOWED_HOSTS || "").split(",").map((host) => host.trim().toLowerCase()).filter(Boolean),
]);

const SECURITY_HEADERS = {
  "content-security-policy": [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; "),
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

function hostnameOf(value) {
  try {
    return new URL(`http://${value}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Blocks two browser-borne attacks on a localhost tool: DNS rebinding (an attacker
// domain resolving to 127.0.0.1 arrives with a foreign Host header) and cross-site
// requests from any page the analyst has open (foreign Origin header).
function checkRequestOrigin(req, allowedHosts = ALLOWED_HOSTS) {
  const host = hostnameOf(req.headers.host || "");
  if (!host || !allowedHosts.has(host)) {
    return { status: 403, error: "Host not allowed. Set ALLOWED_HOSTS to serve ScamIntel under another hostname." };
  }
  const origin = req.headers.origin;
  if (origin !== undefined) {
    let originHost = null;
    try {
      originHost = new URL(origin).hostname.toLowerCase();
    } catch {
      // "null" and malformed origins are rejected below.
    }
    if (!originHost || !allowedHosts.has(originHost)) {
      return { status: 403, error: "Cross-origin requests are not allowed." };
    }
  }
  if (req.headers["sec-fetch-site"] === "cross-site") {
    return { status: 403, error: "Cross-origin requests are not allowed." };
  }
  return null;
}

function isJsonRequest(req) {
  return /^application\/json\s*(?:;|$)/i.test(String(req.headers["content-type"] || ""));
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

// The socket `timeout` option only fires on inactivity, so a server trickling bytes
// could hold a request open indefinitely. This adds a hard per-request deadline and
// ties the request to the overall scan signal.
function attachDeadline(handle, signal, label, deadlineMs = REQUEST_DEADLINE_MS) {
  const timer = setTimeout(() => handle.destroy(new Error(`${label} exceeded the ${deadlineMs} ms time limit`)), deadlineMs);
  const onAbort = () => handle.destroy(new Error("Scan time limit reached"));
  if (signal?.aborted) {
    onAbort();
  } else {
    signal?.addEventListener("abort", onAbort, { once: true });
  }
  return () => {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  };
}

function httpsJson(urlText, signal) {
  return new Promise((resolve) => {
    const url = new URL(urlText);
    let cleanup = () => {};
    const done = (value) => {
      cleanup();
      resolve(value);
    };
    const req = https.request(
      url,
      {
        method: "GET",
        timeout: REQUEST_TIMEOUT_MS,
        headers: {
          "user-agent": USER_AGENT,
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
            done({ ok: res.statusCode >= 200 && res.statusCode < 300, statusCode: res.statusCode, json: JSON.parse(text) });
          } catch (error) {
            done({ ok: false, statusCode: res.statusCode, error: error.message });
          }
        });
      }
    );
    cleanup = attachDeadline(req, signal, "RDAP request");
    req.on("timeout", () => req.destroy(new Error("RDAP request timed out")));
    req.on("error", (error) => done({ ok: false, error: error.code || error.message }));
    req.end();
  });
}

function sha256(value) {
  return crypto.createHash("sha256").update(value || "", "utf8").digest("hex");
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
    host: normalizeIpHost(parsed.hostname),
    port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    path: `${parsed.pathname}${parsed.search}`,
    normalized: parsed.toString(),
  };
}

const BLOCKED_IPV4_CIDRS = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
];

const BLOCKED_IPV6_CIDRS = [
  "::/128",
  "::1/128",
  "64:ff9b:1::/48",
  "100::/64",
  "2001::/32",
  "2001:db8::/32",
  "fc00::/7",
  "fe80::/10",
  "fec0::/10",
  "ff00::/8",
];

// IPv6 ranges that carry an IPv4 address the kernel or a translator may route to.
const EMBEDDED_IPV4_CIDRS = [
  { cidr: "::ffff:0:0/96", shift: 0n },
  { cidr: "::/96", shift: 0n },
  { cidr: "64:ff9b::/96", shift: 0n },
  { cidr: "2002::/16", shift: 80n },
];

function intToIpv4(value) {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 0xffn)).join(".");
}

function embeddedIpv4(ip) {
  const parsed = ipToInt(ip);
  if (!parsed || parsed.bits !== 128) {
    return null;
  }
  const match = EMBEDDED_IPV4_CIDRS.find(({ cidr }) => cidrContainsIp(cidr, ip));
  return match ? intToIpv4((parsed.value >> match.shift) & 0xffffffffn) : null;
}

function isPrivateIp(ip) {
  const address = normalizeIpHost(ip);
  if (net.isIPv4(address)) {
    return BLOCKED_IPV4_CIDRS.some((cidr) => cidrContainsIp(cidr, address));
  }

  if (net.isIPv6(address)) {
    if (BLOCKED_IPV6_CIDRS.some((cidr) => cidrContainsIp(cidr, address))) {
      return true;
    }
    const mapped = embeddedIpv4(address);
    return mapped ? isPrivateIp(mapped) : false;
  }

  return false;
}

function normalizeIpHost(hostname) {
  return String(hostname || "").replace(/^\[/, "").replace(/\]$/, "");
}

// Resolver for http/https/tls `lookup` that rejects private addresses at connect
// time. Validating the exact address the socket uses closes the DNS-rebinding gap
// between the pre-flight check and the real connection.
function createSafeLookup(lookup = dnsCallback.lookup) {
  return (hostname, options, callback) => {
    const opts = typeof options === "function" ? {} : { ...options };
    const cb = typeof options === "function" ? options : callback;
    lookup(hostname, { ...opts, all: true }, (error, addresses) => {
      if (error) {
        cb(error);
        return;
      }
      const list = Array.isArray(addresses) ? addresses : [{ address: addresses, family: net.isIP(addresses) }];
      if (!list.length || list.some((entry) => isPrivateIp(entry.address))) {
        const blocked = new Error(`Blocked connection: ${hostname} resolves to a private, local, reserved, or multicast address.`);
        blocked.code = "EBLOCKEDADDRESS";
        cb(blocked);
        return;
      }
      if (opts.all) {
        cb(null, list);
      } else {
        cb(null, list[0].address, list[0].family);
      }
    });
  };
}

const safeLookup = createSafeLookup();

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
  let text = ip.toLowerCase().replace(/%.*$/, "");
  const dotted = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    if (!net.isIPv4(dotted[2])) {
      return null;
    }
    const v4 = ipv4ToInt(dotted[2]);
    text = `${dotted[1]}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const [headText, tailText = ""] = text.split("::");
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

async function getRdapServiceForIp(ip, signal) {
  const type = net.isIPv4(ip) ? "ipv4" : "ipv6";
  const bootstrap = await getRdapBootstrap(type, signal);
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

async function getRdapBootstrap(type, signal) {
  if (rdapBootstrapCache.has(type)) {
    return rdapBootstrapCache.get(type);
  }
  const response = await httpsJson(RDAP_BOOTSTRAP_URLS[type], signal);
  if (!response.ok) {
    throw new Error(response.error || `RDAP bootstrap failed with ${response.statusCode}`);
  }
  rdapBootstrapCache.set(type, response.json);
  return response.json;
}

// The IANA DNS bootstrap is keyed by top-level domain ("uk"), not by public suffix
// ("co.uk"). psl also includes private suffixes such as blogspot.com, whose
// "registered domain" is not a registry object, so we fall back to shorter names.
function rdapLookupPlan(host, bootstrap) {
  const { registeredDomain } = publicSuffixParts(host);
  const labels = registeredDomain.split(".").filter(Boolean);
  const tld = labels.at(-1) || "";
  const service = (bootstrap?.services || []).find(([tlds]) => tlds.map((entry) => entry.toLowerCase()).includes(tld));
  const candidates = [];
  for (let index = 0; index <= labels.length - 2; index += 1) {
    candidates.push(labels.slice(index).join("."));
  }
  return { tld, server: service?.[1]?.[0] || null, candidates };
}

async function getRdapProfile(target, signal) {
  if (target.type !== "url" || net.isIP(target.host)) {
    return null;
  }
  let domain = publicSuffixParts(target.host).registeredDomain;
  let tld = domain.split(".").at(-1);
  try {
    const bootstrap = await getRdapBootstrap("dns", signal);
    const plan = rdapLookupPlan(target.host, bootstrap);
    tld = plan.tld;
    const base = plan.server;
    if (!base || !plan.candidates.length) {
      return { ok: false, domain, tld, error: `No RDAP service found for .${tld}` };
    }
    let response = null;
    for (const candidate of plan.candidates) {
      domain = candidate;
      response = await httpsJson(`${base.replace(/\/$/, "")}/domain/${encodeURIComponent(candidate)}`, signal);
      if (response.ok || response.statusCode !== 404) {
        break;
      }
    }
    if (!response?.ok) {
      return { ok: false, domain, tld, server: base, error: response?.error || `RDAP lookup failed with ${response?.statusCode}` };
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

async function getIpRdapProfile(target, dnsProfile, signal) {
  const ip = primaryIpFromDns(target, dnsProfile);
  if (!ip || !net.isIP(ip)) {
    return null;
  }
  try {
    const server = await getRdapServiceForIp(ip, signal);
    if (!server) {
      return { ok: false, ip, error: "No RDAP service found for IP address." };
    }
    const response = await httpsJson(`${server.replace(/\/$/, "")}/ip/${encodeURIComponent(ip)}`, signal);
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

  // Mail is configured on the registered domain, not on www. or other subdomains.
  const { registeredDomain } = publicSuffixParts(host);
  if (registeredDomain && registeredDomain !== host.toLowerCase().replace(/\.$/, "")) {
    const label = `MX (${registeredDomain})`;
    records.DOMAIN_MX = await resolveRecord(label, () => dns.resolveMx(registeredDomain));
    // A missing MX drives a signal, so confirm a negative answer before trusting it;
    // resolvers occasionally return a spurious NXDOMAIN under load.
    if (!records.DOMAIN_MX.ok && NO_RECORD_ERRORS.includes(records.DOMAIN_MX.error)) {
      records.DOMAIN_MX = await resolveRecord(label, () => dns.resolveMx(registeredDomain));
    }
  }
  return records;
}

function resolveLocation(location, base) {
  if (!location) {
    return null;
  }
  try {
    return new URL(location, base).toString();
  } catch {
    return null;
  }
}

async function requestOnce(urlText, method = "HEAD", signal) {
  try {
    await assertSafeOutboundUrl(urlText);
  } catch (error) {
    return { ok: false, url: urlText, error: error.message, elapsedMs: 0 };
  }

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const url = new URL(urlText);
    const client = url.protocol === "https:" ? https : http;
    let cleanup = () => {};
    const done = (value) => {
      cleanup();
      resolve(value);
    };
    const req = client.request(
      url,
      {
        method,
        timeout: REQUEST_TIMEOUT_MS,
        lookup: safeLookup,
        headers: {
          "user-agent": USER_AGENT,
          accept: "*/*",
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => {
          done({
            ok: true,
            url: urlText,
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            elapsedMs: Date.now() - startedAt,
            location: resolveLocation(res.headers.location, url),
          });
        });
      }
    );
    cleanup = attachDeadline(req, signal, "HTTP request");

    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });
    req.on("error", (error) => {
      done({
        ok: false,
        url: urlText,
        error: error.code && error.code !== "EBLOCKEDADDRESS" ? error.code : error.message,
        elapsedMs: Date.now() - startedAt,
      });
    });
    req.end();
  });
}

async function fetchPageSource(urlText, signal) {
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
    let cleanup = () => {};
    const done = (value) => {
      cleanup();
      resolve(value);
    };

    const req = client.request(
      url,
      {
        method: "GET",
        timeout: REQUEST_TIMEOUT_MS,
        lookup: safeLookup,
        headers: {
          "user-agent": USER_AGENT,
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
          done({
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
    cleanup = attachDeadline(req, signal, "Source request");

    req.on("timeout", () => {
      req.destroy(new Error("Source request timed out"));
    });
    req.on("error", (error) => {
      const source = chunks.length ? Buffer.concat(chunks).toString("utf8") : "";
      done({
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

function isRedirectHop(hop) {
  return Boolean(hop?.ok && hop.location && REDIRECT_STATUSES.includes(hop.statusCode));
}

function summarizeRedirectChain(chain, startUrl) {
  return {
    chain,
    finalUrl: chain.at(-1)?.url || startUrl,
    redirected: chain.length > 1,
    // Only a limit hit if we stopped while the last hop still pointed elsewhere.
    redirectLimitHit: chain.length > MAX_REDIRECTS && isRedirectHop(chain.at(-1)),
  };
}

async function getHttpProfile(target, signal) {
  if (target.type !== "url") {
    return null;
  }

  const chain = [];
  let current = target.url;
  for (let i = 0; i <= MAX_REDIRECTS && !signal?.aborted; i += 1) {
    let result = await requestOnce(current, "HEAD", signal);
    if (!result.ok && ["ECONNRESET", "EPIPE", "HPE_INVALID_CONSTANT"].includes(result.error) && !signal?.aborted) {
      result = await requestOnce(current, "GET", signal);
    }
    chain.push(result);

    if (!isRedirectHop(result)) {
      break;
    }
    current = result.location;
  }

  return summarizeRedirectChain(chain, target.url);
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
  // Dates and timestamps (2026-10-01, 01/10/2026 12) match the phone pattern.
  if (/^\d{4}[-./]\d{1,2}[-./]\d{1,2}(?:\D|$)/.test(normalized) || /^\d{1,2}[-./]\d{1,2}[-./]\d{4}(?:\D|$)/.test(normalized)) {
    return false;
  }
  const digits = normalized.replace(/\D/g, "");
  return digits.length >= 8 && digits.length <= 15;
}

// Retina asset names such as logo@2x.png look like emails to a plain regex.
function isLikelyEmail(value) {
  return !/\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|css|js|mjs|map|woff2?|ttf)$/i.test(value);
}

const KECCAK_ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROTATIONS = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];
const MASK_64 = (1n << 64n) - 1n;

function rotl64(value, shift) {
  const amount = BigInt(shift);
  return amount === 0n ? value : ((value << amount) | (value >> (64n - amount))) & MASK_64;
}

function keccakF1600(state) {
  for (const roundConstant of KECCAK_ROUND_CONSTANTS) {
    const c = [0, 1, 2, 3, 4].map((x) => state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]);
    for (let x = 0; x < 5; x += 1) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) {
        state[x + y] ^= d;
      }
    }
    const b = new Array(25);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        b[y + ((2 * x + 3 * y) % 5) * 5] = rotl64(state[x + y * 5], KECCAK_ROTATIONS[x + y * 5]);
      }
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 25; y += 5) {
        state[x + y] = b[x + y] ^ (~b[((x + 1) % 5) + y] & MASK_64 & b[((x + 2) % 5) + y]);
      }
    }
    state[0] ^= roundConstant;
  }
}

// Ethereum uses original Keccak-256 padding (0x01), not NIST SHA3-256 (0x06),
// so node:crypto's sha3-256 cannot be used for EIP-55 checksums.
function keccak256(input) {
  const rate = 136;
  const data = Buffer.from(input);
  const padded = Buffer.alloc(Math.floor(data.length / rate) * rate + rate);
  data.copy(padded);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane += 1) {
      state[lane] ^= padded.readBigUInt64LE(offset + lane * 8);
    }
    keccakF1600(state);
  }
  const out = Buffer.alloc(32);
  for (let lane = 0; lane < 4; lane += 1) {
    out.writeBigUInt64LE(state[lane], lane * 8);
  }
  return out.toString("hex");
}

function toEip55Address(value) {
  const body = value.slice(2).toLowerCase();
  const hash = keccak256(body);
  return `0x${[...body].map((char, index) => (parseInt(hash[index], 16) >= 8 ? char.toUpperCase() : char)).join("")}`;
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

function hasValidBase58Check(value, versions) {
  const decoded = decodeBase58(value);
  if (!decoded || decoded.length !== 25 || !versions.includes(decoded[0])) {
    return false;
  }
  const payload = decoded.subarray(0, -4);
  const checksum = decoded.subarray(-4);
  return checksum.equals(doubleSha256(payload).subarray(0, 4));
}

function isValidBase58CheckBitcoinAddress(value) {
  return hasValidBase58Check(value, [0x00, 0x05]);
}

// TRON uses Bitcoin-style Base58Check with version byte 0x41 (addresses start with T).
// USDT on TRON is the dominant payment rail in investment and pig-butchering scams.
function isValidTronAddress(value) {
  return hasValidBase58Check(value, [0x41]);
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
  // Single-case addresses carry no checksum; mixed case must match EIP-55.
  if (body === body.toLowerCase() || body === body.toUpperCase()) {
    return true;
  }
  return toEip55Address(value) === value;
}

function walletExplorerUrl(chain, value) {
  if (chain === "bitcoin") {
    return `https://mempool.space/address/${encodeURIComponent(value)}`;
  }
  if (chain === "ethereum") {
    return `https://etherscan.io/address/${encodeURIComponent(value)}`;
  }
  if (chain === "tron") {
    return `https://tronscan.org/#/address/${encodeURIComponent(value)}`;
  }
  return null;
}

function extractCryptoWalletDetails(source) {
  const base58Candidates = source.match(/\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b/g) || [];
  const bech32Candidates = source.match(/\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71}\b/gi) || [];
  const ethCandidates = source.match(/\b0x[a-fA-F0-9]{40}\b/g) || [];
  const tronCandidates = source.match(/\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g) || [];
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
    ...tronCandidates.filter(isValidTronAddress).map((value) => ({
      value,
      chain: "tron",
      network: "mainnet",
      addressType: "base58",
      explorerUrl: walletExplorerUrl("tron", value),
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

// Phishing kits commonly ship stolen form data straight to a Telegram bot or a
// Discord webhook from the victim's browser. The token itself is the key IOC: it
// identifies the operator's bot and can be reported to the platform.
function extractExfilEndpoints(source) {
  const endpoints = new Map();
  const add = (entry) => {
    if (!endpoints.has(entry.value)) {
      endpoints.set(entry.value, entry);
    }
  };
  const telegramToken = /(?<!\d)(\d{6,12}):(AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])/g;
  let match;
  while ((match = telegramToken.exec(source))) {
    add({ type: "telegram_bot", platform: "Telegram", id: match[1], value: `${match[1]}:${match[2]}` });
  }
  if (!endpoints.size && /api\.telegram\.org\/bot/i.test(source)) {
    add({ type: "telegram_api", platform: "Telegram", id: null, value: "api.telegram.org/bot" });
  }
  const discordWebhook = /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/(\d{5,25})\/([A-Za-z0-9_-]{20,100})/gi;
  while ((match = discordWebhook.exec(source))) {
    add({ type: "discord_webhook", platform: "Discord", id: match[1], value: match[0] });
  }
  return [...endpoints.values()].slice(0, 50);
}

const OBFUSCATION_PATTERNS = [
  { technique: "eval of decoded string", strong: true, pattern: /\beval\s*\(\s*(?:window\.)?(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/g },
  { technique: "document.write of decoded string", strong: true, pattern: /document\.write\s*\(\s*(?:window\.)?(?:atob|unescape|decodeURIComponent)\s*\(/g },
  { technique: "Function constructor on decoded string", strong: true, pattern: /\bnew\s+Function\s*\(\s*(?:window\.)?(?:atob|unescape|decodeURIComponent)\s*\(/g },
  { technique: "p,a,c,k,e,r packer", strong: true, pattern: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/g },
  { technique: "obfuscator.io identifiers", strong: true, minCount: 20, pattern: /\b_0x[a-f0-9]{4,6}\b/g },
  { technique: "large base64 string literal", strong: false, pattern: /["'`][A-Za-z0-9+/]{2000,}={0,2}["'`]/g },
  { technique: "long hex escape sequence", strong: false, pattern: /(?:\\x[0-9a-fA-F]{2}){50,}/g },
];

function detectScriptObfuscation(source) {
  return OBFUSCATION_PATTERNS
    .map(({ technique, strong, minCount = 1, pattern }) => ({ technique, strong, count: (source.match(pattern) || []).length, minCount }))
    .filter(({ count, minCount }) => count >= minCount)
    .map(({ technique, strong, count }) => ({ technique, strong, count }));
}

// Text a visitor actually reads. Phone and handle patterns must not run over
// markup: SVG path data ("M20.45 20.45h-3.55") looks like phone numbers and meta
// names ("twitter:card") look like handles.
function extractVisibleText(source) {
  const withoutBlocks = String(source || "")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|svg|template|head|math|object)\b[\s\S]*?<\/\1\s*>/gi, " ");
  return stripTags(withoutBlocks.replace(/<(?:br|\/p|\/div|\/li|\/tr|\/h[1-6])\b[^>]*>/gi, "\n"));
}

const PHONE_PATTERN = /(?:\+?\d[\d ().-]{7,}\d)/g;

function extractPhones(source, visibleText) {
  const fromText = visibleText.match(PHONE_PATTERN) || [];
  const fromTelLinks = [];
  const telPattern = /\bhref\s*=\s*["']\s*tel:([^"']+)["']/gi;
  let match;
  while ((match = telPattern.exec(source))) {
    try {
      fromTelLinks.push(decodeURIComponent(match[1]).replace(/[;,].*$/, ""));
    } catch {
      fromTelLinks.push(match[1]);
    }
  }
  return uniqueSorted([...fromText, ...fromTelLinks].map(normalizePhone).filter(isLikelyPhone)).slice(0, 100);
}

const SOCIAL_PLATFORMS = [
  {
    platform: "Telegram",
    at: true,
    hosts: ["t.me", "telegram.me", "telegram.dog"],
    path: /^\/(?:s\/)?((?:joinchat\/)?\+?[A-Za-z0-9_-]{4,64})\/?$/,
    reserved: ["share", "addstickers", "addemoji", "proxy", "socks", "iv", "login", "setlanguage"],
  },
  { platform: "WhatsApp", hosts: ["wa.me"], path: /^\/(\d{7,15})\/?$/, format: (value) => `+${value}` },
  {
    platform: "Instagram",
    at: true,
    hosts: ["instagram.com"],
    path: /^\/([A-Za-z0-9_.]{1,30})\/?$/,
    reserved: ["p", "reel", "reels", "explore", "accounts", "stories", "about", "developer", "legal", "direct"],
  },
  {
    platform: "Facebook",
    hosts: ["facebook.com", "fb.com", "fb.me"],
    path: /^\/([A-Za-z0-9.]{5,50})\/?$/,
    reserved: ["sharer", "sharer.php", "share", "dialog", "login", "login.php", "policies", "privacy", "help", "groups", "pages", "watch", "events", "marketplace"],
  },
  {
    platform: "X",
    at: true,
    hosts: ["x.com", "twitter.com"],
    path: /^\/([A-Za-z0-9_]{1,15})\/?$/,
    reserved: ["intent", "share", "home", "i", "search", "hashtag", "login", "signup", "privacy", "tos", "explore", "settings", "messages", "notifications"],
  },
  { platform: "TikTok", at: true, hosts: ["tiktok.com"], path: /^\/@([A-Za-z0-9_.]{2,24})\/?/ },
  { platform: "YouTube", at: true, hosts: ["youtube.com"], path: /^\/@([A-Za-z0-9_.-]{3,30})\/?/ },
  { platform: "LinkedIn", hosts: ["linkedin.com"], path: /^\/(?:in|company)\/([A-Za-z0-9_%-]{2,100})\/?/ },
  {
    platform: "GitHub",
    at: true,
    hosts: ["github.com"],
    path: /^\/([A-Za-z0-9-]{1,39})\/?$/,
    reserved: ["about", "features", "pricing", "login", "join", "signup", "sponsors", "explore", "marketplace", "topics", "trending", "collections", "enterprise", "security", "site", "contact"],
  },
];

function formatHandle(entry, value) {
  // t.me/+code and t.me/joinchat/code are private group invites, not usernames.
  const invite = entry.platform === "Telegram" && value.match(/^(?:\+|joinchat\/)(.+)$/);
  if (invite) {
    return `Telegram invite +${invite[1]}`;
  }
  const handle = entry.format ? entry.format(value) : value;
  return `${entry.platform} ${entry.at && !handle.startsWith("+") ? "@" : ""}${handle}`;
}

function socialHandleFromUrl(urlText) {
  let url;
  try {
    url = new URL(urlText);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase().replace(/^(?:www|m|mobile|web)\./, "");
  if (host === "api.whatsapp.com" || host === "whatsapp.com") {
    const phone = url.searchParams.get("phone")?.replace(/\D/g, "");
    return phone && phone.length >= 7 && phone.length <= 15 ? `WhatsApp +${phone}` : null;
  }
  const entry = SOCIAL_PLATFORMS.find((platform) => platform.hosts.includes(host));
  const match = entry && url.pathname.match(entry.path);
  if (!match || (entry.reserved || []).includes(match[1].toLowerCase())) {
    return null;
  }
  return formatHandle(entry, match[1]);
}

const TEXT_PLATFORM_NAMES = {
  telegram: "Telegram", tg: "Telegram", whatsapp: "WhatsApp", signal: "Signal", wechat: "WeChat",
  instagram: "Instagram", insta: "Instagram", ig: "Instagram", facebook: "Facebook",
  twitter: "X", x: "X", tiktok: "TikTok", youtube: "YouTube",
};

function extractSocialHandles(source, visibleText, links) {
  const handles = links.map(socialHandleFromUrl).filter(Boolean);

  // "Telegram: @name", "Contact us on WhatsApp @name". The @ must start a token,
  // so an email address such as help@example.com never yields a handle.
  const textPattern = /\b(telegram|tg|whatsapp|signal|wechat|instagram|insta|ig|facebook|twitter|tiktok|youtube|x)\b[^\n@]{0,30}?(?<![\w.])@([A-Za-z0-9_][A-Za-z0-9_.]{2,39})/gi;
  const platformWord = /\b(telegram|tg|whatsapp|signal|wechat|instagram|insta|ig|facebook|twitter|tiktok|youtube|x)\b/gi;
  let match;
  while ((match = textPattern.exec(visibleText))) {
    // Inline link text runs together ("IG Post TikTok Telegram: @name"), so the
    // platform named closest to the @ owns the handle.
    const closest = [...match[0].matchAll(platformWord)].at(-1)[1];
    handles.push(`${TEXT_PLATFORM_NAMES[closest.toLowerCase()]} @${match[2].replace(/\.+$/, "")}`);
  }

  for (const name of ["twitter:site", "twitter:creator"]) {
    const value = metaValue(source, [name]);
    const handle = value?.match(/^@?([A-Za-z0-9_]{1,15})$/);
    if (handle) {
      handles.push(`X @${handle[1]}`);
    }
  }
  return uniqueSorted(handles).slice(0, 100);
}

function extractSourceIndicators(source, baseUrl) {
  const emails = uniqueSorted((source.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).filter(isLikelyEmail));
  const ips = uniqueSorted(
    (source.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || [])
      .filter((ip) => net.isIP(ip))
  );
  const links = [];
  const formActions = [];
  const attrPattern = /\b(?:href|src|action|data-url)=["']([^"'#\s][^"']*)["']/gi;
  const formPattern = /<form\b[^>]*\baction=["']([^"']+)["']/gi;
  const plainUrlPattern = /\bhttps?:\/\/[^\s"'<>]+/gi;
  const visibleText = extractVisibleText(source);
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

  const cryptoWalletDetails = extractCryptoWalletDetails(source);
  return {
    metadata: extractHtmlMetadata(source, baseUrl),
    forms: extractForms(source, baseUrl),
    emails,
    ips,
    links: uniqueSorted(links).slice(0, 250),
    phones: extractPhones(source, visibleText),
    cryptoWallets: cryptoWalletDetails.map((wallet) => wallet.value),
    cryptoWalletDetails,
    socialHandles: extractSocialHandles(source, visibleText, uniqueSorted(links)),
    formActions: uniqueSorted(formActions).slice(0, 100),
    exfilEndpoints: extractExfilEndpoints(source),
    scriptObfuscation: detectScriptObfuscation(source),
  };
}

async function getSourceProfile(target, httpProfile, signal) {
  if (target.type !== "url") {
    return null;
  }

  const finalUrl = httpProfile?.finalUrl || target.url;
  const fetched = await fetchPageSource(finalUrl, signal);
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
      exfilEndpoints: [],
      scriptObfuscation: [],
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

function getTlsCertificate(host, port, signal) {
  return new Promise((resolve) => {
    let cleanup = () => {};
    const done = (value) => {
      cleanup();
      resolve(value);
    };
    const socket = tls.connect(
      {
        host,
        port: Number(port || 443),
        servername: net.isIP(host) ? undefined : host,
        timeout: REQUEST_TIMEOUT_MS,
        rejectUnauthorized: false,
        lookup: safeLookup,
      },
      () => {
        const cert = socket.getPeerCertificate();
        done({
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

    cleanup = attachDeadline(socket, signal, "TLS probe");

    socket.on("timeout", () => {
      socket.destroy(new Error("TLS connection timed out"));
    });
    socket.on("error", (error) => {
      done({ ok: false, error: error.code && error.code !== "EBLOCKEDADDRESS" ? error.code : error.message });
    });
  });
}

async function getTlsProfile(target, signal) {
  if (target.type !== "url" || target.protocol !== "https") {
    return null;
  }
  try {
    await assertSafeOutboundUrl(target.url);
  } catch (error) {
    return { ok: false, error: error.message };
  }
  return getTlsCertificate(target.host, target.port, signal);
}

function flattenTxt(records) {
  return records?.TXT?.ok ? records.TXT.value.map((entry) => entry.join("")) : [];
}

const DAY_MS = 86400000;
const NO_RECORD_ERRORS = ["ENODATA", "ENOTFOUND"];

// "present" | "absent" | "unknown". A null MX (RFC 7505, exchange ".") means the
// domain explicitly accepts no mail. DNS failures other than "no such record" are
// treated as unknown so a flaky resolver does not create a signal.
function mailExchangeStatus(dnsProfile) {
  const records = [dnsProfile?.MX, dnsProfile?.DOMAIN_MX].filter(Boolean);
  if (!records.length) {
    return "unknown";
  }
  const usable = (record) => record.ok && record.value.some((mx) => mx.exchange && mx.exchange !== ".");
  if (records.some(usable)) {
    return "present";
  }
  const definitive = records.every((record) => record.ok || NO_RECORD_ERRORS.includes(record.error));
  return definitive ? "absent" : "unknown";
}

function registeredDomainOf(urlText) {
  try {
    const { hostname, protocol } = new URL(urlText);
    const host = normalizeIpHost(hostname);
    return { protocol, domain: net.isIP(host) ? host : publicSuffixParts(host).registeredDomain };
  } catch {
    return null;
  }
}

function isSensitiveForm(form) {
  return form.hasPassword || form.hasOtp || form.hasWalletSecret || form.hasPaymentField;
}

function buildSignals(target, dnsProfile, httpProfile, tlsProfile, sourceProfile, rdapProfile, ipRdapProfile) {
  const signals = [];
  const host = target.host || "";
  const unicodeHost = domainToUnicode(host) || host;
  const txt = flattenTxt(dnsProfile);
  const parts = target.type === "url" && !net.isIP(host) ? publicSuffixParts(host) : null;

  const add = (level, title, detail) => signals.push({ level, title, detail });

  if (target.type === "url" && target.protocol === "http") {
    add("high", "Plain HTTP", "The target is not using HTTPS, so traffic and content integrity are exposed.");
  }
  if (target.type === "url" && host.split(".").some((label) => label.startsWith("xn--"))) {
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
  const certIssuedAt = tlsProfile?.validFrom ? new Date(tlsProfile.validFrom).getTime() : NaN;
  if (Number.isFinite(certIssuedAt)) {
    const certAgeDays = Math.floor((Date.now() - certIssuedAt) / DAY_MS);
    if (certAgeDays >= 0 && certAgeDays < 7) {
      add("info", "Recently issued certificate", `The TLS certificate was issued ${certAgeDays} day(s) ago. Automated certificates renew often, but combined with a new domain this suggests fresh infrastructure.`);
    }
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
    const forms = sourceProfile.forms || [];
    const sensitiveForms = forms.filter(isSensitiveForm);
    if (sensitiveForms.length) {
      add("medium", "Sensitive form fields", `Source scan found ${sensitiveForms.length} form(s) requesting credentials, OTP codes, wallet secrets, or payment details.`);
    }

    const page = registeredDomainOf(sourceProfile.url);
    const offsite = forms
      .map((form) => ({ form, action: registeredDomainOf(form.action) }))
      .filter(({ action }) => page && action && /^https?:$/.test(action.protocol) && action.domain && action.domain !== page.domain);
    const offsiteSensitive = offsite.filter(({ form }) => isSensitiveForm(form));
    const offsiteDomains = (entries) => uniqueSorted(entries.map(({ action }) => action.domain)).join(", ");
    if (offsiteSensitive.length) {
      add("high", "Sensitive form posts to another domain", `${offsiteSensitive.length} form(s) collecting credentials, codes, wallet secrets, or payment data submit to ${offsiteDomains(offsiteSensitive)} instead of ${page.domain}.`);
    } else if (offsite.length) {
      add("info", "Form posts to another domain", `${offsite.length} form(s) submit to ${offsiteDomains(offsite)}. Common for newsletters and search, but confirm the destination.`);
    }
    const plainHttpSensitive = sensitiveForms.filter((form) => registeredDomainOf(form.action)?.protocol === "http:");
    if (plainHttpSensitive.length) {
      add("high", "Sensitive form submits over plain HTTP", `${plainHttpSensitive.length} form(s) send credentials, codes, wallet secrets, or payment data unencrypted.`);
    }

    const exfil = sourceProfile.exfilEndpoints || [];
    if (exfil.length) {
      const platforms = uniqueSorted(exfil.map((endpoint) => endpoint.platform)).join(" and ");
      add("high", "Data exfiltration endpoint", `Page source contains ${exfil.length} ${platforms} bot or webhook endpoint(s). Phishing kits use these to send captured form data to the operator. Report the token to the platform.`);
    }

    const obfuscation = sourceProfile.scriptObfuscation || [];
    if (obfuscation.length) {
      const techniques = obfuscation.map((entry) => entry.technique).join(", ");
      add(obfuscation.some((entry) => entry.strong) ? "medium" : "info", "Obfuscated script", `Page source uses ${techniques}. Kits hide their logic and exfiltration targets this way, though some legitimate sites minify aggressively.`);
    }
  }
  const mailStatus = mailExchangeStatus(dnsProfile);
  if (mailStatus === "absent" && parts?.registeredDomain && dnsProfile?.A?.ok) {
    const ownEmails = (sourceProfile?.emails || []).filter((email) => email.toLowerCase().endsWith(`@${parts.registeredDomain}`));
    if (ownEmails.length) {
      add("medium", "Contact email cannot receive mail", `The page lists ${ownEmails.join(", ")}, but ${parts.registeredDomain} has no mail server (MX), so mail sent to that address cannot be delivered.`);
    } else {
      add("info", "No mail server", `${parts.registeredDomain} has no MX record, which is unusual for a real business.`);
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
  const registeredAt = rdapProfile?.ok ? new Date(rdapProfile.registrationDate).getTime() : NaN;
  const expiresAt = rdapProfile?.ok ? new Date(rdapProfile.expirationDate).getTime() : NaN;
  if (Number.isFinite(expiresAt)) {
    const daysLeft = Math.floor((expiresAt - Date.now()) / DAY_MS);
    if (Number.isFinite(registeredAt) && (expiresAt - registeredAt) / DAY_MS <= 366 && rdapProfile.ageDays !== null && rdapProfile.ageDays < 365) {
      add("info", "One-year registration", `${rdapProfile.domain} was registered for the minimum term. Disposable scam domains are rarely renewed.`);
    }
    if (daysLeft >= 0 && daysLeft <= 30) {
      add("info", "Domain expires soon", `${rdapProfile.domain} expires in ${daysLeft} day(s).`);
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

async function investigate(rawTarget, { timeoutMs = SCAN_TIMEOUT_MS } = {}) {
  const target = normalizeTarget(rawTarget);
  const controller = new AbortController();
  const scanTimer = setTimeout(() => controller.abort(), timeoutMs);
  const { signal } = controller;
  let dnsProfile;
  let httpProfile;
  let tlsProfile;
  let sourceProfile;
  let rdapProfile;
  let ipRdapProfile;
  try {
    [dnsProfile, httpProfile, tlsProfile] = await Promise.all([
      getDnsProfile(target),
      getHttpProfile(target, signal),
      getTlsProfile(target, signal),
    ]);
    [sourceProfile, rdapProfile] = await Promise.all([
      getSourceProfile(target, httpProfile, signal),
      getRdapProfile(target, signal),
    ]);
    ipRdapProfile = await getIpRdapProfile(target, dnsProfile, signal);
  } finally {
    clearTimeout(scanTimer);
  }
  const timedOut = signal.aborted;
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
      timedOut,
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
    domain: target.type === "url" && !net.isIP(target.host) ? {
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
  if (timedOut) {
    result.signals.push({
      level: "info",
      title: "Scan time limit reached",
      detail: `Collection stopped after ${Math.round(timeoutMs / 1000)} seconds. Some profiles may be incomplete.`,
    });
  }

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
  const pathname = new URL(req.url, "http://localhost").pathname;
  const requested = pathname === "/" ? "/index.html" : pathname;
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
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(name, value);
  }
  try {
    const rejection = checkRequestOrigin(req);
    if (rejection) {
      sendJson(res, rejection.status, { error: rejection.error });
      return;
    }

    const requestUrl = new URL(req.url, "http://localhost");

    if (req.method === "POST" && requestUrl.pathname === "/api/investigate") {
      // Requiring JSON forces a CORS preflight, which browsers will not send
      // cross-origin without our consent, so web pages cannot trigger scans.
      if (!isJsonRequest(req)) {
        sendJson(res, 415, { error: "Content-Type must be application/json." });
        return;
      }
      const body = JSON.parse(await readRequestBody(req));
      const result = await investigate(body.target);
      sendJson(res, 200, result);
      return;
    }

    if (requestUrl.pathname.startsWith("/api/")) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }

    if (req.method === "GET" || req.method === "HEAD") {
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
  attachDeadline,
  buildSignals,
  checkRequestOrigin,
  createSafeLookup,
  isValidEthereumAddress,
  keccak256,
  rdapLookupPlan,
  server,
  summarizeRedirectChain,
  toEip55Address,
  extractCryptoWalletDetails,
  extractSourceIndicators,
  extractCryptoWallets,
  isPrivateIp,
  normalizeTarget,
  publicSuffixParts,
};
