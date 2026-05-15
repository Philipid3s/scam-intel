const assert = require("node:assert/strict");
const test = require("node:test");

const {
  REDACTED,
  buildExportPayload,
  redactReportNotes,
  sanitizedResultForExport,
  summarizeSignals,
} = require("../public/report-export");

function sampleResult() {
  return {
    target: {
      normalized: "https://example.test/login",
      type: "url",
    },
    case: {
      victim: "Jane Doe",
      lossAmount: "1000",
      notes: "Sensitive details",
    },
    source: {
      cryptoWalletDetails: [{ value: "0x000000000000000000000000000000000000dead", chain: "ethereum" }],
      emails: ["support@example.test"],
      phones: ["+1 555 123 4567"],
      formActions: ["https://pay.example.test/submit"],
      ips: ["203.0.113.10"],
      links: ["https://example.test/login"],
      socialHandles: ["case_support"],
    },
    domain: {
      registeredDomain: "example.test",
    },
    network: {
      primaryIp: "203.0.113.10",
    },
    http: {
      finalUrl: "https://example.test/login",
    },
    tls: {
      fingerprint256: "AA:BB:CC",
    },
    rdap: {
      ok: true,
      domain: "example.test",
      registrar: "Example Registrar",
      registrationDate: "2026-01-01T00:00:00Z",
      ageDays: 42,
    },
    ipRdap: {
      ok: true,
      ip: "203.0.113.10",
      name: "Example Network",
      handle: "EXAMPLE",
      country: "US",
      startAddress: "203.0.113.0",
      endAddress: "203.0.113.255",
    },
    signals: [{ level: "high", title: "Credential collection form" }],
    evidence: {
      artifacts: {
        result: { sha256: "result-hash" },
        source: { sha256: "source-hash" },
      },
    },
  };
}

test("buildExportPayload includes report sections by default", () => {
  const payload = buildExportPayload({
    result: sampleResult(),
    notes: { title: "Case report" },
    options: {},
    exportedAt: "2026-05-15T00:00:00.000Z",
  });

  assert.equal(payload.exportedAt, "2026-05-15T00:00:00.000Z");
  assert.equal(payload.tool.name, "ScamIntel");
  assert.equal(payload.report.notes.title, "Case report");
  assert.equal(payload.report.evidence.indicators.emails[0], "support@example.test");
  assert.equal(payload.report.evidence.network.primaryIp, "203.0.113.10");
  assert.equal(payload.result.case.victim, "Jane Doe");
});

test("buildExportPayload honors section exclusion options", () => {
  const payload = buildExportPayload({
    result: sampleResult(),
    options: {
      includeIndicators: false,
      includeNetworkEvidence: false,
      includeRawProfiles: false,
    },
  });

  assert.equal("indicators" in payload.report.evidence, false);
  assert.equal("network" in payload.report.evidence, false);
  assert.equal("result" in payload, false);
});

test("redaction removes victim details from report notes and raw profile case metadata", () => {
  const result = sampleResult();
  const payload = buildExportPayload({
    result,
    notes: {
      victim: "Jane Doe",
      lossAmount: "1000",
      notes: "Sensitive details",
    },
    options: {
      includeRawProfiles: true,
      redactVictimDetails: true,
    },
  });
  const serialized = JSON.stringify(payload);

  assert.equal(payload.report.notes.victim, REDACTED);
  assert.equal(payload.report.notes.lossAmount, REDACTED);
  assert.equal(payload.report.notes.notes, REDACTED);
  assert.equal(payload.result.case.victim, REDACTED);
  assert.equal(payload.result.case.lossAmount, REDACTED);
  assert.equal(payload.result.case.notes, REDACTED);
  assert.equal(serialized.includes("Jane Doe"), false);
  assert.equal(serialized.includes("Sensitive details"), false);
  assert.equal(serialized.includes("1000"), false);
  assert.equal(result.case.victim, "Jane Doe");
});

test("redaction helpers preserve empty notes and summarize signals", () => {
  assert.deepEqual(redactReportNotes({ notes: "" }, { redactVictimDetails: true }), {
    victim: REDACTED,
    lossAmount: REDACTED,
    notes: "",
  });
  assert.equal(sanitizedResultForExport({ case: { notes: "" } }, { redactVictimDetails: true }).case.notes, "");
  assert.equal(summarizeSignals([]), "No risk signals were recorded.");
  assert.equal(summarizeSignals([{ level: "medium", title: "Recently registered domain" }]), "MEDIUM: Recently registered domain");
});
