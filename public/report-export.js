(function attachReportExport(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.ScamIntelReportExport = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : null, function createReportExportApi() {
  const REDACTED = "[redacted]";

  function redactReportNotes(notes, options = {}) {
    const copy = { ...(notes || {}) };
    if (options.redactVictimDetails) {
      copy.victim = REDACTED;
      copy.lossAmount = REDACTED;
      copy.notes = copy.notes ? REDACTED : "";
    }
    return copy;
  }

  function sanitizedResultForExport(result, options = {}) {
    const copy = JSON.parse(JSON.stringify(result || {}));
    if (options.redactVictimDetails && copy.case) {
      copy.case.victim = REDACTED;
      copy.case.lossAmount = REDACTED;
      copy.case.notes = copy.case.notes ? REDACTED : "";
    }
    return copy;
  }

  function summarizeSignals(signals = []) {
    if (!signals.length) {
      return "No risk signals were recorded.";
    }
    return signals.map((signal) => `${String(signal.level || "info").toUpperCase()}: ${signal.title}`).join(" | ");
  }

  function buildExportPayload({ result, notes = {}, options = {}, exportedAt = new Date().toISOString() }) {
    const source = result?.source || {};
    const payload = {
      exportedAt,
      tool: { name: "ScamIntel" },
      report: {
        notes: redactReportNotes(notes, options),
        redactions: {
          victimDetails: Boolean(options.redactVictimDetails),
        },
        evidence: {
          target: result?.target,
          signals: result?.signals || [],
          hashes: result?.evidence?.artifacts || {},
        },
      },
    };

    if (options.includeIndicators !== false) {
      payload.report.evidence.indicators = {
        wallets: source.cryptoWalletDetails || source.cryptoWallets || [],
        emails: source.emails || [],
        phones: source.phones || [],
        formActions: source.formActions || [],
        ips: source.ips || [],
        links: source.links || [],
        socialHandles: source.socialHandles || [],
      };
    }

    if (options.includeNetworkEvidence !== false) {
      payload.report.evidence.network = {
        domain: result?.domain || null,
        primaryIp: result?.network?.primaryIp || null,
        httpFinalUrl: result?.http?.finalUrl || null,
        tlsFingerprint: result?.tls?.fingerprint256 || null,
        rdap: result?.rdap?.ok ? {
          domain: result.rdap.domain,
          registrar: result.rdap.registrar,
          registrationDate: result.rdap.registrationDate,
          ageDays: result.rdap.ageDays,
        } : result?.rdap || null,
        ipRdap: result?.ipRdap?.ok ? {
          ip: result.ipRdap.ip,
          name: result.ipRdap.name,
          handle: result.ipRdap.handle,
          country: result.ipRdap.country,
          range: [result.ipRdap.startAddress, result.ipRdap.endAddress].filter(Boolean).join(" - "),
        } : result?.ipRdap || null,
      };
    }

    if (options.includeRawProfiles !== false) {
      payload.result = sanitizedResultForExport(result, options);
    }

    return payload;
  }

  return {
    REDACTED,
    buildExportPayload,
    redactReportNotes,
    sanitizedResultForExport,
    summarizeSignals,
  };
});
