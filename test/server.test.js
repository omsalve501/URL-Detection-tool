"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { buildReport, canonicalizeTarget, createApp, isPublicAddress, scoreReport } = require("../server");

async function withServer(options, run) {
  const app = createApp(options);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await run(base);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("accepts URL, domain, IPv4, and unbracketed IPv6 targets", () => {
  assert.equal(canonicalizeTarget("example.com").url, "https://example.com/");
  assert.equal(canonicalizeTarget("http://example.com/path").domain, "example.com");
  assert.equal(canonicalizeTarget("8.8.8.8").isIp, true);
  assert.equal(canonicalizeTarget("2001:4860:4860::8888").url, "https://[2001:4860:4860::8888]/");
  assert.throws(() => canonicalizeTarget("javascript:alert(1)"), /valid URL/);
  assert.throws(() => canonicalizeTarget("https://user:pass@example.com"), /embedded username/);
  assert.throws(() => canonicalizeTarget("localhost"), /fully qualified/);
});

test("rejects private and reserved IP ranges before external analysis", async () => {
  for (const address of ["10.0.0.1", "127.0.0.1", "169.254.1.1", "172.20.1.1", "192.168.1.1", "224.0.0.1", "::1", "fc00::1", "fe80::1"]) {
    assert.equal(isPublicAddress(address), false, `${address} should not be public`);
  }
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) {
    assert.equal(isPublicAddress(address), true, `${address} should be public`);
  }
  await assert.rejects(() => buildReport("192.168.1.1", async () => { throw new Error("should not be called"); }), /Private, reserved/);
});

test("risk score thresholds match the requested risk bands", () => {
  const target = canonicalizeTarget("example.com");
  const threats = {
    google: { status: "not_configured" },
    abuseIpDb: { status: "not_configured" },
    otx: { status: "not_configured" },
  };
  const base = { target, dns: { errors: [] }, rdap: null, tlsReport: null, threats };
  const low = scoreReport(base);
  assert.equal(low.risk, 15);
  assert.equal(low.level, "Safe");
  const malicious = scoreReport({
    ...base,
    threats: { ...threats, google: { status: "available", data: { matches: [{ source: "Google" }] } } },
  });
  assert.equal(malicious.risk, 100);
  assert.equal(malicious.level, "Malicious");
});

test("builds a partial DNS/RDAP report and never uses private DNS answers for enrichment", async () => {
  const previousEnvironment = { ...process.env };
  for (const name of ["GOOGLE_SAFE_BROWSING_API_KEY", "VIRUSTOTAL_API_KEY", "URLHAUS_AUTH_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "IPINFO_TOKEN", "IP_API_ALLOW_HTTP"]) {
    delete process.env[name];
  }
  const fetchCalls = [];
  const fetchImpl = async (input) => {
    const url = new URL(input);
    fetchCalls.push(url);
    if (url.hostname === "dns.google") {
      const recordType = Number(url.searchParams.get("type"));
      return Response.json({
        Status: 0,
        Answer: recordType === 1 ? [{ type: 1, data: "10.1.2.3" }] : [],
      });
    }
    if (url.hostname === "rdap.org") return new Response(null, { status: 404 });
    throw new Error(`Unexpected external request to ${url.hostname}`);
  };
  try {
    const report = await buildReport("example.com", fetchImpl);
    assert.equal(report.target.domain, "example.com");
    assert.equal(report.category, "Uncategorized");
    assert.equal(report.score.risk, 15);
    assert.equal(report.score.level, "Safe");
    assert.deepEqual(report.dns.records.A, []);
    assert.deepEqual(report.dns.blockedAddresses, ["10.1.2.3"]);
    assert.equal(report.hosting.ip, null);
    assert.equal(report.providers.find((provider) => provider.id === "googleDns").status, "available");
    assert.ok(fetchCalls.some((url) => url.hostname === "rdap.org"));
    assert.equal(fetchCalls.some((url) => url.hostname === "ip-api.com"), false);
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in previousEnvironment)) delete process.env[key];
    Object.assign(process.env, previousEnvironment);
  }
});

test("configured intelligence feeds are normalized into one threat report", async () => {
  const keys = ["GOOGLE_SAFE_BROWSING_API_KEY", "VIRUSTOTAL_API_KEY", "URLHAUS_AUTH_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "IPINFO_TOKEN", "IP_API_ALLOW_HTTP"];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  process.env.GOOGLE_SAFE_BROWSING_API_KEY = "test-google-key";
  process.env.VIRUSTOTAL_API_KEY = "test-vt-key";
  process.env.URLHAUS_AUTH_KEY = "test-urlhaus-key";
  process.env.ABUSEIPDB_API_KEY = "test-abuse-key";
  process.env.OTX_API_KEY = "test-otx-key";
  delete process.env.IPINFO_TOKEN;
  delete process.env.IP_API_ALLOW_HTTP;
  const fetchImpl = async (input, options = {}) => {
    const url = new URL(input);
    if (url.hostname === "dns.google") return Response.json({ Status: 0, Answer: [{ type: 12, data: "dns.google." }] });
    if (url.hostname === "safebrowsing.googleapis.com") return Response.json({ threats: [{ threatTypes: ["MALWARE"] }], cacheDuration: "60s" });
    if (url.hostname === "www.virustotal.com") return Response.json({ data: { attributes: { last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 8 }, reputation: -12, tags: ["malware"] } } });
    if (url.hostname === "urlhaus-api.abuse.ch") {
      assert.equal(options.headers["Auth-Key"], "test-urlhaus-key");
      return Response.json({ query_status: "ok", threat: "malware_download", tags: ["elf"] });
    }
    if (url.hostname === "otx.alienvault.com") return Response.json({ pulse_info: { count: 4, pulses: [{ name: "test pulse", tags: ["malware"] }] } });
    if (url.hostname === "api.abuseipdb.com") return Response.json({ data: { ipAddress: "8.8.8.8", abuseConfidenceScore: 65, totalReports: 5, countryCode: "US" } });
    if (url.hostname === "rdap.org") return Response.json({ objectClassName: "ip network", name: "Google", country: "US" });
    throw new Error(`Unexpected provider request to ${url.hostname}`);
  };
  try {
    const report = await buildReport("8.8.8.8", fetchImpl);
    assert.equal(report.score.risk, 100);
    assert.equal(report.score.level, "Malicious");
    assert.equal(report.threats.maliciousReports, 3);
    assert.equal(report.threats.suspiciousReports, 1);
    assert.equal(report.threats.communityReputation, -12);
    assert.equal(report.threats.otxPulseCount, 4);
    assert.equal(report.threats.blacklistHits, 3);
    assert.deepEqual(report.threats.threatTags, ["malware"]);
    for (const id of ["googleSafeBrowsing", "virusTotal", "urlhaus", "abuseIpDb", "otx"]) {
      assert.equal(report.providers.find((provider) => provider.id === id).status, "available");
    }
  } finally {
    for (const key of keys) {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  }
});

test("Express API exposes health/status, validates targets, and caches reports", async () => {
  let analyzeCalls = 0;
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  await withServer({
    analyze: async (target) => {
      analyzeCalls += 1;
      return { target: { url: target }, cacheExpiresAt: expiresAt, score: { risk: 2, level: "Safe" } };
    },
  }, async (base) => {
    const health = await fetch(`${base}/api/health`);
    assert.equal((await health.json()).status, "ok");
    const status = await fetch(`${base}/api/status`);
    assert.equal((await status.json()).service, "ShadowPing URL Detector");
    assert.match(status.headers.get("content-security-policy"), /frame-ancestors 'none'/);
    const invalid = await fetch(`${base}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: "http://127.0.0.1" }),
    });
    assert.equal(invalid.status, 400);
    for (let index = 0; index < 2; index += 1) {
      const response = await fetch(`${base}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "example.com" }),
      });
      assert.equal(response.status, 200);
      assert.equal((await response.json()).score.risk, 2);
    }
    assert.equal(analyzeCalls, 1);
  });
});

test("Mongo-backed reports can be served from the persistent threat cache", async () => {
  const report = { target: { url: "https://persistent-cache.example/" }, cacheExpiresAt: new Date(Date.now() + 60_000).toISOString(), score: { risk: 11 } };
  let analyzed = false;
  let lookup;
  await withServer({
    cacheCollection: {
      async findOne(query) {
        lookup = query;
        return { report, expiresAt: new Date(report.cacheExpiresAt) };
      },
      async updateOne() {
        throw new Error("A MongoDB cache hit should not write a new record.");
      },
    },
    analyze: async () => {
      analyzed = true;
      throw new Error("Expected persistent cache hit.");
    },
  }, async (base) => {
    const response = await fetch(`${base}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: "persistent-cache.example" }),
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-cache"), "MONGODB");
    assert.equal((await response.json()).score.risk, 11);
  });
  assert.equal(analyzed, false);
  assert.match(lookup._id, /^https:\/\/persistent-cache\.example\/:/);
});

test("report API rejects oversized request bodies", async () => {
  await withServer({}, async (base) => {
    const response = await fetch(`${base}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: `https://${"x".repeat(9000)}.com` }),
    });
    assert.equal(response.status, 413);
  });
});
