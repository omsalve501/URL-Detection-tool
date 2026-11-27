"use strict";

const express = require("express");
const path = require("node:path");
const net = require("node:net");
const tls = require("node:tls");
const { MongoClient } = require("mongodb");

const PORT = Number(process.env.PORT || 3000);
const MAX_TARGET_LENGTH = 2048;
const MAX_BODY_BYTES = "8kb";
const DNS_ENDPOINT = "https://dns.google/resolve";
const cache = new Map();
const rateWindows = new Map();
const THREAT_TYPES = new Set([
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
]);
const DNS_TYPES = [
  ["A", 1],
  ["AAAA", 28],
  ["MX", 15],
  ["NS", 2],
  ["TXT", 16],
  ["CNAME", 5],
];

function isPublicIPv4(address) {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => part < 0 || part > 255)) return false;
  const [a, b] = octets;
  return !(a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 192 && b === 0)
    || (a === 198 && (b === 18 || b === 19 || b === 51))
    || (a === 203 && b === 0));
}

function isPublicIPv6(value) {
  const address = value.toLowerCase().split("%")[0];
  if (address.startsWith("::ffff:")) {
    const mapped = address.slice(7);
    if (net.isIPv4(mapped)) return isPublicIPv4(mapped);
    const parts = mapped.split(":");
    if (parts.length === 2) {
      const high = Number.parseInt(parts[0], 16);
      const low = Number.parseInt(parts[1], 16);
      if (Number.isFinite(high) && Number.isFinite(low)) {
        return isPublicIPv4(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
      }
    }
    return false;
  }
  if (address === "::" || address === "::1" || address.startsWith("fc") || address.startsWith("fd")
    || /^fe[89ab]/.test(address) || address.startsWith("ff") || address.startsWith("2001:db8:")
    || address.startsWith("2002:") || /^2001:0[0-1]/.test(address)) return false;
  return address.startsWith("2") || address.startsWith("3");
}

function isPublicAddress(address) {
  const version = net.isIP(address);
  return version === 4 ? isPublicIPv4(address) : version === 6 && isPublicIPv6(address);
}

function ipv6Ptr(address) {
  const expanded = address.toLowerCase().split("::");
  let left = expanded[0] ? expanded[0].split(":") : [];
  let right = expanded[1] ? expanded[1].split(":") : [];
  if (left.at(-1)?.includes(".")) {
    const bytes = left.pop().split(".").map(Number);
    right = [...right, ((bytes[0] << 8) | bytes[1]).toString(16), ((bytes[2] << 8) | bytes[3]).toString(16)];
  }
  const groups = [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right]
    .map((group) => group.padStart(4, "0"));
  return `${groups.join("").split("").reverse().join(".")}.ip6.arpa`;
}

function canonicalizeTarget(input) {
  if (typeof input !== "string" || !input.trim() || input.trim().length > MAX_TARGET_LENGTH) {
    throw new Error(`Enter a URL, domain, or IP address (maximum ${MAX_TARGET_LENGTH} characters).`);
  }
  let raw = input.trim();
  if (raw.startsWith("//")) raw = `https:${raw}`;
  if (net.isIP(raw) === 6) raw = `https://[${raw}]/`;
  let parsed;
  try {
    parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    throw new Error("Enter a valid URL, domain, or IP address.");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS URLs are supported.");
  if (parsed.username || parsed.password) throw new Error("URLs with embedded username or password are not accepted.");
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
  const ipVersion = net.isIP(hostname);
  if (ipVersion && !isPublicAddress(hostname)) {
    throw new Error("Private, reserved, and local IP addresses cannot be analyzed.");
  }
  if (!ipVersion && (!hostname.includes(".") || hostname.length > 253
    || hostname.split(".").some((part) => !/^(?!-)[a-z\d-]{1,63}(?<!-)$/i.test(part)))) {
    throw new Error("Enter a fully qualified domain name or a valid IP address.");
  }
  const url = ipVersion ? `${parsed.protocol}//${hostname.includes(":") ? `[${hostname}]` : hostname}${parsed.pathname}${parsed.search}${parsed.hash}` : parsed.href;
  return {
    hostname,
    isIp: Boolean(ipVersion),
    ipVersion,
    url,
    domain: ipVersion ? hostname : hostname.replace(/^www\./, ""),
    protocol: parsed.protocol,
    pathname: parsed.pathname,
  };
}

async function fetchJson(url, options = {}, timeout = 7000, fetchImpl = globalThis.fetch) {
  const response = await fetchImpl(url, {
    ...options,
    headers: { Accept: "application/json", ...options.headers },
    signal: AbortSignal.timeout(timeout),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Provider returned HTTP ${response.status}`);
  return response.json();
}

async function dnsQuery(name, type, fetchImpl) {
  const url = new URL(DNS_ENDPOINT);
  url.searchParams.set("name", name);
  url.searchParams.set("type", type);
  const result = await fetchJson(url, { headers: { Accept: "application/dns-json" } }, 7000, fetchImpl);
  if (result.Status !== 0 && result.Status !== 3) throw new Error(`DNS query returned status ${result.Status}.`);
  return result;
}

async function getDns(hostname, inputIp, fetchImpl) {
  if (inputIp) {
    const started = Date.now();
    const answer = await dnsQuery(
      inputIp.includes(":") ? ipv6Ptr(inputIp) : `${inputIp.split(".").reverse().join(".")}.in-addr.arpa`,
      12,
      fetchImpl,
    );
    return {
      records: { A: [], AAAA: [], MX: [], NS: [], TXT: [], CNAME: [] },
      reverseDns: (answer.Answer || []).filter((item) => item.type === 12).map((item) => item.data),
      responseTimeMs: Date.now() - started,
      resolvedAddresses: [inputIp],
      blockedAddresses: [],
      errors: [],
    };
  }
  const started = Date.now();
  const results = await Promise.allSettled(DNS_TYPES.map(([, type]) => dnsQuery(hostname, type, fetchImpl)));
  const records = {};
  const errors = [];
  for (let index = 0; index < DNS_TYPES.length; index += 1) {
    const [name, type] = DNS_TYPES[index];
    const result = results[index];
    if (result.status === "fulfilled") {
      records[name] = (result.value.Answer || []).filter((answer) => answer.type === type).map((answer) => answer.data);
    } else {
      records[name] = [];
      errors.push(`${name}: ${result.reason.message}`);
    }
  }
  const addresses = [...new Set([...records.A, ...records.AAAA].filter(isPublicAddress))];
  const blockedAddresses = [...new Set([...records.A, ...records.AAAA].filter((address) => !isPublicAddress(address)))];
  records.A = records.A.filter(isPublicAddress);
  records.AAAA = records.AAAA.filter(isPublicAddress);
  let reverseDns = [];
  if (addresses.length) {
    const address = addresses[0];
    const ptrName = address.includes(":") ? ipv6Ptr(address) : `${address.split(".").reverse().join(".")}.in-addr.arpa`;
    try {
      const ptr = await dnsQuery(ptrName, 12, fetchImpl);
      reverseDns = (ptr.Answer || []).filter((answer) => answer.type === 12).map((answer) => answer.data);
    } catch (error) {
      errors.push(`PTR: ${error.message}`);
    }
  }
  return { records, reverseDns, responseTimeMs: Date.now() - started, resolvedAddresses: addresses, blockedAddresses, errors };
}

async function getRdap(target, fetchImpl) {
  const type = net.isIP(target) ? "ip" : "domain";
  const response = await fetchImpl(`https://rdap.org/${type}/${encodeURIComponent(target)}`, {
    headers: { Accept: "application/rdap+json, application/json" },
    signal: AbortSignal.timeout(7000),
    redirect: "follow",
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`RDAP returned HTTP ${response.status}`);
  const data = await response.json();
  const eventDate = (action) => data.events?.find((event) => event.eventAction === action)?.eventDate || null;
  const registrar = data.entities?.find((entity) => entity.roles?.includes("registrar"));
  const vcard = registrar?.vcardArray?.[1] || [];
  const registrarName = vcard.find((field) => field[0] === "fn")?.[3] || null;
  const registrationDate = eventDate("registration") || eventDate("registered");
  const expirationDate = eventDate("expiration");
  const ageDays = registrationDate ? Math.max(0, Math.floor((Date.now() - Date.parse(registrationDate)) / 86_400_000)) : null;
  const countryField = vcard.find((field) => field[0] === "adr")?.[3];
  const registrantCountry = Array.isArray(countryField) ? countryField.at(-1) : null;
  return {
    type,
    registrar: registrarName,
    registrationDate,
    expirationDate,
    ageDays,
    registrantCountry: registrantCountry || null,
    nameservers: (data.nameservers || []).map((server) => server.ldhName).filter(Boolean),
    status: data.status || [],
    handle: data.handle || null,
  };
}

function getTls(hostname, addresses) {
  if (!addresses.length || net.isIP(hostname)) return Promise.resolve(null);
  const address = addresses[0];
  if (!isPublicAddress(address)) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => {
      socket.destroy();
      finish(new Error("TLS connection timed out."));
    }, 5000);
    const socket = tls.connect({
      host: address,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
    });
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const validFrom = Date.parse(certificate.valid_from);
      const validTo = Date.parse(certificate.valid_to);
      const daysRemaining = Number.isFinite(validTo) ? Math.floor((validTo - Date.now()) / 86_400_000) : null;
      const selfSigned = certificate.issuerCertificate?.fingerprint256 === certificate.fingerprint256;
      const cipher = socket.getCipher()?.name || null;
      const weakEncryption = /(?:RC4|DES|3DES|NULL|EXPORT|MD5)/i.test(cipher || "");
      const grade = weakEncryption ? "F" : socket.authorized && daysRemaining > 30 ? "A"
        : socket.authorized && daysRemaining >= 0 ? "B"
          : selfSigned || !socket.authorized ? "F" : "C";
      const chain = [];
      let current = certificate;
      const seen = new Set();
      while (current?.subject && chain.length < 8) {
        const key = current.fingerprint256 || JSON.stringify(current.subject);
        if (seen.has(key)) break;
        seen.add(key);
        chain.push(current.subject.CN || current.subject.O || "Certificate");
        if (current.issuerCertificate === current) break;
        current = current.issuerCertificate;
      }
      finish(null, {
        issuer: certificate.issuer?.O || certificate.issuer?.CN || "Unknown issuer",
        validFrom: Number.isFinite(validFrom) ? new Date(validFrom).toISOString() : null,
        validUntil: Number.isFinite(validTo) ? new Date(validTo).toISOString() : null,
        daysRemaining,
        tlsVersion: socket.getProtocol(),
        chain,
        authorized: socket.authorized,
        authorizationError: socket.authorized ? null : String(socket.authorizationError || "Certificate is not trusted"),
        selfSigned,
        cipher,
        weakEncryption,
        grade,
      });
      socket.end();
    });
    socket.once("error", (error) => finish(error));
  });
}

function parseIpApi(data) {
  if (data.status !== "success") throw new Error(data.message || "IP geolocation lookup failed.");
  return {
    ip: data.query,
    country: data.country,
    countryCode: data.countryCode,
    region: data.regionName,
    city: data.city,
    coordinates: typeof data.lat === "number" && typeof data.lon === "number" ? [data.lat, data.lon] : null,
    timezone: data.timezone,
    isp: data.isp,
    organization: data.org,
    asn: data.as,
  };
}

async function runProvider(name, enabled, callback) {
  if (!enabled) return { status: "not_configured", data: null, error: "API key is not configured." };
  try {
    return { status: "available", data: await callback(), error: null };
  } catch (error) {
    return { status: "unavailable", data: null, error: error.message };
  }
}

function scoreReport({ target, dns, rdap, tlsReport, threats }) {
  const findings = [];
  let risk = 15;
  const add = (points, title, detail, source) => {
    risk += points;
    findings.push({ title, detail, source, points });
  };
  const allThreats = Object.values(threats);
  const hits = allThreats.flatMap((provider) => provider.status === "available" ? provider.data?.matches || [] : []);
  if (hits.length) {
    add(90, "Threat intelligence match", `${hits.length} potential threat indicator(s) were reported by a configured feed.`, "Threat feeds");
  }
  if (rdap?.ageDays !== null && rdap?.ageDays !== undefined && rdap.ageDays < 30) {
    add(20, "Recently registered domain", `Registration data indicates this domain is about ${rdap.ageDays} days old.`, "RDAP");
  } else if (rdap?.ageDays !== null && rdap?.ageDays !== undefined && rdap.ageDays > 365) {
    add(-8, "Established domain", "Registration data indicates this domain has existed for more than a year.", "RDAP");
  }
  if (tlsReport && tlsReport.grade === "F") add(20, "TLS certificate concern", "The HTTPS certificate is expired, untrusted, or self-signed.", "TLS");
  else if (tlsReport && tlsReport.daysRemaining !== null && tlsReport.daysRemaining <= 14) add(8, "TLS certificate expiring", "The certificate expires within 14 days.", "TLS");
  if (tlsReport?.weakEncryption) add(20, "Weak TLS cipher", "The negotiated cipher matches a deprecated or weak encryption pattern.", "TLS");
  const abuseConfidence = threats.abuseIpDb.status === "available" ? threats.abuseIpDb.data.abuseConfidenceScore : null;
  if (abuseConfidence !== null && abuseConfidence >= 50) {
    add(20, "Abuse reports for hosting IP", `AbuseIPDB reports an abuse confidence score of ${abuseConfidence}/100 for the resolved IP.`, "AbuseIPDB");
  } else if (abuseConfidence !== null && abuseConfidence >= 10) {
    add(8, "Some abuse reports for hosting IP", `AbuseIPDB reports an abuse confidence score of ${abuseConfidence}/100 for the resolved IP.`, "AbuseIPDB");
  }
  const otxPulseCount = threats.otx.status === "available" ? threats.otx.data.pulseCount : 0;
  if (otxPulseCount >= 3) add(12, "Multiple threat-intelligence pulses", `AlienVault OTX reports ${otxPulseCount} pulses associated with this indicator.`, "AlienVault OTX");
  if (!target.isIp) {
    const tld = target.hostname.split(".").at(-1);
    if (["zip", "mov", "click", "country", "gq", "tk", "ml", "cf", "top", "work", "rest"].includes(tld)) {
      add(7, "Higher-abuse TLD", `The .${tld} TLD is reported more often in abuse datasets; this alone does not establish malicious activity.`, "URL structure");
    }
    if (target.hostname.split(".").length > 4) add(7, "Many subdomains", "Several subdomain levels can make the registered domain harder to identify.", "URL structure");
    if (SHORTENED_DOMAINS.has(target.hostname)) add(8, "Shortened URL", "The final destination is not visible from this shortened address.", "URL structure");
    const registrableLabel = target.domain.split(".")[0].replaceAll("-", "");
    const similarBrand = COMMON_BRANDS.find((brand) => registrableLabel !== brand && isNearBrandName(registrableLabel, brand));
    if (similarBrand) add(15, "Possible typosquatting", `The domain name resembles “${similarBrand}”; verify the exact spelling.`, "URL structure");
    if (/(?:login|verify|account|secure|update|password|wallet|confirm)[-_]/i.test(target.url)) {
      add(6, "Account-related wording", "The URL contains account-prompt wording; verify the domain before signing in.", "URL structure");
    }
  }
  risk = Math.max(0, Math.min(100, risk));
  const level = risk <= 20 ? "Safe" : risk <= 50 ? "Low Risk" : risk <= 75 ? "Suspicious" : "Malicious";
  return { score: risk, risk, level, findings };
}

const SHORTENED_DOMAINS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"]);
const COMMON_BRANDS = ["google", "paypal", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix", "github"];

function isNearBrandName(candidate, brand) {
  if (Math.abs(candidate.length - brand.length) > 1 || candidate.length < 4) return false;
  let previous = Array.from({ length: brand.length + 1 }, (_, index) => index);
  for (let index = 1; index <= candidate.length; index += 1) {
    const current = [index];
    for (let other = 1; other <= brand.length; other += 1) {
      current[other] = Math.min(
        previous[other] + 1,
        current[other - 1] + 1,
        previous[other - 1] + (candidate[index - 1] === brand[other - 1] ? 0 : 1),
      );
    }
    previous = current;
  }
  return previous[brand.length] === 1;
}


function categoryOf(target, threats) {
  const matches = Object.values(threats).some((provider) => provider.status === "available" && provider.data?.matches?.length);
  if (matches) return "Phishing / malware indicator";
  const value = `${target.domain}${target.pathname || ""}`.toLowerCase();
  const categories = [
    ["Banking", /\b(bank|banking|creditunion|financial)\b/],
    ["Government", /\.(gov|gouv|govt)(\.|$)|\b(government|municipal)\b/],
    ["Education", /\.(edu|ac)(\.|$)|\b(university|school|education|academy)\b/],
    ["Cryptocurrency", /\b(crypto|bitcoin|ethereum|blockchain|wallet|token)\b/],
    ["Shopping", /\b(shop|store|market|cart|retail|amazon|ebay|etsy)\b/],
    ["News", /\b(news|media|press|journal|times|reuters)\b/],
    ["Social Media", /\b(social|community|reddit|facebook|instagram|tiktok|linkedin)\b/],
    ["Entertainment", /\b(movie|music|stream|entertainment|netflix|spotify)\b/],
    ["Gaming", /\b(game|gaming|play|steam|xbox|playstation)\b/],
    ["Adult Content", /\.(xxx|adult)(\.|$)|\b(adult|explicit)\b/],
    ["Technology", /\b(tech|software|developer|cloud|github|microsoft|apple)\b/],
  ];
  return categories.find(([, pattern]) => pattern.test(value))?.[0] || "Uncategorized";
}

async function buildReport(input, fetchImpl = globalThis.fetch) {
  const target = canonicalizeTarget(input);
  const dns = await getDns(target.hostname, target.isIp ? target.hostname : null, fetchImpl);
  const lookupIp = target.isIp ? target.hostname : dns.resolvedAddresses[0] || null;
  const threats = {};
  const configured = {
    safeBrowsing: process.env.GOOGLE_SAFE_BROWSING_API_KEY,
    virusTotal: process.env.VIRUSTOTAL_API_KEY,
    urlhaus: process.env.URLHAUS_AUTH_KEY,
    abuseIpDb: process.env.ABUSEIPDB_API_KEY,
    otx: process.env.OTX_API_KEY,
  };
  const reputationPromise = Promise.all([
    runProvider("Google Safe Browsing", configured.safeBrowsing, async () => {
      const url = new URL("https://safebrowsing.googleapis.com/v5/urls:search");
      url.searchParams.set("key", configured.safeBrowsing);
      url.searchParams.set("urls", target.url);
      const data = await fetchJson(url, {}, 7000, fetchImpl);
      if (data.threats !== undefined && !Array.isArray(data.threats)) throw new Error("Invalid threat response.");
      if ((data.threats || []).some((threat) => !Array.isArray(threat.threatTypes)
        || threat.threatTypes.some((type) => !THREAT_TYPES.has(type)))) {
        throw new Error("Google Safe Browsing returned an unknown threat classification.");
      }
      if ((data.threats || []).length && !/^(\d+(?:\.\d+)?)s$/.test(data.cacheDuration || "")) {
        throw new Error("Google Safe Browsing returned a threat match without a valid expiration.");
      }
      return {
        matches: (data.threats || []).flatMap((threat) =>
          (threat.threatTypes || []).filter((type) => THREAT_TYPES.has(type)).map((type) => ({ type, source: "Google Safe Browsing" })),
        ),
        cacheDuration: data.cacheDuration || null,
      };
    }),
    runProvider("VirusTotal", configured.virusTotal, async () => {
      const urlId = Buffer.from(target.url).toString("base64url").replace(/=+$/, "");
      const data = await fetchJson(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { "x-apikey": configured.virusTotal },
      }, 7000, fetchImpl);
      const attributes = data.data?.attributes;
      if (!attributes) throw new Error("VirusTotal report is missing URL attributes.");
      const stats = attributes.last_analysis_stats || {};
      return {
        stats,
        reputation: attributes.reputation ?? null,
        tags: Array.isArray(attributes.tags) ? attributes.tags.slice(0, 12) : [],
        lastAnalysisDate: attributes.last_analysis_date || null,
        matches: Number(stats.malicious || 0) + Number(stats.suspicious || 0) > 0
          ? [{ source: "VirusTotal", malicious: stats.malicious || 0, suspicious: stats.suspicious || 0 }]
          : [],
      };
    }),
    runProvider("URLhaus", configured.urlhaus, async () => {
      const body = new URLSearchParams({ url: target.url });
      const data = await fetchJson("https://urlhaus-api.abuse.ch/v1/url/", {
        method: "POST",
        headers: { "Auth-Key": configured.urlhaus, "Content-Type": "application/x-www-form-urlencoded" },
        body,
      }, 7000, fetchImpl);
      return { status: data.query_status, matches: data.query_status === "ok" ? [{ source: "URLhaus", threat: data.threat || null, tags: data.tags || [] }] : [] };
    }),
    runProvider("AlienVault OTX", configured.otx, async () => {
      const kind = target.ipVersion === 6 ? "IPv6" : target.isIp ? "IPv4" : "domain";
      const endpoint = target.isIp
        ? `https://otx.alienvault.com/api/v1/indicators/${kind}/${encodeURIComponent(target.hostname)}/general`
        : `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(target.domain)}/general`;
      const data = await fetchJson(endpoint, { headers: { "X-OTX-API-KEY": configured.otx } }, 7000, fetchImpl);
      return { pulseCount: data.pulse_info?.count || 0, pulses: (data.pulse_info?.pulses || []).slice(0, 5).map((pulse) => ({ name: pulse.name, created: pulse.created, tags: pulse.tags || [] })), kind };
    }),
    runProvider("AbuseIPDB", configured.abuseIpDb && lookupIp, async () => {
      const url = new URL("https://api.abuseipdb.com/api/v2/check");
      url.searchParams.set("ipAddress", lookupIp);
      url.searchParams.set("maxAgeInDays", "90");
      url.searchParams.set("verbose", "");
      const data = await fetchJson(url, { headers: { Key: configured.abuseIpDb, Accept: "application/json" } }, 7000, fetchImpl);
      return { ip: data.data?.ipAddress, abuseConfidenceScore: data.data?.abuseConfidenceScore ?? null, totalReports: data.data?.totalReports ?? 0, countryCode: data.data?.countryCode || null };
    }),
  ]);
  const [safeBrowsing, virusTotal, urlhaus, otx, abuseIpDb] = await reputationPromise;
  threats.safeBrowsing = safeBrowsing;
  threats.virusTotal = virusTotal;
  threats.urlhaus = urlhaus;
  threats.otx = otx;
  threats.abuseIpDb = abuseIpDb;

  const parallel = await Promise.allSettled([
    getRdap(target.domain, fetchImpl),
    target.isIp ? Promise.resolve(null) : getTls(target.hostname, dns.resolvedAddresses),
    process.env.IP_API_ALLOW_HTTP === "true" && lookupIp
      ? fetchJson(`http://ip-api.com/json/${encodeURIComponent(lookupIp)}?fields=status,message,continent,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query`, {}, 6000, fetchImpl).then(parseIpApi)
      : Promise.resolve(null),
    process.env.IPINFO_TOKEN && lookupIp
      ? fetchJson(`https://ipinfo.io/${encodeURIComponent(lookupIp)}/json?token=${encodeURIComponent(process.env.IPINFO_TOKEN)}`, {}, 7000, fetchImpl).then((data) => ({
        ip: data.ip || lookupIp, hostname: data.hostname || null, city: data.city || null, region: data.region || null,
        country: data.country || null, organization: data.org || null, timezone: data.timezone || null,
        coordinates: data.loc ? data.loc.split(",").map(Number) : null,
      }))
      : Promise.resolve(null),
  ]);
  const [rdapResult, tlsResult, geoResult, ipinfoResult] = parallel;
  const rdap = rdapResult.status === "fulfilled" ? rdapResult.value : null;
  const tlsReport = tlsResult.status === "fulfilled" ? tlsResult.value : null;
  const geolocation = geoResult.status === "fulfilled" ? geoResult.value : null;
  const ipinfo = ipinfoResult.status === "fulfilled" ? ipinfoResult.value : null;
  const errors = {
    rdap: rdapResult.status === "rejected" ? rdapResult.reason.message : null,
    tls: tlsResult.status === "rejected" ? tlsResult.reason.message : null,
    geolocation: geoResult.status === "rejected" ? geoResult.reason.message : null,
    ipinfo: ipinfoResult.status === "rejected" ? ipinfoResult.reason.message : null,
  };
  const score = scoreReport({ target, dns, rdap, tlsReport, threats });
  const publicThreatMatches = Object.values(threats).filter((provider) => provider.status === "available")
    .flatMap((provider) => provider.data?.matches || []);
  const vtStats = virusTotal.status === "available" ? virusTotal.data.stats : {};
  const googleMatches = safeBrowsing.status === "available" ? safeBrowsing.data.matches : [];
  const cacheDuration = safeBrowsing.status === "available"
    ? /^(\d+(?:\.\d+)?)s$/.exec(safeBrowsing.data.cacheDuration || "")
    : null;
  const safeBrowsingTtl = googleMatches.length && cacheDuration ? Number(cacheDuration[1]) * 1000 : 5 * 60_000;
  const cacheLifetime = Math.max(1, Math.min(5 * 60_000, safeBrowsingTtl));
  const signals = [
    ...score.findings,
    ...publicThreatMatches.map((match) => ({ title: "Reputation feed match", detail: `${match.source} reported a match.`, source: match.source, points: 90 })),
  ];
  return {
    generatedAt: new Date().toISOString(),
    cacheExpiresAt: new Date(Date.now() + cacheLifetime).toISOString(),
    target: { url: target.url, domain: target.domain, hostname: target.hostname, isIp: target.isIp, ipVersion: target.ipVersion || null },
    score,
    category: categoryOf(target, threats),
    dns,
    hosting: {
      ip: lookupIp,
      provider: ipinfo?.organization || geolocation?.organization || null,
      cloudProvider: (ipinfo?.organization || geolocation?.organization || "").match(/amazon|aws|google|microsoft|azure|cloudflare/i)?.[0] || null,
      isp: geolocation?.isp || null,
      asn: geolocation?.asn || ipinfo?.organization || null,
      country: ipinfo?.country || geolocation?.country || null,
      region: ipinfo?.region || geolocation?.region || null,
      city: ipinfo?.city || geolocation?.city || null,
      coordinates: ipinfo?.coordinates || geolocation?.coordinates || null,
      organization: ipinfo?.organization || geolocation?.organization || null,
      timezone: ipinfo?.timezone || geolocation?.timezone || null,
    },
    rdap,
    tls: tlsReport,
    threats: {
      providers: threats,
      virusTotalStats: vtStats,
      communityReputation: virusTotal.status === "available" ? virusTotal.data.reputation : null,
      threatTags: virusTotal.status === "available" ? virusTotal.data.tags : [],
      otxPulseCount: otx.status === "available" ? otx.data.pulseCount : null,
      blacklistHits: publicThreatMatches.length,
      maliciousReports: Number(vtStats.malicious || 0),
      suspiciousReports: Number(vtStats.suspicious || 0),
      matches: publicThreatMatches,
    },
    signals,
    errors: { ...errors, dns: dns.errors },
    providers: [
      { id: "googleSafeBrowsing", name: "Google Safe Browsing", status: safeBrowsing.status },
      { id: "virusTotal", name: "VirusTotal", status: virusTotal.status },
      { id: "urlhaus", name: "URLhaus", status: urlhaus.status },
      { id: "abuseIpDb", name: "AbuseIPDB", status: abuseIpDb.status },
      { id: "otx", name: "AlienVault OTX", status: otx.status },
      { id: "googleDns", name: "Google DNS-over-HTTPS", status: dns.errors.length === DNS_TYPES.length ? "unavailable" : "available" },
      { id: "rdap", name: "RDAP", status: rdapResult.status === "fulfilled" && rdap ? "available" : "unavailable" },
      { id: "tls", name: "TLS certificate", status: tlsReport ? "available" : target.isIp ? "not_applicable" : "unavailable" },
      { id: "ipApi", name: "ip-api.com", status: geolocation ? "available" : "not_configured" },
      { id: "ipinfo", name: "IPinfo", status: ipinfo ? "available" : process.env.IPINFO_TOKEN ? "unavailable" : "not_configured" },
    ],
  };
}

function pruneCache() {
  const now = Date.now();
  for (const [key, entry] of cache) if (entry.expiresAt <= now) cache.delete(key);
  while (cache.size > 200) cache.delete(cache.keys().next().value);
}

function createApp({ fetchImpl = globalThis.fetch, analyze = buildReport, cacheCollection = null } = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: MAX_BODY_BYTES, strict: true }));
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https://*.tile.openstreetmap.org; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    );
    res.setHeader("Permissions-Policy", "camera=(self), geolocation=()");
    next();
  });
  app.get("/api/status", (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json({
      service: "ShadowPing URL Detector",
      providers: {
        safeBrowsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
        virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
        urlhaus: Boolean(process.env.URLHAUS_AUTH_KEY),
        abuseIpDb: Boolean(process.env.ABUSEIPDB_API_KEY),
        otx: Boolean(process.env.OTX_API_KEY),
        ipinfo: Boolean(process.env.IPINFO_TOKEN),
        dns: true,
        rdap: true,
        ipApi: process.env.IP_API_ALLOW_HTTP === "true",
      },
      persistentCache: Boolean(cacheCollection),
    });
  });
  app.post("/api/analyze", async (req, res) => {
    const address = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    const window = (rateWindows.get(address) || []).filter((time) => now - time < 60_000);
    if (window.length >= 10) {
      res.setHeader("Retry-After", "60");
      return res.status(429).json({ error: "Analysis rate limit reached. Wait one minute and try again." });
    }
    window.push(now);
    rateWindows.set(address, window);
    if (rateWindows.size > 500) {
      for (const [client, times] of rateWindows) {
        const active = times.filter((time) => now - time < 60_000);
        if (active.length) rateWindows.set(client, active);
        else rateWindows.delete(client);
      }
    }
    let target;
    try {
      target = canonicalizeTarget(req.body?.target);
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
    const providerSignature = [
      process.env.GOOGLE_SAFE_BROWSING_API_KEY,
      process.env.VIRUSTOTAL_API_KEY,
      process.env.URLHAUS_AUTH_KEY,
      process.env.ABUSEIPDB_API_KEY,
      process.env.OTX_API_KEY,
      process.env.IPINFO_TOKEN,
      process.env.IP_API_ALLOW_HTTP === "true",
    ].map(Boolean).map(Number).join("");
    const cacheKey = `${target.url}:${providerSignature}`;
    pruneCache();
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      res.setHeader("X-Cache", "HIT");
      return res.json(cached.report);
    }
    try {
      if (cacheCollection) {
        const stored = await cacheCollection.findOne({ _id: cacheKey, expiresAt: { $gt: new Date(now) } });
        if (stored?.report) {
          cache.set(cacheKey, { report: stored.report, expiresAt: new Date(stored.expiresAt).valueOf() });
          res.setHeader("X-Cache", "MONGODB");
          return res.json(stored.report);
        }
      }
      const report = await analyze(target.url, fetchImpl);
      const expiresAt = new Date(report.cacheExpiresAt).valueOf();
      cache.set(cacheKey, { report, expiresAt });
      if (cacheCollection) {
        await cacheCollection.updateOne(
          { _id: cacheKey },
          { $set: { report, expiresAt: new Date(expiresAt) } },
          { upsert: true },
        );
      }
      res.setHeader("X-Cache", "MISS");
      return res.json(report);
    } catch (error) {
      if (error instanceof SyntaxError) return res.status(400).json({ error: "Request body must be valid JSON." });
      console.error("ShadowPing analysis failed:", error.message);
      return res.status(502).json({ error: error.message || "Analysis failed." });
    }
  });
  app.get("/api/health", (_req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));
  app.use(express.static(path.join(__dirname, "dist"), { index: false, maxAge: "1h" }));
  app.get("*splat", (req, res, next) => {
    if (req.path.startsWith("/api/")) return res.status(404).json({ error: "API route not found." });
    res.setHeader("Cache-Control", "no-cache");
    return res.sendFile(path.join(__dirname, "dist", "index.html"), (error) => {
      if (error) next(error);
    });
  });
  app.use((error, _req, res, _next) => {
    if (res.headersSent) return;
    if (error.type === "entity.too.large") return res.status(413).json({ error: "Request body exceeds 8 KB." });
    console.error("HTTP request failed:", error.message);
    return res.status(500).json({ error: "Internal server error." });
  });
  return app;
}

if (require.main === module) {
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error("PORT must be between 1 and 65535.");
  async function start() {
    let client;
    let cacheCollection = null;
    if (process.env.MONGODB_URI) {
      client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
      await client.connect();
      cacheCollection = client.db(process.env.MONGODB_DATABASE || "shadowping").collection("threatCache");
      await cacheCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
      console.log("MongoDB threat cache enabled (cache records expire automatically).");
    }
    const server = createApp({ cacheCollection }).listen(PORT, "0.0.0.0", () => {
      console.log(`ShadowPing API listening on port ${PORT}`);
    });
    const shutdown = async () => {
      server.close();
      await client?.close();
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  }
  start().catch((error) => {
    console.error("Could not start ShadowPing:", error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  buildReport,
  canonicalizeTarget,
  createApp,
  isPublicAddress,
  scoreReport,
};
