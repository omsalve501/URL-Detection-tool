import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowRight, BadgeCheck, BarChart3,
  BellRing, BookOpenCheck, Building2, CalendarDays, Check, ChevronDown, ChevronRight,
  CircleHelp, Copy, Crosshair, Database, Download,
  FileJson2, FileSpreadsheet, Fingerprint, Globe2, History, House, Info,
  Link2, LoaderCircle, LockKeyhole, MapPin, Menu, Network, Radar, Search,
  Server, Shield, ShieldAlert, ShieldCheck, ShieldHalf, Sparkles, Terminal, Upload,
  Wifi, X,
} from "lucide-react";

const ChartVisualization = lazy(() => import("./ChartVisualization.jsx"));
const MapPanel = lazy(() => import("./MapPanel.jsx"));

const HISTORY_KEY = "shadowping-history-v1";
const SAMPLE_TARGETS = ["cloudflare.com", "github.com", "1.1.1.1"];
const PROVIDER_LABELS = {
  googleSafeBrowsing: "Google Safe Browsing",
  virusTotal: "VirusTotal",
  urlhaus: "URLhaus",
  abuseIpDb: "AbuseIPDB",
  otx: "AlienVault OTX",
  googleDns: "Google DNS",
  rdap: "RDAP / WHOIS",
  tls: "SSL / TLS",
  ipApi: "ip-api.com",
  ipinfo: "IPinfo",
};
const THREAT_COLORS = ["#ff4655", "#ffb547", "#26c9eb", "#7d8cff"];
const KNOWN_BRANDS = ["google", "paypal", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix", "github", "bankofamerica"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"];
const DANGEROUS_TLDS = new Set(["zip", "mov", "click", "country", "gq", "tk", "ml", "cf", "top", "work", "rest"]);
const GOOGLE_THREAT_INFO = {
  SOCIAL_ENGINEERING: ["phishing or deceptive content", "https://www.antiphishing.org/", "Learn about phishing"],
  MALWARE: ["malware", "https://developers.google.com/search/docs/monitor-debug/security/malware", "Learn about malware warnings"],
  UNWANTED_SOFTWARE: ["unwanted software", "https://www.google.com/about/company/unwanted-software-policy.html", "Review the Unwanted Software Policy"],
  POTENTIALLY_HARMFUL_APPLICATION: ["a potentially harmful application", "https://developers.google.com/safe-browsing/v4/advisory", "Learn about Safe Browsing advisories"],
};

function readHistory() {
  try {
    const items = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(items) ? items.slice(0, 7) : [];
  } catch {
    return [];
  }
}

function downloadFile(filename, contents, type) {
  const blob = new Blob([contents], { type });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(href);
}

function escapeCsv(value) {
  const text = value == null ? "" : String(value);
  return `"${text.replaceAll('"', '""')}"`;
}

function getSummary(report) {
  const risk = report.score.risk;
  const positive = report.signals.length ? report.signals.map((finding) => finding.title.toLowerCase()) : ["no significant risk indicators were returned"];
  const feedCount = report.providers.filter((provider) => provider.status === "available").length;
  return `${report.target.domain} has a ${report.score.level.toLowerCase()} risk rating (${risk}/100). Category estimate: ${report.category}. ${feedCount} data sources responded. Key findings: ${positive.join(", ")}. Results are intelligence signals, not a guarantee of safety.`;
}

function formatDate(value) {
  if (!value) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Not reported" : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function remainingDays(value) {
  if (!value) return null;
  return Math.floor((new Date(value).valueOf() - Date.now()) / 86_400_000);
}

function riskClass(level = "") {
  return level.toLowerCase().replaceAll(" ", "-");
}

function display(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) return value.length ? value.join(", ") : fallback;
  return value;
}

function shortDomain(value = "") {
  return value.replace(/^https?:\/\//i, "").split(/[/?#]/)[0];
}

function editDistance(a, b) {
  const row = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    let diagonal = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const previous = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diagonal + (a[i - 1] === b[j - 1] ? 0 : 1));
      diagonal = previous;
    }
  }
  return row[b.length];
}

function analyzeLocalSignals(report) {
  const hostname = report.target.hostname.toLowerCase();
  const domain = report.target.domain.split(".")[0];
  const tld = report.target.hostname.split(".").at(-1);
  const signals = [];
  if (DANGEROUS_TLDS.has(tld)) signals.push({ title: "Higher-abuse TLD", detail: `.${tld} has elevated abuse in some threat datasets; this is not proof of malicious activity.`, tone: "warning" });
  const brand = KNOWN_BRANDS.find((item) => domain !== item && editDistance(domain, item) <= 1);
  if (brand) signals.push({ title: "Possible lookalike domain", detail: `The domain name resembles “${brand}”. Confirm the exact spelling before signing in.`, tone: "danger" });
  if (SHORTENERS.some((shortener) => hostname === shortener || hostname.endsWith(`.${shortener}`))) signals.push({ title: "URL shortener", detail: "The final destination is not visible in the shortened URL.", tone: "warning" });
  if (/(?:login|verify|account|secure|update|password|wallet|confirm)[-_]/i.test(report.target.url)) signals.push({ title: "Account-related wording", detail: "Words often used in account prompts appear in the address. Check the domain carefully.", tone: "warning" });
  if (report.target.url.length > 150) signals.push({ title: "Long URL", detail: "A long address can make the actual destination harder to review.", tone: "warning" });
  return signals;
}

function riskBreakdown(report) {
  const stats = report.threats.virusTotalStats || {};
  const otxPulses = report.threats.otxPulseCount || 0;
  return [
    { name: "Malicious", value: Math.max(Number(stats.malicious || report.threats.maliciousReports || 0), report.threats.blacklistHits || 0), color: THREAT_COLORS[0] },
    { name: "Suspicious", value: Number(stats.suspicious || report.threats.suspiciousReports || 0), color: THREAT_COLORS[1] },
    { name: "Harmless", value: Number(stats.harmless || 0), color: THREAT_COLORS[2] },
    { name: "OTX pulses", value: Number(otxPulses), color: THREAT_COLORS[3] },
  ];
}

function ScoreGauge({ score, level }) {
  const color = score >= 76 ? "#ff4655" : score >= 51 ? "#ffb547" : score >= 21 ? "#26c9eb" : "#00ff66";
  return (
    <div className="gauge-wrap">
      <div className="gauge" style={{ "--gauge-value": `${score * 3.6}deg`, "--gauge-color": color }}>
        <div className="gauge-inner">
          <strong>{score}</strong>
          <span>RISK / 100</span>
        </div>
      </div>
      <div className={`risk-badge ${riskClass(level)}`}><span className="risk-dot" />{level}</div>
      <p className="gauge-note">0 = lower risk <span>·</span> 100 = higher risk</p>
    </div>
  );
}

function ProviderPill({ provider }) {
  const status = provider.status;
  const label = status === "available" ? "LIVE" : status === "not_configured" ? "KEY NEEDED" : status === "not_applicable" ? "N/A" : "OFFLINE";
  return (
    <div className={`provider-pill provider-${status}`} title={`${provider.name}: ${label}`}>
      <span className="provider-dot" />
      <span className="provider-name">{provider.name}</span>
      <span className="provider-state">{label}</span>
    </div>
  );
}

function App() {
  const [target, setTarget] = useState("");
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState(readHistory);
  const [serviceStatus, setServiceStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeNav, setActiveNav] = useState("Overview");
  const [copied, setCopied] = useState(false);
  const [qrMessage, setQrMessage] = useState("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const qrInput = useRef(null);

  useEffect(() => {
    fetch("/api/status").then((response) => response.ok ? response.json() : Promise.reject())
      .then(setServiceStatus).catch(() => setServiceStatus(null));
  }, []);

  useEffect(() => {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 7)));
  }, [history]);

  const scan = useCallback(async (value = target) => {
    const query = value.trim();
    if (!query) {
      setError("Enter a URL, domain, or public IP address to start an investigation.");
      return;
    }
    setLoading(true);
    setError("");
    setReport(null);
    setActiveNav("Overview");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: query }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `Analysis request failed (${response.status}).`);
      setReport(payload);
      setTarget(payload.target.url);
      setHistory((previous) => [
        { url: payload.target.url, domain: payload.target.domain, score: payload.score.risk, level: payload.score.level, category: payload.category, scannedAt: payload.generatedAt },
        ...previous.filter((item) => item.url !== payload.target.url),
      ].slice(0, 7));
      window.setTimeout(() => document.querySelector("#report")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
    } catch (reason) {
      setError(reason.message || "The analysis could not be completed.");
    } finally {
      setLoading(false);
    }
  }, [target]);

  useEffect(() => {
    const safeBrowsing = report?.threats?.providers?.safeBrowsing;
    if (safeBrowsing?.status !== "available" || !safeBrowsing.data?.matches?.length || !report.cacheExpiresAt) return undefined;
    const delay = Math.max(0, new Date(report.cacheExpiresAt).valueOf() - Date.now());
    const timer = window.setTimeout(() => scan(report.target.url), delay);
    return () => window.clearTimeout(timer);
  }, [report, scan]);

  useEffect(() => {
    const refreshExpiredThreat = () => {
      const expiry = report?.cacheExpiresAt ? new Date(report.cacheExpiresAt).valueOf() : null;
      if (report?.threats?.providers?.safeBrowsing?.data?.matches?.length
        && expiry !== null && Date.now() >= expiry) scan(report.target.url);
    };
    document.addEventListener("visibilitychange", refreshExpiredThreat);
    return () => document.removeEventListener("visibilitychange", refreshExpiredThreat);
  }, [report, scan]);

  useEffect(() => {
    const onKey = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        document.querySelector("#target-input")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const localSignals = useMemo(() => report ? analyzeLocalSignals(report) : [], [report]);
  const chartData = useMemo(() => report ? riskBreakdown(report) : [], [report]);

  const navTo = (name, id) => {
    setActiveNav(name);
    setMobileMenuOpen(false);
    document.querySelector(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const exportJson = () => {
    if (report) downloadFile(`shadowping-${report.target.domain}-report.json`, JSON.stringify(report, null, 2), "application/json");
  };

  const exportCsv = () => {
    if (!report) return;
    const rows = [
      ["Section", "Field", "Value"],
      ["Overview", "Target", report.target.url],
      ["Overview", "Risk score", report.score.risk],
      ["Overview", "Risk level", report.score.level],
      ["Overview", "Category", report.category],
      ["DNS", "Response time (ms)", report.dns.responseTimeMs],
      ...Object.entries(report.dns.records).flatMap(([type, values]) => values.map((value) => ["DNS", type, value])),
      ["DNS", "Reverse DNS", report.dns.reverseDns.join(" | ")],
      ...Object.entries(report.hosting).map(([field, value]) => ["Infrastructure", field, Array.isArray(value) ? value.join(", ") : value]),
      ...report.providers.map((provider) => ["Provider", provider.name, provider.status]),
      ...report.signals.map((finding) => ["Finding", finding.title, finding.detail]),
    ];
    downloadFile(`shadowping-${report.target.domain}-report.csv`, rows.map((row) => row.map(escapeCsv).join(",")).join("\n"), "text/csv;charset=utf-8");
  };

  const copySummary = async () => {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(getSummary(report));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError("Clipboard access is unavailable in this browser.");
    }
  };

  const handleQrFile = async (event) => {
    setQrMessage("");
    const file = event.target.files?.[0];
    if (!file) return;
    if (!("BarcodeDetector" in window)) {
      setQrMessage("QR scanning is not supported in this browser. Try a current Chrome-based browser.");
      return;
    }
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const bitmap = await createImageBitmap(file);
      const codes = await detector.detect(bitmap);
      bitmap.close();
      const decoded = codes[0]?.rawValue;
      if (!decoded) throw new Error("No QR code was found in that image.");
      setTarget(decoded);
      setQrMessage(`QR decoded: ${shortDomain(decoded)}`);
      await scan(decoded);
    } catch (reason) {
      setQrMessage(reason.message || "Could not read the QR code.");
    } finally {
      event.target.value = "";
    }
  };

  const navItems = [
    { label: "Overview", icon: House, id: "#top" },
    { label: "DNS & Records", icon: Network, id: "#dns" },
    { label: "Infrastructure", icon: Building2, id: "#infrastructure" },
    { label: "Threat Intel", icon: Crosshair, id: "#threats" },
    { label: "SSL / TLS", icon: LockKeyhole, id: "#tls" },
    { label: "Scan History", icon: History, id: "#history" },
  ];

  return (
    <div className="app-shell" id="top">
      <aside className={`sidebar ${mobileMenuOpen ? "sidebar-open" : ""}`}>
        <a className="brand" href="#top" onClick={() => setActiveNav("Overview")}>
          <span className="brand-symbol"><Radar size={22} strokeWidth={2.2} /></span>
          <span className="brand-copy"><strong>SHADOW<span>PING</span></strong><small>URL DETECTOR</small></span>
        </a>
        <div className="sidebar-label">INTELLIGENCE PLATFORM</div>
        <nav className="main-nav" aria-label="Dashboard navigation">
          {navItems.map(({ label, icon: Icon, id }) => (
            <button type="button" className={`nav-link ${activeNav === label ? "nav-active" : ""}`} key={label} onClick={() => navTo(label, id)}>
              <Icon size={16} /><span>{label}</span>{label === "Threat Intel" && <span className="nav-indicator" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-separator" />
        <div className="sidebar-label">DATA SOURCES</div>
        <div className="source-list">
          {Object.entries(PROVIDER_LABELS).slice(0, 6).map(([id, label]) => {
            const provider = serviceStatus?.providers?.[id === "googleSafeBrowsing" ? "safeBrowsing" : id === "abuseIpDb" ? "abuseIpDb" : id === "otx" ? "otx" : id];
            return <div className="source-row" key={id}><span className={`source-led ${provider ? "source-led-on" : ""}`} /><span>{label}</span><small>{provider ? "READY" : "—"}</small></div>;
          })}
        </div>
        <div className="sidebar-bottom">
          <div className="sidebar-status"><span className="status-pulse" /><div><strong>Engine operational</strong><small>{serviceStatus ? "Provider status synced" : "Connecting to API"}</small></div><ChevronRight size={14} /></div>
          <div className="sidebar-version">SHADOWPING <span>·</span> v1.0.0</div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button type="button" className="mobile-menu" aria-label="Toggle menu" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}><Menu size={19} /></button>
          <div className="breadcrumbs"><span>Workspace</span><ChevronRight size={13} /><strong>{activeNav}</strong></div>
          <div className="topbar-actions">
            <div className={`api-health ${serviceStatus ? "api-health-live" : ""}`}><span />{serviceStatus ? "API CONNECTED" : "API OFFLINE"}</div>
            <button className="icon-button notification-button" aria-label="API information" title="API provider readiness" onClick={() => navTo("Threat Intel", "#threats")}><BellRing size={16} /></button>
            <div className="user-avatar">SP</div>
          </div>
        </header>

        <div className="workspace">
          <section className="hero-section">
            <div className="hero-copy">
              <div className="overline"><span className="overline-line" /> THREAT INTELLIGENCE · INVESTIGATION CONSOLE</div>
              <h1>SHADOWPING <span>URL DETECTOR</span></h1>
              <p>Analyze domains, detect threats, investigate infrastructure, and identify malicious activity using real-time threat intelligence.</p>
              <div className="hero-tags"><span><span className="tag-led" /> Passive-first analysis</span><span><LockKeyhole size={12} /> No destination page fetched</span></div>
            </div>
            <div className="hero-art" aria-hidden="true">
              <div className="hero-orbit orbit-outer" /><div className="hero-orbit orbit-inner" />
              <div className="hero-radar"><Radar size={47} strokeWidth={1.2} /></div><div className="radar-node node-one" /><div className="radar-node node-two" /><div className="radar-node node-three" />
              <div className="hero-coordinates">SECURE // SCAN<br />0x44.F2.91.AB</div>
            </div>
          </section>

          <section className="scan-panel" aria-label="URL investigation">
            <div className="scan-panel-heading">
              <div className="scan-heading-icon"><Crosshair size={16} /></div>
              <div><strong>New investigation</strong><span>URL · DOMAIN · PUBLIC IP</span></div>
              <span className="scan-encryption"><LockKeyhole size={11} /> SERVER-SIDE LOOKUP</span>
            </div>
            <form className="scan-form" onSubmit={(event) => { event.preventDefault(); scan(); }}>
              <div className="search-field">
                <Search size={17} />
                <input id="target-input" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="Enter a URL, domain, or IP address…" autoComplete="url" />
                <kbd>⌘ K</kbd>
              </div>
              <button className="scan-button" disabled={loading} type="submit">
                {loading ? <LoaderCircle size={16} className="spin" /> : <Radar size={16} />}
                <span>{loading ? "Analyzing…" : "Analyze URL"}</span><ArrowRight size={15} />
              </button>
              <button className="qr-button" type="button" title="Scan a QR code image" onClick={() => qrInput.current?.click()}><Upload size={15} /><span>QR scan</span></button>
              <input ref={qrInput} type="file" accept="image/*" hidden onChange={handleQrFile} />
            </form>
            <div className="scan-panel-bottom">
              <div className="quick-targets"><span>QUICK SCAN</span>{SAMPLE_TARGETS.map((sample) => <button key={sample} type="button" onClick={() => { setTarget(sample); scan(sample); }}>{sample}</button>)}</div>
              <div className="scan-tip"><Info size={12} /> Submitted target is sent to responding intelligence providers</div>
            </div>
            {error && <div className="inline-error" role="alert"><AlertTriangle size={14} />{error}</div>}
            {qrMessage && <div className="qr-message" role="status">{qrMessage}</div>}
          </section>

          {loading && <div className="loading-banner"><LoaderCircle className="spin" size={18} /><div><strong>Running intelligence checks</strong><span>Querying DNS, registration, infrastructure, TLS and configured reputation feeds…</span></div></div>}

          {!report && !loading && (
            <section className="empty-dashboard">
              <div className="empty-dashboard-icon"><ShieldHalf size={30} /></div>
              <div className="empty-dashboard-copy"><div className="overline">READY FOR ANALYSIS</div><h2>Start with a domain or IP</h2><p>Run a scan to populate reputation feeds, DNS, WHOIS, TLS, infrastructure, and risk insights in this dashboard.</p></div>
              <div className="empty-dashboard-note"><span className="status-pulse" /><span>Passive intelligence only<br /><small>Submitted URLs are never opened.</small></span></div>
            </section>
          )}

          {report && (
            <div id="report" className="report-view">
              <div className="report-title-row">
                <div><div className="overline"><span className="overline-line" /> INVESTIGATION REPORT</div><h2>{report.target.domain}</h2><p className="report-subtitle">{report.target.url} <span>·</span> scanned {new Date(report.generatedAt).toLocaleString()}</p></div>
                <div className="report-actions">
                  <button className="export-button" onClick={copySummary}><Copy size={14} />{copied ? "Copied" : "Copy summary"}</button>
                  <div className="export-menu">
                    <button className="export-primary" onClick={() => window.print()}><Download size={14} />Export report <ChevronDown size={13} /></button>
                    <div className="export-dropdown">
                      <button onClick={exportJson}><FileJson2 size={14} />Download JSON</button>
                      <button onClick={exportCsv}><FileSpreadsheet size={14} />Download CSV</button>
                      <button onClick={() => window.print()}><ArrowDownToLine size={14} />Print / Save PDF</button>
                    </div>
                  </div>
                </div>
              </div>

              <section className="overview-grid" id="overview">
                <article className="panel score-panel">
                  <div className="panel-head"><div className="panel-title"><span className="panel-icon"><ShieldCheck size={15} /></span><div><h3>Risk assessment</h3><span>AGGREGATED INTELLIGENCE</span></div></div><button className="plain-icon" title="Risk score from rules-based signals, not an AI verdict"><CircleHelp size={15} /></button></div>
                  <div className="score-content">
                    <ScoreGauge score={report.score.risk} level={report.score.level} />
                    <div className="score-findings">
                      <div className="mini-label">KEY SIGNALS <span>{report.score.findings.length}</span></div>
                      {report.score.findings.length ? report.score.findings.slice(0, 4).map((finding, index) => <div className={`finding-row ${finding.points > 0 ? "finding-risk" : "finding-positive"}`} key={`${finding.title}-${index}`}><span className="finding-dot" /><div><strong>{finding.title}</strong><small>{finding.source}</small></div><span className="finding-points">{finding.points > 0 ? "+" : ""}{finding.points}</span></div>) : <div className="no-findings"><BadgeCheck size={16} />No risk factors reported by responding sources.</div>}
                      {report.score.findings.length > 4 && <div className="more-findings">+ {report.score.findings.length - 4} additional indicators</div>}
                    </div>
                  </div>
                  <div className="score-footnote"><Info size={12} /> Scores reflect returned signals only. Missing feeds do not mean a clean result.</div>
                </article>

                <article className="panel category-panel">
                  <div className="panel-head"><div className="panel-title"><span className="panel-icon blue"><Fingerprint size={15} /></span><div><h3>Classification</h3><span>URL & THREAT CONTEXT</span></div></div><span className="category-chip">{report.target.isIp ? `IPv${report.target.ipVersion}` : "DOMAIN"}</span></div>
                  <div className="category-feature"><div className="category-glyph"><Globe2 size={21} /></div><div><span>LIKELY CATEGORY</span><strong>{report.category}</strong><small>{report.threats.blacklistHits ? "Threat feed match detected" : "Heuristic based on domain and threat feeds"}</small></div></div>
                  <div className="domain-indicators">
                    <div><span className={`indicator-status ${localSignals.some((signal) => signal.title === "Higher-abuse TLD") ? "indicator-warn" : ""}`} /><span>Suspicious TLD</span><strong>{localSignals.some((signal) => signal.title === "Higher-abuse TLD") ? "Review" : "Not flagged"}</strong></div>
                    <div><span className={`indicator-status ${localSignals.some((signal) => signal.title === "Possible lookalike domain") ? "indicator-warn" : ""}`} /><span>Typosquatting</span><strong>{localSignals.some((signal) => signal.title === "Possible lookalike domain") ? "Possible match" : "No close match"}</strong></div>
                    <div><span className="indicator-status indicator-neutral" /><span>Redirect chain</span><strong>Not followed</strong></div>
                  </div>
                </article>

                <article className="panel threat-chart-panel" id="threats">
                  <div className="panel-head"><div className="panel-title"><span className="panel-icon red"><Activity size={15} /></span><div><h3>Threat breakdown</h3><span>AVAILABLE FEED SIGNALS</span></div></div><span className="panel-count">{report.threats.blacklistHits} hits</span></div>
                  <div className="threat-chart">
                    <Suspense fallback={<div className="chart-loading">Loading chart…</div>}><ChartVisualization type="pie" data={chartData} /></Suspense>
                    <div className="chart-center"><strong>{report.threats.blacklistHits}</strong><span>FEED HITS</span></div>
                  </div>
                  <div className="chart-legend">{chartData.map((item) => <div key={item.name}><span style={{ background: item.color }} />{item.name}<strong>{item.value}</strong></div>)}</div>
                </article>

                <article className="panel summary-panel">
                  <div className="panel-head"><div className="panel-title"><span className="panel-icon violet"><Sparkles size={15} /></span><div><h3>Threat summary</h3><span>GENERATED FROM SCAN SIGNALS</span></div></div><span className="summary-type">RULES-BASED</span></div>
                  <div className="summary-body"><div className={`summary-status ${riskClass(report.score.level)}`}><ShieldAlert size={18} /><div><strong>{report.score.level} risk</strong><span>{report.score.risk}/100 risk index</span></div></div><p>{getSummary(report)}</p><div className="summary-foot"><Info size={12} /> Automated synthesis of available sources; not generative AI or a safety guarantee.</div></div>
                </article>
              </section>

              <section className="section-block" id="threat-intelligence">
                <div className="section-heading"><div><div className="overline">MULTI-SOURCE REPUTATION</div><h2>Threat intelligence center</h2></div><div className="section-side-note"><span className="live-led" /> PROVIDER STATUS</div></div>
                <div className="provider-grid">{report.providers.map((provider) => <ProviderPill key={provider.id} provider={provider} />)}</div>
                <div className="intel-grid">
                  <div className="panel intel-card">
                    <div className="panel-head"><div className="panel-title"><span className="panel-icon red"><Crosshair size={15} /></span><div><h3>Reputation & detections</h3><span>THREAT FEED RESULTS</span></div></div></div>
                    <div className="intel-stats">
                      <div><span>VT MALICIOUS</span><strong className="red-text">{display(report.threats.maliciousReports, "0")}</strong></div>
                      <div><span>VT SUSPICIOUS</span><strong className="amber-text">{display(report.threats.suspiciousReports, "0")}</strong></div>
                      <div><span>VT COMMUNITY REP</span><strong>{display(report.threats.communityReputation, "—")}</strong></div>
                      <div><span>ABUSE REPORTS</span><strong>{display(report.threats.providers.abuseIpDb.data?.totalReports, "—")}</strong></div>
                      <div><span>OTX PULSES</span><strong>{display(report.threats.otxPulseCount, "—")}</strong></div>
                    </div>
                    <div className="tag-row"><span>THREAT TAGS</span>{report.threats.threatTags.length ? report.threats.threatTags.map((tag) => <em key={tag}>{tag}</em>) : <small>No tags returned by configured sources.</small>}</div>
                    <div className="intel-footer"><Info size={12} /> Feeds that need keys show as “KEY NEEDED”; no response is not a clean verdict.</div>
                  </div>
                  <div className="panel intel-card intel-events">
                    <div className="panel-head"><div className="panel-title"><span className="panel-icon blue"><History size={15} /></span><div><h3>Threat activity</h3><span>THIS INVESTIGATION</span></div></div><span className="event-date">{new Date(report.generatedAt).toLocaleTimeString()}</span></div>
                    <div className="timeline">
                      {report.threats.matches.length ? report.threats.matches.map((match, index) => <div className="timeline-item" key={`${match.source}-${index}`}><span className="timeline-dot timeline-danger" /><div><strong>{match.source} potential match</strong><small>{match.threat || (GOOGLE_THREAT_INFO[match.type]?.[0]) || match.type || "Potential threat indicator"} · {new Date(report.generatedAt).toLocaleString()}</small></div></div>) : <div className="timeline-item"><span className="timeline-dot timeline-neutral" /><div><strong>No feed hits reported</strong><small>Only providers marked LIVE returned data for this investigation.</small></div></div>}
                      {report.providers.filter((provider) => provider.status !== "available").slice(0, 3).map((provider) => <div className="timeline-item" key={provider.id}><span className="timeline-dot timeline-muted" /><div><strong>{provider.name}: {provider.status === "not_configured" ? "API key required" : provider.status === "not_applicable" ? "Not applicable" : "Unavailable"}</strong><small>Not counted as a clear result.</small></div></div>)}
                    </div>
                    {report.threats.providers.safeBrowsing.status === "available" && report.threats.providers.safeBrowsing.data.matches.length > 0 && <div className="google-advisory"><p><a href="https://developers.google.com/safe-browsing/v4/advisory" target="_blank" rel="noopener noreferrer">Advisory provided by Google,</a></p>{[...new Set(report.threats.providers.safeBrowsing.data.matches.map((match) => match.type))].map((type) => GOOGLE_THREAT_INFO[type] && <a key={type} href={GOOGLE_THREAT_INFO[type][1]} target="_blank" rel="noopener noreferrer">{GOOGLE_THREAT_INFO[type][2]}</a>)}</div>}
                  </div>
                </div>
              </section>

              <section className="section-block" id="dns">
                <div className="section-heading"><div><div className="overline">DOMAIN NAME SYSTEM</div><h2>DNS & NSLookup</h2></div><div className="section-side-note"><Wifi size={13} /> {report.dns.responseTimeMs == null ? "—" : `${report.dns.responseTimeMs} ms`} response</div></div>
                <div className="panel dns-panel">
                  <div className="table-scroll"><table className="dns-table"><thead><tr><th>RECORD TYPE</th><th>ANSWER</th><th>COUNT</th><th>STATUS</th></tr></thead><tbody>
                    {Object.entries(report.dns.records).map(([type, values]) => <tr key={type}><td><span className="record-type">{type}</span></td><td className="record-data">{values.length ? values.map((value, index) => <code key={`${type}-${index}`}>{value}</code>) : <span className="muted-answer">No record returned</span>}</td><td>{values.length}</td><td><span className={`record-status ${values.length ? "record-found" : ""}`}>{values.length ? "RESOLVED" : "—"}</span></td></tr>)}
                    <tr><td><span className="record-type">PTR</span></td><td className="record-data">{report.dns.reverseDns.length ? report.dns.reverseDns.map((value) => <code key={value}>{value}</code>) : <span className="muted-answer">No reverse record returned</span>}</td><td>{report.dns.reverseDns.length}</td><td><span className={`record-status ${report.dns.reverseDns.length ? "record-found" : ""}`}>{report.dns.reverseDns.length ? "RESOLVED" : "—"}</span></td></tr>
                  </tbody></table></div>
                  <div className="dns-foot"><span><Database size={12} /> Source: Google DNS-over-HTTPS</span><span>{report.dns.errors.length ? `${report.dns.errors.length} record queries unavailable` : "Partial DNS results may occur"}</span></div>
                </div>
              </section>

              <section className="section-block infrastructure-section" id="infrastructure">
                <div className="section-heading"><div><div className="overline">NETWORK & REGISTRATION</div><h2>Hosting & infrastructure</h2></div><div className="section-side-note"><Globe2 size={13} /> GEOLOCATION IS APPROXIMATE</div></div>
                <div className="infrastructure-grid">
                  <div className="panel infrastructure-card">
                    <div className="panel-head"><div className="panel-title"><span className="panel-icon blue"><Server size={15} /></span><div><h3>Network intelligence</h3><span>PUBLIC IP ENRICHMENT</span></div></div></div>
                    <div className="infra-ip"><span className="ip-icon"><Network size={16} /></span><div><small>PUBLIC IP</small><strong>{display(report.hosting.ip)}</strong></div><span className="ip-version">{report.target.ipVersion ? `IPv${report.target.ipVersion}` : "A / AAAA"}</span></div>
                    <div className="data-grid">
                      <div><span>HOSTING / CLOUD</span><strong>{display(report.hosting.provider || report.hosting.cloudProvider)}</strong></div>
                      <div><span>ISP</span><strong>{display(report.hosting.isp)}</strong></div>
                      <div><span>ASN</span><strong>{display(report.hosting.asn)}</strong></div>
                      <div><span>ORGANIZATION</span><strong>{display(report.hosting.organization)}</strong></div>
                      <div><span>COUNTRY</span><strong>{display(report.hosting.country)}</strong></div>
                      <div><span>REGION / CITY</span><strong>{[report.hosting.region, report.hosting.city].filter(Boolean).join(" / ") || "—"}</strong></div>
                      <div><span>TIMEZONE</span><strong>{display(report.hosting.timezone)}</strong></div>
                      <div><span>COORDINATES</span><strong>{report.hosting.coordinates?.join(", ") || "—"}</strong></div>
                    </div>
                    <div className="source-attribution"><Info size={11} /> IP geolocation can be imprecise and may identify a proxy or data center.</div>
                  </div>
                  <div className="panel map-panel">
                    <div className="panel-head"><div className="panel-title"><span className="panel-icon green"><MapPin size={15} /></span><div><h3>Hosting location</h3><span>IP GEOLOCATION</span></div></div><MapPin size={14} className="map-pin-top" /></div>
                    <Suspense fallback={<div className="map-empty"><LoaderCircle size={17} className="spin" />Loading map…</div>}><MapPanel hosting={report.hosting} /></Suspense>
                  </div>
                </div>
                <div className="panel rdap-panel">
                  <div className="panel-head"><div className="panel-title"><span className="panel-icon violet"><BookOpenCheck size={15} /></span><div><h3>WHOIS / RDAP intelligence</h3><span>REGISTRATION DATA</span></div></div><span className="rdap-source">RDAP</span></div>
                  {report.rdap ? <div className="rdap-grid">
                    <div><span><Building2 size={12} /> REGISTRAR</span><strong>{display(report.rdap.registrar)}</strong></div>
                    <div><span><CalendarDays size={12} /> REGISTERED</span><strong>{formatDate(report.rdap.registrationDate)}</strong></div>
                    <div><span><CalendarDays size={12} /> EXPIRES</span><strong>{formatDate(report.rdap.expirationDate)}</strong></div>
                    <div><span><History size={12} /> DOMAIN AGE</span><strong>{report.rdap.ageDays == null ? "Not reported" : `${report.rdap.ageDays} days`}</strong><small className="age-track"><span style={{ width: `${Math.min(100, (report.rdap.ageDays / 365) * 100)}%` }} /></small></div>
                    <div><span><Globe2 size={12} /> REGISTRANT COUNTRY</span><strong>{display(report.rdap.registrantCountry)}</strong></div>
                    <div><span><Network size={12} /> NAME SERVERS</span><strong>{display(report.rdap.nameservers)}</strong></div>
                    <div className="rdap-status"><span><BadgeCheck size={12} /> DOMAIN STATUS</span><strong>{display(report.rdap.status)}</strong></div>
                  </div> : <div className="unavailable-panel"><Info size={15} />Registration data is not available for this target or the RDAP service did not respond.</div>}
                </div>
              </section>

              <section className="section-block" id="tls">
                <div className="section-heading"><div><div className="overline">TRANSPORT SECURITY</div><h2>SSL / TLS analysis</h2></div><div className="section-side-note"><LockKeyhole size={13} /> TLS 1.2+ RECOMMENDED</div></div>
                <div className="panel tls-panel">
                  {report.tls ? <>
                    <div className="tls-grade-block"><div className={`tls-grade grade-${report.tls.grade.toLowerCase()}`}>{report.tls.grade}</div><div><strong>Security grade</strong><span>{report.tls.authorized ? "Certificate trusted by system CA" : report.tls.authorizationError || "Certificate not trusted"}</span></div></div>
                    <div className="tls-details">
                      <div><span>ISSUER</span><strong>{report.tls.issuer}</strong></div><div><span>TLS VERSION</span><strong>{display(report.tls.tlsVersion)}</strong></div>
                      <div><span>NEGOTIATED CIPHER</span><strong className={report.tls.weakEncryption ? "red-text" : ""}>{display(report.tls.cipher)}</strong></div>
                      <div><span>VALID FROM</span><strong>{formatDate(report.tls.validFrom)}</strong></div><div><span>VALID UNTIL</span><strong>{formatDate(report.tls.validUntil)}</strong></div>
                      <div><span>DAYS REMAINING</span><strong className={report.tls.daysRemaining < 0 ? "red-text" : report.tls.daysRemaining <= 14 ? "amber-text" : ""}>{display(report.tls.daysRemaining)}</strong></div>
                      <div><span>SELF-SIGNED</span><strong>{report.tls.selfSigned ? "Yes — review" : "No"}</strong></div>
                      <div className="chain-field"><span>CERTIFICATE CHAIN</span><strong>{display(report.tls.chain)}</strong></div>
                    </div>
                  </> : <div className="unavailable-panel"><LockKeyhole size={16} />TLS certificate could not be inspected. TLS checks require a domain with a public DNS address and an accessible port 443.</div>}
                  <div className="tls-disclaimer"><Info size={12} />Certificate inspection is a point-in-time check; no TLS service is probed on private or reserved IP addresses.</div>
                </div>
              </section>

              <section className="section-block" id="signals">
                <div className="section-heading"><div><div className="overline">INVESTIGATION DETAILS</div><h2>Indicators & recommendations</h2></div><div className="section-side-note"><Terminal size={13} /> EVIDENCE-BASED</div></div>
                <div className="signal-grid">
                  <div className="panel signal-panel">
                    <div className="panel-head"><div className="panel-title"><span className="panel-icon amber"><AlertTriangle size={15} /></span><div><h3>Observed indicators</h3><span>URL & INFRASTRUCTURE SIGNALS</span></div></div></div>
                    {localSignals.length || report.signals.length ? <div className="signal-list">
                      {[...report.signals, ...localSignals].filter((signal, index, list) => list.findIndex((entry) => entry.title === signal.title) === index).map((signal, index) => <div className={`signal-detail ${signal.tone || (signal.points > 0 ? "danger" : "positive")}`} key={`${signal.title}-${index}`}><span className="signal-detail-icon">{signal.tone === "danger" || signal.points > 0 ? <AlertTriangle size={14} /> : signal.tone === "positive" ? <Check size={14} /> : <Info size={14} />}</span><div><strong>{signal.title}</strong><p>{signal.detail}</p></div><small>{signal.source || "URL ANALYSIS"}</small></div>)}
                    </div> : <div className="unavailable-panel"><BadgeCheck size={15} />No additional URL-pattern indicators were flagged.</div>}
                  </div>
                  <div className="panel recommendations-panel">
                    <div className="panel-head"><div className="panel-title"><span className="panel-icon green"><Shield size={15} /></span><div><h3>Recommended actions</h3><span>BASED ON RETURNED DATA</span></div></div></div>
                    <div className="recommendation-list">
                      {(report.threats.blacklistHits ? [
                        "Avoid visiting this URL or entering credentials while a threat-feed match is present.",
                        "Verify the destination through a trusted, independently obtained source.",
                        "Share the potential indicator with your security team for triage.",
                      ] : [
                        "Treat missing or unavailable threat feeds as unknown, not as clean results.",
                        "Verify the domain spelling and reach sensitive services from a known bookmark.",
                        "Do not enter credentials or download files solely because this report found no match.",
                      ]).map((text, index) => <div key={text}><span>0{index + 1}</span><p>{text}</p></div>)}
                    </div>
                  </div>
                </div>
              </section>

              <section className="section-block trend-block">
                <div className="section-heading"><div><div className="overline">LOCAL ACTIVITY</div><h2>Recent risk trend</h2></div><div className="section-side-note"><History size={13} /> THIS BROWSER</div></div>
                <div className="panel trend-panel">
                  {history.length > 1 ? <div className="trend-chart"><Suspense fallback={<div className="trend-empty">Loading trend…</div>}><ChartVisualization type="area" data={[...history].reverse().map((item, index) => ({ scan: index + 1, risk: item.score, domain: item.domain }))} /></Suspense></div> : <div className="trend-empty"><BarChart3 size={16} />Run additional scans to build a local risk trend. Scan history is stored in this browser only.</div>}
                  <div className="trend-foot"><span>SCAN HISTORY IS STORED LOCALLY</span><span>{history.length} / 7 recent scans</span></div>
                </div>
              </section>
            </div>
          )}

          <section className="section-block history-block" id="history">
            <div className="section-heading"><div><div className="overline">LOCAL ACTIVITY</div><h2>Scan history</h2></div><button className="text-button" onClick={() => { setHistory([]); localStorage.removeItem(HISTORY_KEY); }}>Clear history <X size={12} /></button></div>
            <div className="panel history-panel">
              {history.length ? history.map((item) => <button type="button" className="history-row" key={`${item.url}-${item.scannedAt}`} onClick={() => { setTarget(item.url); scan(item.url); }}>
                <span className={`history-risk risk-${riskClass(item.level)}`}><span />{item.score}</span><span className="history-domain"><Link2 size={14} />{item.domain}</span><span className="history-category">{item.category}</span><span className="history-date">{new Date(item.scannedAt).toLocaleString()}</span><ChevronRight size={14} />
              </button>) : <div className="history-empty"><History size={17} />Your recent investigations will appear here.</div>}
            </div>
          </section>

          <footer className="app-footer"><span>SHADOWPING URL DETECTOR <i>·</i> ANALYZE. DETECT. PROTECT.</span><span><span className="footer-green-dot" /> THREAT INTELLIGENCE IS PARTIAL BY DESIGN</span></footer>
        </div>
      </main>
      {mobileMenuOpen && <button className="mobile-scrim" aria-label="Close menu" onClick={() => setMobileMenuOpen(false)} />}
    </div>
  );
}

export default App;
