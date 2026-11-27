# ShadowPing URL Detector

**Analyze. Detect. Protect.**

ShadowPing is a React dashboard and Node.js/Express API for passive URL and infrastructure investigation. It combines public DNS-over-HTTPS and RDAP data with optional reputation feeds. The scanner never requests the submitted website itself. It resolves public DNS addresses for enrichment and makes a pinned TLS handshake only to a validated public address on port 443.

## Run locally

Requirements: Node.js 20.12 or later and npm.

```sh
npm ci
cp .env.example .env
# Add provider API keys to .env as desired.
npm run dev
```

Open <http://localhost:5173>. The Express API runs on port 3000 and the Vite development server proxies `/api` requests to it. For production, run `npm run build`, then `npm start`; Express serves the built React app and API on port 3000.

Run backend tests with `npm test`.

## Docker

Copy `.env.example` to `.env`, add the keys you have, then start the app and its MongoDB cache:

```sh
docker compose up --build
```

The Compose setup stores cached reports in the `shadowping-data` Mongo volume. Cache documents expire automatically according to their cache TTL. Submitted URLs and returned reports are included in those cache documents when MongoDB is enabled. Do not enable persistent caching unless that storage is appropriate for the URLs you submit. To run without MongoDB, run the app directly with `npm start` and leave `MONGODB_URI` unset.

## Data sources and credentials

The app does not ship API keys. Public DNS-over-HTTPS and RDAP lookups work without keys. Reputation and IP enrichment sources need their own credentials and may impose quotas, licensing, or non-commercial restrictions:

| Environment variable | Provider | Notes |
| --- | --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing v5 | Google Safe Browsing is non-commercial. Returned threat matches expire according to Google's cache duration. |
| `VIRUSTOTAL_API_KEY` | VirusTotal | A private API key is required; the free tier has restrictive usage limits. |
| `URLHAUS_AUTH_KEY` | URLhaus | Obtain a free Auth-Key from abuse.ch. |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Requires a key and is queried only for a public resolved IP. |
| `OTX_API_KEY` | AlienVault OTX | Requires an API key. |
| `IPINFO_TOKEN` | IPinfo | Optional IP geolocation and ASN enrichment. |
| `IP_API_ALLOW_HTTP=true` | ip-api.com | Opt-in only: its free API uses plain HTTP, so the IP lookup is not encrypted in transit. Leave disabled unless you accept that trade-off. |
| `MONGODB_URI` | MongoDB | Optional persistent report cache. Configure `MONGODB_DATABASE` to select a database. |

Keys are read by the server and are never bundled into browser code. The UI shows whether a provider is live, not configured, unavailable, or not applicable. A missing, rate-limited, or failed source is **unknown**, never a clean verdict.

## Analysis and limitations

- **Risk index:** 0–20 Safe, 21–50 Low Risk, 51–75 Suspicious, 76–100 Malicious. It is an explainable heuristic combining returned threat matches, age, certificate status, AbuseIPDB reports, selected URL patterns, and OTX pulse counts. A threat-feed match can raise the score sharply. This is not a calibrated probability.
- **URL category:** a best-effort heuristic over the domain/path and threat results, not a content classifier. The app does not classify the destination page's contents or detect adult content from page data.
- **DNS:** A, AAAA, MX, NS, TXT, CNAME, and PTR records are queried via Google DNS-over-HTTPS. Non-public resolved addresses are excluded from infrastructure enrichment and TLS connections.
- **WHOIS:** structured RDAP registration data is used; registrant details may be redacted or unavailable.
- **TLS:** certificate, validity, negotiated protocol and cipher are inspected for a domain after DNS resolves to a public IP. No private/reserved IP is probed.
- **Threat feeds:** VirusTotal, Safe Browsing, URLhaus, AbuseIPDB, and OTX have different coverage and may not have a report for every indicator. Redirects and downloaded files are not followed or fetched. The tool does not detonate files.
- **Hosting location:** geolocation is approximate and can identify a proxy or data center rather than an operator. OpenStreetMap tile requests are made by your browser when coordinates are shown.
- **Threat summary:** generated from report evidence using local rules; it is not generative AI or analyst validation.
- **QR scan:** image decoding uses the browser's `BarcodeDetector` API where supported.
- **History and trends:** recent scans are stored in the current browser. Cross-device user accounts and persistent scan history are not implemented.
- **Exports:** JSON and CSV downloads are generated locally. “Print / Save PDF” opens the browser print dialog; select “Save as PDF”.

For Google Safe Browsing's user warning and usage requirements, see [usage restrictions](https://developers.google.com/safe-browsing/v4/usage-limits) and the [v5 URL search API](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search). For commercial threat checking, use an appropriately licensed service such as Google Web Risk.

## REST endpoints

- `GET /api/health` — process health.
- `GET /api/status` — provider-key configuration status; never returns keys.
- `POST /api/analyze` — accepts `{"target":"example.com"}` and returns a report. Requests are rate-limited and private/reserved IPs, embedded URL credentials, and oversized input are rejected.

The default server listens on port `3000`; set `PORT` to change it.
