# ScamIntel

ScamIntel is a local investigation tool for suspicious websites. Give it a URL, domain, or IP address and it collects technical evidence (DNS, HTTP redirects, TLS, domain and IP registration data, page source), extracts indicators of compromise, raises risk signals, and produces a JSON report you can redact and export.

## Features

- **Targets:** URLs, bare domains (treated as `https://`), IPv4 and IPv6 addresses.
- **Collection:** DNS records (A, AAAA, MX, NS, TXT, CAA, PTR), the HTTP redirect chain, the TLS certificate, domain RDAP (registrar, registration date, domain age), and IP RDAP (network, range, country).
- **Page extraction:** emails, phone numbers, links, IP addresses, social handles, page metadata (title, Open Graph, canonical, favicon), and forms. Form fields are classified as credential, OTP, wallet secret, payment, or identity.
- **Kit detection:** Telegram bot tokens and Discord webhooks that phishing kits use to send stolen data to the operator, plus script obfuscation (eval of decoded strings, packers, obfuscator.io output, large encoded blobs).
- **Crypto wallets:** Bitcoin addresses are checked with Base58Check, bech32, and bech32m checksums. Ethereum addresses are checked against EIP-55 when written in mixed case. TRON addresses (USDT TRC20) are checked with Base58Check. Each wallet links to mempool.space, Etherscan, or Tronscan.
- **Risk signals:**
  - Transport and hosting: plain HTTP, punycode in any hostname label, IP-literal URLs, deep subdomain chains, non-standard ports.
  - Certificate: validation failures, expiry, a certificate issued in the last 7 days.
  - Registration: recently registered domains, one-year registrations, domains expiring within 30 days.
  - Forms: sensitive fields, sensitive forms that post to another domain or over plain HTTP.
  - Page content: exfiltration endpoints, obfuscated scripts.
  - Mail: no mail server on the registered domain, including when the page advertises a contact address on that domain.
- **Report export:** add report notes (title, status, category, examiner, victim, loss, jurisdiction), choose which sections to include, optionally redact victim details, then download or copy the JSON package or a plain-text IOC list.
- **Evidence hashes:** SHA-256 of the page source, the HTTP headers, the RDAP responses, and the full result.
- **Outbound safety:** requests to loopback, private, link-local, reserved, documentation, and multicast addresses are blocked. This includes IPv4 addresses embedded in IPv6 (IPv4-mapped, NAT64, 6to4). See [Security Notes](#security-notes).

## Requirements

- Node.js 18 or newer (the Docker image uses Node 20)
- npm

## Setup

```bash
npm install
npm start
```

Then open <http://localhost:3000>.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port the app listens on. |
| `SCAN_TIMEOUT_MS` | `60000` | Upper bound for a whole investigation. Collection stops when it is reached and the result is marked incomplete. |
| `ALLOWED_HOSTS` | *(empty)* | Extra comma-separated hostnames the UI may be reached under, for example behind a reverse proxy. `localhost`, `127.0.0.1`, and `[::1]` are always allowed. |

Every outbound request also has an 8-second inactivity timeout and a 15-second hard deadline.

PowerShell example:

```powershell
$env:PORT=3001; npm start
```

## Docker

Build and run locally:

```bash
docker build -t philipid3s/scam-intel .
docker run --rm -p 127.0.0.1:3000:3000 philipid3s/scam-intel
```

Or deploy the published image with Docker Compose:

```bash
docker compose up -d
```

`docker-compose.yml` publishes the app at <http://localhost:3020>, bound to `127.0.0.1` only. ScamIntel has no authentication, so keep it on loopback unless you put an authenticating reverse proxy in front of it. If you do, add the proxy's hostname to `ALLOWED_HOSTS`.

The container runs as the unprivileged `node` user. Compose also makes the filesystem read-only, drops all Linux capabilities, and sets `no-new-privileges`.

The published image is `philipid3s/scam-intel`.

## CI

- **CI** (`.github/workflows/ci.yml`) runs a syntax check and the tests on pushes to `master` and on pull requests.
- **Docker Publish** (`.github/workflows/docker-publish.yml`) runs the same checks, then builds and pushes the image on every push to `Philipid3s/scam-intel`. Forks skip this job. Every branch push gets a `sha-*` tag and a branch tag. `latest` is published only from the default branch.

The publish job needs these repository secrets:

```text
DOCKERHUB_USERNAME
DOCKERHUB_TOKEN
```

## Testing

```bash
npm test
```

The suite uses the built-in `node:test` runner and needs no network access. It covers:

- target normalization, including IPv6 URLs, and public suffix parsing
- the SSRF filter: private and reserved ranges, IPv4 embedded in IPv6, connect-time DNS checks (rebinding), and request deadlines
- the request guard: Host and Origin checks, JSON-only API, and security headers
- RDAP server selection for multi-label suffixes such as `co.uk`
- indicator extraction, form classification, and false-positive filtering
- exfiltration endpoint and script obfuscation detection
- Bitcoin, Ethereum (EIP-55 / Keccak-256), and TRON address validation
- risk signals and redirect-chain summaries
- report export and redaction
- HTTP routing

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/investigate` | Body `{"target": "<url, domain, or IP>"}` with `Content-Type: application/json` (anything else returns `415`). Returns the full investigation result as JSON. Invalid targets return `400` with `{"error": "..."}`. |

Any other path is served as a static file from `public/`.

## Data Storage

ScamIntel is stateless. Results go to the browser and are not saved on the server. Report notes exist only in the browser tab and in the JSON you export. To keep a scan, export it.

## Security Notes

This tool is for local analyst use. Do not expose it to the public internet without adding authentication, authorization, rate limiting, CSRF protection, and a hardened collection sandbox.

How the local app is protected from the browser:

- Requests whose `Host` header is not an allowed hostname are rejected with `403`. This defeats DNS-rebinding attacks, where an attacker's domain resolves to `127.0.0.1` so their page can read the app's responses.
- Requests carrying a foreign `Origin`, or marked `Sec-Fetch-Site: cross-site`, are rejected. Requiring JSON means a cross-site page cannot send a scan request without a CORS preflight, which the app never approves.
- Every response carries a strict Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, and `Referrer-Policy: no-referrer`. The UI loads no third-party resources.

How outbound requests are protected:

- Before each request, the target hostname is resolved and rejected if any address is non-public.
- HTTP, HTTPS, and TLS sockets use a resolver that checks the exact address being connected to. A hostname that rebinds to an internal address between the check and the connection is still blocked.
- Every redirect hop is checked separately.
- RDAP lookups go only to servers listed in the IANA bootstrap registry.

Investigating hostile infrastructure is still risky. Run the app in an isolated environment. Note that the scanner's own IP address is visible to every site it investigates.

## Evidence Caveat

ScamIntel records useful technical artifacts and hashes, but it is not a forensic evidence management system. For high-assurance investigations, also preserve raw responses, screenshots, details of the collection environment, and chain-of-custody records outside the app.

## Project Structure

```text
server.js               HTTP server, collectors, extractors, risk signals, API
public/index.html       UI markup
public/app.js           UI rendering and interactions
public/report-export.js Report payload and redaction (shared by browser and tests)
public/styles.css       UI styles
public/favicon.svg      App icon
test/                   node:test suites
```

## License

No license has been selected yet. Add one before publishing publicly if you want others to use or contribute to the project.
