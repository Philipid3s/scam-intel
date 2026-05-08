# ScamIntel

ScamIntel is a local scam and fraud website investigation platform. It collects technical evidence from suspicious URLs, domains, and IP addresses, extracts indicators, preserves scan history, and builds reusable case intelligence.

## Features

- URL, domain, and IP investigation
- DNS, HTTP redirect, TLS certificate, RDAP, and IP allocation collection
- Page-source indicator extraction for emails, links, IPs, phones, social handles, forms, and crypto wallets
- Validated Bitcoin and Ethereum wallet recognition
- BTC and ETH explorer links for detected wallets
- Case metadata, scan history, audit log, evidence hashes, and JSON export
- IOC reuse pivots and relationship graph
- SSRF protections for local, private, reserved, multicast, and metadata-style IP ranges

## Requirements

- Node.js 18 or newer
- npm

## Setup

```bash
npm install
npm start
```

Then open:

```text
http://localhost:3000
```

To use another port:

```powershell
$env:PORT=3001; npm start
```

## Docker

Build and run locally:

```bash
docker build -t philipid3s/scam-intel .
docker run --rm -p 3000:3000 philipid3s/scam-intel
```

The published image is:

```text
philipid3s/scam-intel
```

GitHub Actions builds and pushes the Docker image on every push. Configure these repository secrets before relying on the workflow:

```text
DOCKERHUB_USERNAME
DOCKERHUB_TOKEN
```

The workflow publishes `sha-*` and branch tags for every branch push. It publishes `latest` only from the default branch.

## Testing

```bash
npm test
```

The test suite covers target normalization, public suffix parsing, SSRF blocking, indicator extraction, and wallet validation.

## Data Storage

ScamIntel is currently stateless. Investigation results are returned to the browser but are not saved to a local database.

## Security Notes

This tool is intended for local analyst use. Do not expose it directly to the public internet without adding authentication, authorization, rate limiting, CSRF protection, and a hardened collection sandbox.

Outbound URL collection blocks private and local network targets, but suspicious website investigation is inherently risky. Run the app in an isolated environment when handling hostile infrastructure.

## Evidence Caveat

ScamIntel records useful technical artifacts and hashes, but it is not yet a full forensic evidence management system. For high-assurance investigations, preserve raw responses, screenshots, collection environment details, and chain-of-custody records outside the app as well.

## Project Structure

```text
server.js          Node HTTP server, scanner, and API routes
public/           Browser UI
test/             Node test suite
```

## License

No license has been selected yet. Add a license before publishing publicly if you want others to use or contribute to the project.
