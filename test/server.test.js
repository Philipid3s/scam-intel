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
  assert.ok(indicators.socialHandles.includes("case_support"));
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
