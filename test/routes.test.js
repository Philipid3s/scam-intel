const assert = require("node:assert/strict");
const test = require("node:test");

const { checkRequestOrigin, server } = require("../server");

const JSON_HEADERS = { "content-type": "application/json" };

test("HTTP routes", async (t) => {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  await t.test("serves the UI at / with or without a query string", async () => {
    for (const path of ["/", "/?ref=bookmark"]) {
      const response = await fetch(`${base}${path}`);
      assert.equal(response.status, 200, path);
      assert.match(response.headers.get("content-type"), /text\/html/);
    }
  });

  await t.test("answers HEAD requests for static files", async () => {
    const response = await fetch(`${base}/`, { method: "HEAD" });
    assert.equal(response.status, 200);
  });

  await t.test("rejects path traversal outside the public directory", async () => {
    const response = await fetch(`${base}/..%2fserver.js`);
    assert.notEqual(response.status, 200);
  });

  await t.test("returns 404 for removed persistence endpoints", async () => {
    for (const path of ["/api/cases", "/api/graph", "/api/pivots", "/api/cases/1"]) {
      const response = await fetch(`${base}${path}`);
      assert.equal(response.status, 404, path);
    }
    const response = await fetch(`${base}/api/cases`, { method: "DELETE" });
    assert.equal(response.status, 404);
  });

  await t.test("returns 400 for malformed or blocked investigation requests", async () => {
    const malformed = await fetch(`${base}/api/investigate`, { method: "POST", headers: JSON_HEADERS, body: "{not json" });
    assert.equal(malformed.status, 400);

    const unsupported = await fetch(`${base}/api/investigate`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ target: "ftp://example.test" }),
    });
    assert.equal(unsupported.status, 400);
    assert.match((await unsupported.json()).error, /Only HTTP and HTTPS/);
  });

  await t.test("rejects investigation requests that are not JSON", async () => {
    for (const contentType of ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"]) {
      const response = await fetch(`${base}/api/investigate`, {
        method: "POST",
        headers: { "content-type": contentType },
        body: JSON.stringify({ target: "example.test" }),
      });
      assert.equal(response.status, 415, contentType);
    }
  });

  await t.test("rejects cross-origin investigation requests", async () => {
    const response = await fetch(`${base}/api/investigate`, {
      method: "POST",
      headers: { ...JSON_HEADERS, origin: "https://attacker.example" },
      body: JSON.stringify({ target: "example.test" }),
    });
    assert.equal(response.status, 403);
  });

  await t.test("sends security headers with every response", async () => {
    for (const path of ["/", "/app.js", "/api/missing"]) {
      const response = await fetch(`${base}${path}`);
      assert.match(response.headers.get("content-security-policy"), /default-src 'none'.*frame-ancestors 'none'/, path);
      assert.equal(response.headers.get("x-content-type-options"), "nosniff", path);
      assert.equal(response.headers.get("referrer-policy"), "no-referrer", path);
    }
  });

  await t.test("returns 405 for unsupported methods on non-API paths", async () => {
    const response = await fetch(`${base}/`, { method: "PUT" });
    assert.equal(response.status, 405);
  });
});

test("checkRequestOrigin blocks DNS-rebinding hosts and foreign origins", () => {
  const check = (headers) => checkRequestOrigin({ headers })?.status ?? 200;
  assert.equal(check({ host: "localhost:3000" }), 200);
  assert.equal(check({ host: "127.0.0.1:3020" }), 200);
  assert.equal(check({ host: "[::1]:3000" }), 200);
  assert.equal(check({ host: "localhost:3000", origin: "http://localhost:3000" }), 200);
  assert.equal(check({ host: "localhost:3000", "sec-fetch-site": "same-origin" }), 200);

  assert.equal(check({ host: "rebind.attacker.example:3000" }), 403);
  assert.equal(check({}), 403);
  assert.equal(check({ host: "localhost:3000", origin: "https://attacker.example" }), 403);
  assert.equal(check({ host: "localhost:3000", origin: "null" }), 403);
  assert.equal(check({ host: "localhost:3000", "sec-fetch-site": "cross-site" }), 403);
});

test("checkRequestOrigin honours an extended allowlist", () => {
  const allowed = new Set(["localhost", "scamintel.internal"]);
  assert.equal(checkRequestOrigin({ headers: { host: "scamintel.internal" } }, allowed), null);
  assert.equal(checkRequestOrigin({ headers: { host: "other.internal" } }, allowed).status, 403);
});
