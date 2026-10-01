const assert = require("node:assert/strict");
const http = require("node:http");
const { EventEmitter } = require("node:events");
const test = require("node:test");

const {
  assertSafeOutboundUrl,
  attachDeadline,
  createSafeLookup,
  isPrivateIp,
} = require("../server");

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

test("isPrivateIp blocks IPv4 addresses embedded in IPv6", () => {
  assert.equal(isPrivateIp("::ffff:127.0.0.1"), true);
  assert.equal(isPrivateIp("::ffff:7f00:1"), true);
  assert.equal(isPrivateIp("::ffff:a9fe:a9fe"), true);
  assert.equal(isPrivateIp("::127.0.0.1"), true);
  assert.equal(isPrivateIp("64:ff9b::7f00:1"), true);
  assert.equal(isPrivateIp("2002:c0a8:0101::1"), true);
  assert.equal(isPrivateIp("::ffff:8.8.8.8"), false);
  assert.equal(isPrivateIp("2002:808:808::1"), false);
});

test("isPrivateIp blocks reserved IPv6 ranges and accepts bracketed or zoned input", () => {
  assert.equal(isPrivateIp("::"), true);
  assert.equal(isPrivateIp("2001:db8::1"), true);
  assert.equal(isPrivateIp("2001:0:4136:e378::1"), true);
  assert.equal(isPrivateIp("fec0::1"), true);
  assert.equal(isPrivateIp("ff02::1"), true);
  assert.equal(isPrivateIp("fe80::1%eth0"), true);
  assert.equal(isPrivateIp("[::1]"), true);
  assert.equal(isPrivateIp("2606:4700:4700::1111"), false);
});

test("isPrivateIp blocks documentation and benchmarking IPv4 ranges", () => {
  assert.equal(isPrivateIp("0.0.0.0"), true);
  assert.equal(isPrivateIp("100.64.0.1"), true);
  assert.equal(isPrivateIp("198.18.0.1"), true);
  assert.equal(isPrivateIp("198.51.100.7"), true);
  assert.equal(isPrivateIp("203.0.113.7"), true);
  assert.equal(isPrivateIp("255.255.255.255"), true);
  assert.equal(isPrivateIp("1.1.1.1"), false);
});

test("assertSafeOutboundUrl rejects IPv4-mapped and NAT64 loopback and metadata URLs", async () => {
  await assert.rejects(() => assertSafeOutboundUrl("http://[::ffff:127.0.0.1]/"), /blocked/);
  await assert.rejects(() => assertSafeOutboundUrl("http://[::ffff:169.254.169.254]/latest/meta-data/"), /blocked/);
  await assert.rejects(() => assertSafeOutboundUrl("http://[64:ff9b::7f00:1]/"), /blocked/);
});

test("createSafeLookup rejects any private address in the answer", async () => {
  const lookup = createSafeLookup((hostname, options, callback) => {
    callback(null, [{ address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 }]);
  });
  const error = await new Promise((resolve) => lookup("rebind.example", {}, resolve));
  assert.equal(error.code, "EBLOCKEDADDRESS");
});

test("createSafeLookup returns single or all addresses as the caller requested", async () => {
  const answers = [{ address: "93.184.216.34", family: 4 }, { address: "2606:2800:220:1::1", family: 6 }];
  const lookup = createSafeLookup((hostname, options, callback) => callback(null, answers));

  const single = await new Promise((resolve) => lookup("example.test", { family: 0 }, (...args) => resolve(args)));
  assert.deepEqual(single, [null, "93.184.216.34", 4]);

  const all = await new Promise((resolve) => lookup("example.test", { all: true }, (...args) => resolve(args)));
  assert.deepEqual(all, [null, answers]);

  const noOptions = await new Promise((resolve) => lookup("example.test", (...args) => resolve(args)));
  assert.deepEqual(noOptions, [null, "93.184.216.34", 4]);
});

test("createSafeLookup passes resolver errors through", async () => {
  const failure = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  const lookup = createSafeLookup((hostname, options, callback) => callback(failure));
  const error = await new Promise((resolve) => lookup("missing.test", {}, resolve));
  assert.equal(error, failure);
});

test("safe lookup stops a real HTTP request to a host resolving to loopback", async (t) => {
  const server = await listen((req, res) => res.end("reached"));
  t.after(() => server.close());
  const { port } = server.address();

  const error = await new Promise((resolve) => {
    const req = http.get({ host: "localhost", port, lookup: createSafeLookup() }, () => resolve(null));
    req.on("error", resolve);
  });
  assert.ok(error, "request should not reach the local server");
  assert.equal(error.code, "EBLOCKEDADDRESS");
});

test("attachDeadline destroys a handle that outlives the deadline", async () => {
  const handle = new EventEmitter();
  const destroyed = new Promise((resolve) => {
    handle.destroy = resolve;
  });
  attachDeadline(handle, null, "Probe", 20);
  const error = await destroyed;
  assert.match(error.message, /Probe exceeded the 20 ms time limit/);
});

test("attachDeadline destroys on scan abort and cleanup disarms it", async () => {
  const controller = new AbortController();
  const aborted = { destroy: (error) => { aborted.error = error; } };
  attachDeadline(aborted, controller.signal, "Probe", 10000)();
  const live = { destroy: (error) => { live.error = error; } };
  const cleanupLive = attachDeadline(live, controller.signal, "Probe", 10000);
  controller.abort();
  cleanupLive();
  assert.equal(aborted.error, undefined);
  assert.match(live.error.message, /Scan time limit reached/);

  const already = { destroy: (error) => { already.error = error; } };
  attachDeadline(already, controller.signal, "Probe", 10000)();
  assert.match(already.error.message, /Scan time limit reached/);
});

test("attachDeadline cuts off a server that trickles a response", async (t) => {
  const server = await listen((req, res) => {
    res.writeHead(200);
    const timer = setInterval(() => res.write("."), 10);
    res.on("close", () => clearInterval(timer));
  });
  t.after(() => server.close());
  const { port } = server.address();

  const error = await new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, timeout: 5000 }, (res) => res.resume());
    const cleanup = attachDeadline(req, null, "Trickle", 150);
    req.on("error", (failure) => {
      cleanup();
      resolve(failure);
    });
  });
  assert.match(error.message, /Trickle exceeded the 150 ms time limit/);
});
