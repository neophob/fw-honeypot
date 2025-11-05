import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";

import { ApiServer } from "../src/ApiServer.js";

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close((err) => {
        if (err) return reject(err);
        resolve(port);
      });
    });
    srv.on("error", reject);
  });
}

function httpGetText(host, port, path) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: host, port, path, method: "GET" };
    const req = http.request(opts, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (data += d));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.end();
  });
}

/*
  Helper: check whether a parsed response contains an IP substring anywhere.
*/
const containsIp = (container, ip) => {
  if (!container) return false;
  if (Array.isArray(container))
    return container.some((e) => String(e).includes(ip));
  if (typeof container === "string") return container.includes(ip);
  if (typeof container === "object")
    return Object.values(container).some((v) => containsIp(v, ip));
  return false;
};

const makeHoneypot = ({ v4 = ["1.2.3.4"], v6 = ["::1"] } = {}) => ({
  attacker: {
    ipV4: v4,
    ipV6: v6,
  },
  config: { internalApiPort: 0, host: "127.0.0.1" },
});

test("GIVEN honeypot with IPv4 and IPv6 WHEN GET /blacklist THEN returns both in plain text", async () => {
  // GIVEN
  const honeypot = makeHoneypot();
  const api = ApiServer.create(honeypot);
  const port = await getFreePort();
  api.listen(port, "127.0.0.1");
  await new Promise((r) => setTimeout(r, 20));

  // WHEN
  const res = await httpGetText("127.0.0.1", port, "/blacklist");

  // THEN
  assert.equal(res.status, 200);
  assert.ok(res.body.includes("1.2.3.4"));
  assert.ok(res.body.includes("::1"));

  // cleanup
  api.close();
});

test("GIVEN honeypot with IPv4 WHEN GET /blacklist/v4 THEN returns only IPv4", async () => {
  // GIVEN
  const honeypot = makeHoneypot({ v4: ["9.9.9.9"], v6: [] });
  const api = ApiServer.create(honeypot);
  const port = await getFreePort();
  api.listen(port, "127.0.0.1");
  await new Promise((r) => setTimeout(r, 20));

  // WHEN
  const res = await httpGetText("127.0.0.1", port, "/blacklist/v4");

  // THEN
  assert.equal(res.status, 200);
  assert.ok(res.body.includes("9.9.9.9"));
  assert.ok(!res.body.includes("::1"));

  api.close();
});

test("GIVEN honeypot with IPv4 and IPv6 WHEN GET /blacklist/json THEN returns JSON with both arrays", async () => {
  // GIVEN
  const honeypot = makeHoneypot();
  const api = ApiServer.create(honeypot);
  const port = await getFreePort();
  api.listen(port, "127.0.0.1");
  await new Promise((r) => setTimeout(r, 20));

  // WHEN
  const res = await httpGetText("127.0.0.1", port, "/blacklist/json");
  assert.equal(res.status, 200);
  const parsed = JSON.parse(res.body);

  // THEN
  assert.ok(containsIp(parsed, "1.2.3.4"));
  assert.ok(containsIp(parsed, "::1"));

  api.close();
});

test("GIVEN honeypot with IPv4 WHEN GET /blacklist/v4/json THEN returns JSON array with IPv4", async () => {
  // GIVEN
  const honeypot = makeHoneypot({ v4: ["7.7.7.7"], v6: [] });
  const api = ApiServer.create(honeypot);
  const port = await getFreePort();
  api.listen(port, "127.0.0.1");
  await new Promise((r) => setTimeout(r, 20));

  // WHEN
  const res = await httpGetText("127.0.0.1", port, "/blacklist/v4/json");
  assert.equal(res.status, 200);
  const parsed = JSON.parse(res.body);

  // THEN
  assert.ok(containsIp(parsed, "7.7.7.7"));

  api.close();
});
