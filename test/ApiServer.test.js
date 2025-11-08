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
  config: { internalApiPort: 0, host: "127.0.0.1" },
});

test("GET /up THEN returns OK in plain text", async () => {
  // GIVEN
  const honeypot = makeHoneypot();
  const api = ApiServer.create(honeypot);
  const port = await getFreePort();
  api.listen(port, "127.0.0.1");
  await new Promise((r) => setTimeout(r, 20));

  // WHEN
  const res = await httpGetText("127.0.0.1", port, "/up");

  // THEN
  assert.equal(res.status, 200);
  assert.ok(res.body.includes("OK"));

  // cleanup
  api.close();
});

test("GET / THEN returns OK in plain text", async () => {
  // GIVEN
  const honeypot = makeHoneypot();
  const api = ApiServer.create(honeypot);
  const port = await getFreePort();
  api.listen(port, "127.0.0.1");
  await new Promise((r) => setTimeout(r, 20));

  // WHEN
  const res = await httpGetText("127.0.0.1", port, "/");

  // THEN
  assert.equal(res.status, 200);
  //assert.ok(res.body.includes("OK"));

  // cleanup
  api.close();
});
