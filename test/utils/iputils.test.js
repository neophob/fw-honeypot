import test from "node:test";
import assert from "node:assert/strict";

import { IpAddress, splitIpAddress } from "../../src/utils/ip-utils.js";

test("GIVEN IpAddress with IPv4 WHEN checking getters and toString THEN values match", () => {
  // GIVEN
  const ip = new IpAddress("10.0.0.1", null);

  // WHEN/THEN
  assert.equal(ip.ipV4, "10.0.0.1");
  assert.equal(ip.ipV6, null);
  assert.equal(ip.toString(), "10.0.0.1");
});

test("GIVEN IpAddress with IPv6 WHEN toString THEN includes IPv6", () => {
  // GIVEN
  const ip = new IpAddress(null, "::1");

  // WHEN/THEN
  assert.equal(ip.ipV4, null);
  assert.equal(ip.ipV6, "::1");
  assert.equal(ip.toString(), "::1");
});

test("GIVEN mixed address WHEN toString THEN shows both separated by /", () => {
  // GIVEN
  const ip = new IpAddress("1.2.3.4", "::1");

  // WHEN/THEN
  assert.equal(ip.toString(), "1.2.3.4/::1");
});

test("GIVEN valid IPv4 string WHEN splitIpAddress THEN returns IpAddress with ipV4 set", () => {
  // WHEN
  const parsed = splitIpAddress("client 1.2.3.4:1234");

  // THEN
  assert.ok(parsed instanceof IpAddress);
  assert.equal(parsed.ipV4, "1.2.3.4");
  assert.equal(parsed.ipV6, null);
});

test("GIVEN valid IPv6 string WHEN splitIpAddress THEN returns IpAddress with ipV6 set", () => {
  // WHEN
  const parsed = splitIpAddress("[::1]:1234");

  // THEN
  assert.ok(parsed instanceof IpAddress);
  assert.equal(parsed.ipV4, null);
  assert.equal(parsed.ipV6, "::1");
});

test("GIVEN invalid string WHEN splitIpAddress THEN returns null", () => {
  // WHEN
  const parsed = splitIpAddress("not an ip");

  // THEN
  assert.equal(parsed, null);
});
