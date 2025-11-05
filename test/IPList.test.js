import test from "node:test";
import assert from "node:assert/strict";
import { IPList } from "../src/IPList.js";
import { IpAddress } from "../src/utils/ip-utils.js";

test("IPList basic add/contains/del", (t) => {
  const list = new IPList();
  const ip = new IpAddress("1.2.3.4");

  // initially not contained
  assert.equal(list.contains(ip), false);

  // add with a ban duration and ensure a timestamp was set
  list.add(ip, 1000);
  const ts = list.getIpV4Timestamp("1.2.3.4");
  assert.equal(typeof ts, "number");
  assert.ok(ts > 0, "timestamp should be a positive number");
  assert.equal(list.contains(ip), true);

  // remove the IP and ensure it's gone
  list.del("1.2.3.4");
  assert.equal(list.contains(ip), false);
});

test("IPList IPv6 add/getters/del", () => {
  const list = new IPList();
  const ip6 = new IpAddress(null, "::1");

  assert.equal(list.contains(ip6), false);
  list.add(ip6, 5000);
  const keys = list.ipV6;
  assert.ok(Array.isArray(keys));
  assert.ok(keys.includes("::1"));
  assert.equal(list.contains(ip6), true);

  // delete via del should remove IPv6
  list.del("::1");
  assert.equal(list.contains(ip6), false);
});
