import test from "node:test";
import assert from "node:assert/strict";

import { mergeConfigs } from "../../src/utils/config-utils.js";

test("GIVEN undefined configs WHEN mergeConfigs THEN returns empty object", () => {
  // WHEN
  const merged = mergeConfigs(undefined, undefined);

  // THEN
  assert.deepEqual(merged, {});
});

test("GIVEN configA with defaults and configB overriding one key WHEN mergeConfigs THEN configB wins", () => {
  // GIVEN
  const a = { foo: "a", keep: "fromA" };
  const b = { foo: "b" };

  // WHEN
  const merged = mergeConfigs(a, b);

  // THEN
  assert.equal(merged.foo, "b");
  assert.equal(merged.keep, "fromA");
});

test("GIVEN configB has undefined/null WHEN mergeConfigs THEN values from A fill nullish entries", () => {
  // GIVEN
  const a = { x: 1, y: 2 };
  const b = { x: undefined, y: null };

  // WHEN
  const merged = mergeConfigs(a, b);

  // THEN
  assert.equal(merged.x, 1); // undefined in B -> take from A
  assert.equal(merged.y, 2); // null in B -> take from A
});

test("GIVEN only one config WHEN mergeConfigs THEN returns the other config", () => {
  assert.deepEqual(mergeConfigs({ a: 1 }, undefined), { a: 1 });
  assert.deepEqual(mergeConfigs(undefined, { b: 2 }), { b: 2 });
});
