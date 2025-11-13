import test from "node:test";
import assert from "node:assert/strict";
import { handleServerAuth } from "../../../src/Integrations/ssh/server-auth.js";

// Mock the ctx object and the necessary methods
const mockCtx = (
  method,
  username = "testUser",
  password = "testPass",
  key = null,
  signature = null,
) => {
  let resolveFn;
  const promise = new Promise((resolve) => {
    resolveFn = resolve;
  });

  return {
    method,
    username,
    password,
    key,
    signature,
    reject: (methods) => {
      const result = { status: "rejected", allowedMethods: methods };
      resolveFn(result);
      return result;
    },
    accept: () => {
      const result = { status: "accepted" };
      resolveFn(result);
      return result;
    },
    prompt: (prompts, callback) => callback(["userinput"]),
    _resultPromise: promise, // expose so test can await it
  };
};

test("handleServerAuth: Rejects 'none' method and provides allowed methods", () => {
  const ctx = mockCtx("none");
  const result = handleServerAuth(ctx, "127.0.0.1", 1);

  assert.deepEqual(
    result,
    ctx.reject(["password", "publickey", "keyboard-interactive"]),
  );
});

test("handleServerAuth: Accepts 'password' method with 60% chance", () => {
  // Mocking Math.random to control the randomness for testing
  const originalMathRandom = Math.random;
  Math.random = () => 0.5; // For a 50% chance, we'll force acceptance in this case

  const ctx = mockCtx("password");
  const result = handleServerAuth(ctx, "127.0.0.1", 1);

  assert.deepEqual(result.status, "accepted");

  // Restore Math.random after the test
  Math.random = originalMathRandom;
});

test("handleServerAuth: Rejects 'password' method with 40% chance", () => {
  // Mocking Math.random to control the randomness for testing
  const originalMathRandom = Math.random;
  Math.random = () => 0.9; // For a 90% chance, we'll force rejection in this case

  const ctx = mockCtx("password");
  const result = handleServerAuth(ctx, "127.0.0.1", 1);

  assert.deepEqual(result.status, "rejected");

  // Restore Math.random after the test
  Math.random = originalMathRandom;
});

test("handleServerAuth: Accepts 'keyboard-interactive' method with 60% chance", async () => {
  const originalMathRandom = Math.random;
  Math.random = () => 0.5; // force acceptance

  const ctx = mockCtx("keyboard-interactive");

  handleServerAuth(ctx, "127.0.0.1", 1);

  const result = await ctx._resultPromise; // wait until accept() or reject() is called
  assert.equal(result.status, "accepted");

  Math.random = originalMathRandom;
});

test("handleServerAuth: Rejects unknown auth methods", () => {
  const ctx = mockCtx("unknown-method");
  const result = handleServerAuth(ctx, "127.0.0.1", 1);

  assert.deepEqual(result.status, "rejected");
});
