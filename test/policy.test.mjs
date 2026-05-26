import test from "node:test";
import assert from "node:assert/strict";

import {
  assertUrlAllowed,
  buildAuthHeaders,
  hostMatches,
  normalizeConfig,
  redactHeaders,
} from "../lib/policy.mjs";

test("hostMatches supports exact and wildcard hosts", () => {
  assert.equal(hostMatches("api.github.com", "api.github.com"), true);
  assert.equal(hostMatches("api.github.com", "uploads.github.com"), false);
  assert.equal(hostMatches("*.github.com", "api.github.com"), true);
  assert.equal(hostMatches("*.github.com", "github.com"), false);
  assert.equal(hostMatches("*", "anything.example"), true);
});

test("assertUrlAllowed enforces host and method", () => {
  const credential = { allowedHosts: ["api.github.com"], allowedMethods: ["GET"] };
  assert.equal(assertUrlAllowed("github", credential, "https://api.github.com/repos", "GET").parsed.hostname, "api.github.com");
  assert.throws(() => assertUrlAllowed("github", credential, "https://evil.example/repos", "GET"), /not allowed/);
  assert.throws(() => assertUrlAllowed("github", credential, "https://api.github.com/repos", "DELETE"), /method/);
  assert.throws(() => assertUrlAllowed("github", credential, "file:///tmp/x", "GET"), /http\/https/);
});

test("assertUrlAllowed enforces path rules when configured", () => {
  const credential = {
    allowedHosts: ["api.github.com"],
    rules: [
      { methods: ["GET"], pathPrefix: "/repos/bry-guy/" },
      { methods: ["DELETE"], path: "/repos/bry-guy/clanker", requiresApproval: true },
    ],
  };
  assert.equal(assertUrlAllowed("github", credential, "https://api.github.com/repos/bry-guy/foo", "GET").matchedRule.requiresApproval, undefined);
  assert.equal(assertUrlAllowed("github", credential, "https://api.github.com/repos/bry-guy/clanker", "DELETE").matchedRule.requiresApproval, true);
  assert.throws(() => assertUrlAllowed("github", credential, "https://api.github.com/user", "GET"), /no matching path rule/);
});

test("buildAuthHeaders supports bearer, header, and proxmox token", () => {
  assert.deepEqual(buildAuthHeaders("x", { auth: { type: "bearer" } }, "s"), { Authorization: "Bearer s" });
  assert.deepEqual(buildAuthHeaders("x", { auth: { type: "header", headerName: "X-Token", headerValueTemplate: "token {{secret}}" } }, "s"), { "X-Token": "token s" });
  assert.deepEqual(buildAuthHeaders("x", { auth: { type: "proxmox-api-token", tokenId: "root@pam!t" } }, "s"), { Authorization: "PVEAPIToken=root@pam!t=s" });
});

test("normalizeConfig rejects unknown backend", () => {
  assert.throws(() => normalizeConfig({ backends: {}, credentials: { c: { backend: "missing", allowedHosts: ["x"] } } }), /unknown backend/);
});

test("redactHeaders hides sensitive headers", () => {
  assert.deepEqual(redactHeaders({ authorization: "secret", etag: "abc", "x-api-key": "k" }), {
    authorization: "<redacted>",
    etag: "abc",
    "x-api-key": "<redacted>",
  });
});
