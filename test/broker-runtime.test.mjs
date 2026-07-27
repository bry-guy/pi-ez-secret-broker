import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";

import { configureGithubApp, getConversationAccess, loadPolicy, mintGithubAppToken, upsertGithubAppPolicy } from "../lib/broker-runtime.mjs";

function privateKeyPem() {
  return generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" });
}


async function withHome(fn) {
  const dir = await mkdtemp(join(tmpdir(), "secret-broker-"));
  const old = process.env.PI_EZ_SECRET_BROKER_HOME;
  process.env.PI_EZ_SECRET_BROKER_HOME = dir;
  try { await fn(dir); } finally { if (old === undefined) delete process.env.PI_EZ_SECRET_BROKER_HOME; else process.env.PI_EZ_SECRET_BROKER_HOME = old; await rm(dir, { recursive: true, force: true }); }
}

test("upserts GitHub policy and creates a conversation token", async () => withHome(async () => {
  await upsertGithubAppPolicy("acct/chan", ["bry-guy/pi-ez-chat-workspace"]);
  const policy = await loadPolicy();
  assert.deepEqual(policy["acct/chan"].githubApp.allowedRepos, ["bry-guy/pi-ez-chat-workspace"]);
  assert.match(policy["acct/chan"].token, /^[A-Za-z0-9_-]+$/);
  const access = await getConversationAccess("acct/chan");
  assert.equal(access.url, "http://pi-secret-broker");
  assert.equal(typeof access.port, "number");
}));

test("mintGithubAppToken posts a GitHub App JWT and scoped repository request", async () => withHome(async (dir) => {
  const keyPath = join(dir, "app.pem");
  await writeFile(keyPath, privateKeyPem());
  await configureGithubApp({ appId: "123", installationId: "456", privateKeyPath: keyPath });
  const calls = [];
  const token = await mintGithubAppToken("bry-guy/pi-ez-chat-workspace", {
    fetch: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ token: "ghs_unit", expires_at: "2026-01-01T00:00:00Z" }), { status: 201 });
    },
  });
  assert.deepEqual(token, { token: "ghs_unit", expiresAt: "2026-01-01T00:00:00Z" });
  assert.match(calls[0].options.headers.Authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
  assert.equal(JSON.parse(calls[0].options.body).repositories[0], "pi-ez-chat-workspace");
}));
