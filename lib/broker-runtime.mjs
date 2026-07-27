import { createSign, randomBytes } from "node:crypto";
import { appendFile, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const BROKER_API_KEY = Symbol.for("pi-ez-secret-broker.api.v1");
const BROKER_HOSTNAME = "pi-secret-broker";
const BROKER_GUEST_URL = `http://${BROKER_HOSTNAME}`;

function brokerDir() {
  return process.env.PI_EZ_SECRET_BROKER_HOME ?? path.join(os.homedir(), ".pi", "agent", "secret-broker");
}

export function paths() {
  const dir = brokerDir();
  return {
    dir,
    policy: path.join(dir, "policy.json"),
    audit: path.join(dir, "audit.log"),
    githubApp: path.join(dir, "github-app.json"),
  };
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return fallback;
    throw error;
  }
}

async function writeJson(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function audit(event) {
  const file = paths().audit;
  await mkdir(path.dirname(file), { recursive: true });
  await appendFile(file, `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`, { mode: 0o600 });
}

function normalizeRepo(repo) {
  const value = String(repo ?? "").trim().replace(/\.git$/, "");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)) throw new Error(`invalid GitHub repo: ${repo}`);
  return value;
}

function normalizeOpRef(ref) {
  const value = String(ref ?? "").trim();
  if (!value.startsWith("op://") || value.length < 6) throw new Error(`invalid 1Password reference: ${ref}`);
  return value;
}

function unique(values) {
  return [...new Set(values.map((v) => String(v).trim()).filter(Boolean))];
}

export async function loadPolicy() {
  const policy = await readJson(paths().policy, {});
  return policy && typeof policy === "object" && !Array.isArray(policy) ? policy : {};
}

export async function savePolicy(policy) {
  await writeJson(paths().policy, policy);
}

export async function configureGithubApp(config) {
  const appId = String(config.appId ?? "").trim();
  const installationId = String(config.installationId ?? "").trim();
  const privateKeyPath = String(config.privateKeyPath ?? "").trim();
  if (!appId) throw new Error("GitHub App appId is required");
  if (!installationId) throw new Error("GitHub App installationId is required");
  if (!privateKeyPath) throw new Error("GitHub App privateKeyPath is required");
  await writeJson(paths().githubApp, { appId, installationId, privateKeyPath });
}

export async function readGithubAppConfig() {
  const config = await readJson(paths().githubApp, undefined);
  if (!config) throw new Error(`GitHub App config not found at ${paths().githubApp}`);
  if (!config.appId || !config.installationId || !config.privateKeyPath) throw new Error("GitHub App config requires appId, installationId, and privateKeyPath");
  return config;
}

function ensureConversation(policy, conversationId) {
  const id = String(conversationId ?? "").trim();
  if (!id) throw new Error("conversationId is required");
  policy[id] ??= { token: randomBytes(32).toString("base64url") };
  policy[id].token ??= randomBytes(32).toString("base64url");
  return policy[id];
}

export async function upsertGithubAppPolicy(conversationId, repos) {
  const normalized = unique((repos ?? []).map(normalizeRepo));
  if (normalized.length === 0) throw new Error("at least one GitHub repo is required");
  const policy = await loadPolicy();
  const entry = ensureConversation(policy, conversationId);
  const previous = entry.githubApp?.allowedRepos ?? [];
  entry.githubApp = { allowedRepos: unique([...previous, ...normalized]) };
  await savePolicy(policy);
  return entry;
}

export async function upsertOpReadPolicy(conversationId, refs) {
  const normalized = unique((refs ?? []).map(normalizeOpRef));
  if (normalized.length === 0) throw new Error("at least one 1Password ref is required");
  const policy = await loadPolicy();
  const entry = ensureConversation(policy, conversationId);
  const previous = entry.opRead?.allowedRefs ?? [];
  entry.opRead = { allowedRefs: unique([...previous, ...normalized]) };
  await savePolicy(policy);
  return entry;
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signGithubJwt(appId, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = { iat: now - 60, exp: now + 9 * 60, iss: String(appId) };
  const body = `${base64urlJson(header)}.${base64urlJson(payload)}`;
  const signature = createSign("RSA-SHA256").update(body).sign(privateKey, "base64url");
  return `${body}.${signature}`;
}

export async function mintGithubAppToken(repo, deps = {}) {
  const normalized = normalizeRepo(repo);
  const config = await readGithubAppConfig();
  const privateKey = await readFile(config.privateKeyPath, "utf8");
  const jwt = signGithubJwt(config.appId, privateKey);
  const repositoryName = normalized.split("/")[1];
  const fetchImpl = deps.fetch ?? globalThis.fetch;
  const response = await fetchImpl(`https://api.github.com/app/installations/${encodeURIComponent(config.installationId)}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ repositories: [repositoryName] }),
  });
  const body = await response.text();
  if (!response.ok) throw new Error(`GitHub App token request failed ${response.status} ${response.statusText}: ${body.slice(0, 500)}`);
  const parsed = JSON.parse(body);
  if (!parsed.token) throw new Error("GitHub App token response did not include token");
  return { token: parsed.token, expiresAt: parsed.expires_at };
}

export async function readOpRef(ref) {
  const normalized = normalizeOpRef(ref);
  const { stdout } = await execFileAsync("op", ["read", normalized], { encoding: "utf8", maxBuffer: 1024 * 1024 });
  const value = stdout.trim();
  if (!value) throw new Error(`op read returned an empty value for ${normalized}`);
  return value;
}

function findPolicyByToken(policy, token) {
  for (const [conversationId, entry] of Object.entries(policy)) {
    if (entry?.token === token) return { conversationId, entry };
  }
  return undefined;
}

async function handleMint(request, response) {
  let auth = request.headers.authorization ?? "";
  if (Array.isArray(auth)) auth = auth[0] ?? "";
  const token = String(auth).match(/^Bearer\s+(.+)$/i)?.[1];
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  const payload = raw ? JSON.parse(raw) : {};
  const policy = await loadPolicy();
  const resolved = token ? findPolicyByToken(policy, token) : undefined;
  if (!resolved) throw new Error("secret broker token is missing or invalid");

  if (payload.kind === "github-app-token") {
    const repo = normalizeRepo(payload.repo);
    const allowed = resolved.entry.githubApp?.allowedRepos ?? [];
    if (!allowed.includes(repo)) throw new Error(`GitHub repo is not allowed for this conversation: ${repo}`);
    const minted = await mintGithubAppToken(repo);
    await audit({ action: "mint", kind: payload.kind, conversationId: resolved.conversationId, repo, expiresAt: minted.expiresAt ?? null });
    return { ok: true, username: "x-access-token", password: minted.token, expiresAt: minted.expiresAt };
  }

  if (payload.kind === "op-read") {
    const ref = normalizeOpRef(payload.ref);
    const allowed = resolved.entry.opRead?.allowedRefs ?? [];
    if (!allowed.includes(ref)) throw new Error(`1Password ref is not allowed for this conversation: ${ref}`);
    const value = await readOpRef(ref);
    await audit({ action: "mint", kind: payload.kind, conversationId: resolved.conversationId, ref });
    return { ok: true, value };
  }

  throw new Error(`unsupported broker request kind: ${payload.kind}`);
}

let serverState;

export async function startBrokerServer() {
  if (serverState) return serverState;
  const server = http.createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    try {
      if (request.method !== "POST" || request.url !== "/mint") {
        response.statusCode = 404;
        response.end(JSON.stringify({ ok: false, error: "not found" }));
        return;
      }
      const result = await handleMint(request, response);
      response.end(JSON.stringify(result));
    } catch (error) {
      await audit({ action: "deny", error: error instanceof Error ? error.message : String(error) }).catch(() => undefined);
      response.statusCode = 403;
      response.end(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  server.unref();
  const { port } = server.address();
  serverState = { server, host: "127.0.0.1", port, guestUrl: BROKER_GUEST_URL };
  return serverState;
}

export async function getConversationAccess(conversationId) {
  const policy = await loadPolicy();
  const entry = policy[conversationId];
  if (!entry?.token) return undefined;
  const server = await startBrokerServer();
  return { url: server.guestUrl, token: entry.token, port: server.port };
}


async function writeGuestHelpers(conversationId) {
  const safe = encodeURIComponent(conversationId);
  const dir = path.join(paths().dir, "generated", safe);
  await mkdir(dir, { recursive: true });
  const shell = `#!/bin/sh
exec node /gondolin-secret-broker/pi-secret.js "$@"
`;
  const js = `#!/usr/bin/env node
const [kind, value] = process.argv.slice(2);
if (!kind || !value || !["op-read", "github-app-token"].includes(kind)) {
  console.error("Usage: pi-secret op-read op://... | pi-secret github-app-token owner/repo");
  process.exit(2);
}
const baseUrl = process.env.PI_SECRET_BROKER_URL;
const token = process.env.PI_SECRET_BROKER_TOKEN;
if (!baseUrl || !token) {
  console.error("PI_SECRET_BROKER_URL and PI_SECRET_BROKER_TOKEN are required");
  process.exit(1);
}
const body = kind === "op-read" ? { kind, ref: value } : { kind, repo: value };
const response = await fetch(new URL("/mint", baseUrl), {
  method: "POST",
  headers: { Authorization: \`Bearer \${token}\`, "Content-Type": "application/json" },
  body: JSON.stringify(body),
});
const text = await response.text();
let parsed;
try { parsed = JSON.parse(text); } catch { parsed = { ok: false, error: text }; }
if (!response.ok || !parsed.ok) {
  console.error(parsed.error || \`secret broker returned \${response.status}\`);
  process.exit(1);
}
if (kind === "op-read") process.stdout.write(parsed.value);
else process.stdout.write(JSON.stringify({ username: parsed.username, password: parsed.password, expiresAt: parsed.expiresAt }) + "\n");
`;
  await writeFile(path.join(dir, "pi-secret"), shell, "utf8");
  await chmod(path.join(dir, "pi-secret"), 0o755).catch(() => undefined);
  await writeFile(path.join(dir, "pi-secret.js"), js, "utf8");
  await chmod(path.join(dir, "pi-secret.js"), 0o755).catch(() => undefined);
  return dir;
}

export async function vmFragmentForConversation(ctx) {
  const access = await getConversationAccess(ctx.conversationId);
  if (!access) return undefined;
  const helperDir = await writeGuestHelpers(ctx.conversationId);
  const fragment = {
    env: {
      PI_SECRET_BROKER_URL: access.url,
      PI_SECRET_BROKER_TOKEN: access.token,
      PI_SECRET_BROKER_HELPER: "/gondolin-secret-broker/pi-secret",
    },
    tcp: { hosts: { [`${BROKER_HOSTNAME}:80`]: `127.0.0.1:${access.port}` } },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
  };
  if (ctx.gondolin?.RealFSProvider && ctx.gondolin?.ReadonlyProvider) {
    fragment.vfs = { mounts: { "/gondolin-secret-broker": new ctx.gondolin.ReadonlyProvider(new ctx.gondolin.RealFSProvider(helperDir)) } };
  }
  return fragment;
}

export function getOrCreateBrokerApi() {
  const global = globalThis;
  if (global[BROKER_API_KEY]) return global[BROKER_API_KEY];
  const api = {
    paths,
    loadPolicy,
    savePolicy,
    configureGithubApp,
    readGithubAppConfig,
    upsertGithubAppPolicy,
    upsertOpReadPolicy,
    getConversationAccess,
    vmFragmentForConversation,
    startBrokerServer,
  };
  global[BROKER_API_KEY] = api;
  return api;
}

export function getBrokerApiIfRegistered() {
  return globalThis[BROKER_API_KEY];
}

export function hasGithubAppConfig() {
  return existsSync(paths().githubApp);
}
