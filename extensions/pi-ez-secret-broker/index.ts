import { randomBytes } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import {
  assertUrlAllowed,
  buildAuthHeaders,
  maxBodyChars,
  normalizeConfig,
  normalizeCredentialName,
  redactHeaders,
  ttlMillis,
} from "../../lib/policy.mjs";
import { readOnePasswordConnectSecret } from "../../lib/onepassword-connect.mjs";
import { getOrCreateBrokerApi } from "../../lib/broker-runtime.mjs";
import { matchSlashCommand } from "./match.js";

type BrokerConfig = {
  backends: Record<string, any>;
  credentials: Record<string, any>;
};

type RuntimeHandle = {
  id: string;
  name: string;
  secretValue: string;
  expiresAt: number;
};

type PendingApproval = {
  id: string;
  handle: string;
  credential: string;
  method: string;
  url: string;
  createdAt: number;
  expiresAt: number;
};

const handles = new Map<string, RuntimeHandle>();
const approvals = new Map<string, PendingApproval>();

function globalConfigPath(): string {
  return path.join(os.homedir(), ".pi", "agent", "pi-ez-secret-broker.json");
}

function projectConfigPath(): string {
  return path.join(process.cwd(), ".pi", "secret-broker.json");
}

function defaultConfig(): BrokerConfig {
  return {
    backends: {
      "op-connect": {
        type: "1password-connect",
        url: "http://127.0.0.1:8080",
        tokenEnv: "OP_CONNECT_TOKEN",
      },
    },
    credentials: {
      "github-api-token": {
        backend: "op-connect",
        vault: "CHANGE_ME",
        item: "GITHUB_TOKEN",
        field: "credential",
        allowedHosts: ["api.github.com"],
        allowedMethods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
        ttlSeconds: 900,
        auth: { type: "bearer" },
        rules: [
          { methods: ["GET"], pathPrefix: "/" },
          { methods: ["POST", "PATCH", "PUT", "DELETE"], pathPrefix: "/", requiresApproval: true },
        ],
      },
      "proxmox-api-token": {
        backend: "op-connect",
        vault: "CHANGE_ME",
        item: "PROXMOX_VE_API_TOKEN",
        field: "password",
        allowedHosts: ["100.112.146.24"],
        allowedMethods: ["GET", "POST", "PUT", "DELETE"],
        ttlSeconds: 900,
        auth: { type: "proxmox-api-token", tokenId: "CHANGE_ME@pam!CHANGE_ME" },
        rules: [
          { methods: ["GET"], pathPrefix: "/api2/json/" },
          { methods: ["POST", "PUT", "DELETE"], pathPrefix: "/api2/json/", requiresApproval: true },
        ],
      },
    },
  };
}

function writeConfigTemplate(target: "global" | "project", force = false): string {
  const targetPath = target === "global" ? globalConfigPath() : projectConfigPath();
  if (existsSync(targetPath) && !force) {
    throw new Error(`${targetPath} already exists. Re-run with --force to overwrite.`);
  }
  mkdirSync(path.dirname(targetPath), { recursive: true });
  writeFileSync(targetPath, `${JSON.stringify(defaultConfig(), null, 2)}\n`, { mode: 0o600 });
  return targetPath;
}

function loadConfig(): BrokerConfig {
  const candidates = [
    process.env.PI_EZ_SECRET_BROKER_CONFIG,
    projectConfigPath(),
    globalConfigPath(),
  ].filter(Boolean) as string[];

  const configPath = candidates.find((candidate) => existsSync(candidate));
  if (!configPath) {
    throw new Error(
      `pi-ez-secret-broker config not found. Set PI_EZ_SECRET_BROKER_CONFIG or create .pi/secret-broker.json`,
    );
  }
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  return normalizeConfig(config) as BrokerConfig;
}

function newHandleId(name: string): string {
  return `piez_${name.replace(/[^a-zA-Z0-9]/g, "_")}_${randomBytes(18).toString("base64url")}`;
}

function auditLogPath(): string {
  return process.env.PI_EZ_SECRET_BROKER_AUDIT_LOG ?? path.join(os.homedir(), ".pi", "agent", "pi-ez-secret-broker-audit.jsonl");
}

function writeAudit(event: Record<string, unknown>): void {
  const file = auditLogPath();
  mkdirSync(path.dirname(file), { recursive: true });
  appendFileSync(file, `${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`, { mode: 0o600 });
}

function purgeExpiredHandles(): void {
  const now = Date.now();
  for (const [id, handle] of handles.entries()) {
    if (handle.expiresAt <= now) handles.delete(id);
  }
  for (const [id, approval] of approvals.entries()) {
    if (approval.expiresAt <= now) approvals.delete(id);
  }
}

async function resolveSecret(config: BrokerConfig, name: string): Promise<{ credential: any; secretValue: string }> {
  normalizeCredentialName(name);
  const credential = config.credentials[name];
  if (!credential) throw new Error(`credential ${name} is not configured`);
  const backend = config.backends[credential.backend];
  if (!backend) throw new Error(`credential ${name} references missing backend ${credential.backend}`);
  switch (backend.type) {
    case "1password-connect":
      return { credential, secretValue: await readOnePasswordConnectSecret(backend, credential) };
    case "env": {
      const envName = credential.env ?? credential.envVar;
      if (!envName) throw new Error(`credential ${name} with env backend requires env/envVar`);
      const value = process.env[envName];
      if (!value) throw new Error(`environment variable ${envName} is not set`);
      return { credential, secretValue: value };
    }
    default:
      throw new Error(`unsupported backend type ${backend.type}`);
  }
}

function getHandle(handleId: string): RuntimeHandle {
  purgeExpiredHandles();
  const handle = handles.get(handleId);
  if (!handle) throw new Error(`credential handle ${handleId} was not found or expired`);
  return handle;
}

function responseText(data: unknown): { content: { type: "text"; text: string }[]; details: Record<string, unknown> } {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }], details: typeof data === "object" && data ? data as Record<string, unknown> : {} };
}

export default function piEzSecretBroker(pi: ExtensionAPI) {
  const brokerApi = getOrCreateBrokerApi();
  const registryKey = Symbol.for("pi-chat.vmConfigContributors.v1");
  const registeredKey = Symbol.for("pi-ez-secret-broker.vmConfigContributorRegistered");
  const globals = globalThis as Record<symbol, unknown>;
  if (!globals[registeredKey]) {
    const registry = (globals[registryKey] as { contributors: unknown[] } | undefined) ?? { contributors: [] };
    globals[registryKey] = registry;
    registry.contributors.push({ name: "pi-ez-secret-broker", contribute: brokerApi.vmFragmentForConversation });
    globals[registeredKey] = true;
  }

  async function handleSecretBroker(args: unknown, ctx: any) {
    const parts = String(args ?? "").trim().split(/\s+/).filter(Boolean);
    const subcommand = parts[0] ?? "help";
    const force = parts.includes("--force") || parts.includes("-f");
    const project = parts.includes("--project") || parts.includes("-p");
    const global = parts.includes("--global") || parts.includes("-g") || !project;
    try {
      if (["init", "new", "bootstrap"].includes(subcommand)) {
        const written = writeConfigTemplate(global ? "global" : "project", force);
        ctx.ui.notify(`pi-ez-secret-broker config written: ${written}`, "info");
        return;
      }
      if (subcommand === "approve") {
        const id = parts[1];
        const approval = id ? approvals.get(id) : undefined;
        if (!approval) throw new Error(`pending approval not found: ${id ?? "<missing>"}`);
        approval.expiresAt = Date.now() + 10 * 60 * 1000;
        writeAudit({ action: "approval_granted", approvalId: id, credential: approval.credential, method: approval.method, url: approval.url });
        ctx.ui.notify(`approved ${id} for ${approval.method} ${approval.url}`, "info");
        return;
      }
      if (subcommand === "github-app" && parts[1] === "configure") {
        const valueAfter = (flag: string) => {
          const index = parts.indexOf(flag);
          return index >= 0 ? parts[index + 1] : undefined;
        };
        await brokerApi.configureGithubApp({
          appId: valueAfter("--app-id") ?? valueAfter("--appId"),
          installationId: valueAfter("--installation-id") ?? valueAfter("--installationId"),
          privateKeyPath: valueAfter("--private-key") ?? valueAfter("--privateKeyPath"),
        });
        ctx.ui.notify(`GitHub App config written: ${brokerApi.paths().githubApp}`, "info");
        return;
      }
      if (subcommand === "github-app" && parts[1] === "allow") {
        const conversationId = parts[2];
        const repos = parts.slice(3);
        if (!conversationId || repos.length === 0) throw new Error("Usage: /secret-broker github-app allow <conversationId> <owner/repo> [...]");
        await brokerApi.upsertGithubAppPolicy(conversationId, repos);
        ctx.ui.notify(`allowed GitHub App repos for ${conversationId}: ${repos.join(", ")}`, "info");
        return;
      }
      if (subcommand === "op-read" && parts[1] === "allow") {
        const conversationId = parts[2];
        const refs = parts.slice(3);
        if (!conversationId || refs.length === 0) throw new Error("Usage: /secret-broker op-read allow <conversationId> <op://...> [...]");
        await brokerApi.upsertOpReadPolicy(conversationId, refs);
        ctx.ui.notify(`allowed 1Password refs for ${conversationId}: ${refs.join(", ")}`, "info");
        return;
      }
      if (subcommand === "status") {
        const config = (() => {
          try { return loadConfig(); } catch { return { credentials: {} }; }
        })();
        const policy = await brokerApi.loadPolicy();
        ctx.ui.notify(
          `pi-ez-secret-broker: ${Object.keys(config.credentials).length} legacy credential(s): ${Object.keys(config.credentials).join(", ") || "none"}; broker conversations: ${Object.keys(policy).length}; pending approvals: ${approvals.size}`,
          "info",
        );
        return;
      }
      ctx.ui.notify(
        "Usage: /secret-broker init [--global|--project] [--force] | /secret-broker status | /secret-broker github-app configure --app-id ID --installation-id ID --private-key PATH | /secret-broker github-app allow <conversationId> <owner/repo> [...] | /secret-broker op-read allow <conversationId> <op://...> [...] | /secret-broker approve <id>",
        "info",
      );
    } catch (error) {
      ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
    }
  }

  pi.registerCommand("secret-broker", {
    description: "Initialize and inspect pi-ez-secret-broker config",
    handler: handleSecretBroker,
  });

  pi.on("input", async (event, ctx) => {
    const match = matchSlashCommand(event.text, ["secret-broker"]);
    if (!match) return { action: "continue" };
    const messages: string[] = [];
    const remoteCtx = { ...ctx, ui: { ...ctx.ui, notify: (message: string) => messages.push(String(message)) } };
    await handleSecretBroker(match.args, remoteCtx);
    return {
      action: "transform",
      text: `The remote /secret-broker command completed. Reply to the user with this result exactly:\n\n${messages.join("\n\n") || "/secret-broker completed."}`,
    };
  });

  pi.registerTool({
    name: "secret_broker_request_credential",
    label: "Request credential handle",
    description:
      "Resolve an allowlisted credential from the host secret backend and return an opaque short-lived handle. The raw secret is never returned to the VM or transcript. Use the handle with secret_broker_http_request.",
    parameters: Type.Object({
      name: Type.String({ description: "Allowlisted credential name from pi-ez-secret-broker config." }),
      reason: Type.String({ description: "Why this credential is needed. Logged in the tool result for auditability." }),
    }),
    async execute(_toolCallId, params) {
      const config = loadConfig();
      const name = normalizeCredentialName(params.name);
      const { credential, secretValue } = await resolveSecret(config, name);
      const id = newHandleId(name);
      const expiresAt = Date.now() + ttlMillis(credential);
      handles.set(id, { id, name, secretValue, expiresAt });
      writeAudit({ action: "handle_issued", credential: name, handle: id, reason: params.reason, expiresAt: new Date(expiresAt).toISOString() });
      return responseText({
        handle: id,
        name,
        reason: params.reason,
        expiresAt: new Date(expiresAt).toISOString(),
        allowedHosts: credential.allowedHosts,
        usage: "Pass this handle to secret_broker_http_request. Do not place it in shell commands; it is not the raw secret.",
      });
    },
  });

  pi.registerTool({
    name: "secret_broker_http_request",
    label: "Credential-brokered HTTP request",
    description:
      "Perform an HTTP(S) request on the host using a short-lived credential handle. The broker injects auth only for allowlisted hosts/methods and redacts sensitive response metadata.",
    parameters: Type.Object({
      handle: Type.String({ description: "Handle returned by secret_broker_request_credential." }),
      url: Type.String({ description: "HTTP or HTTPS URL to request." }),
      method: Type.Optional(Type.String({ description: "HTTP method. Defaults to GET." })),
      headers: Type.Optional(Type.Record(Type.String(), Type.String(), { description: "Non-secret request headers." })),
      body: Type.Optional(Type.String({ description: "Optional request body." })),
      approvalId: Type.Optional(Type.String({ description: "Approval id from a previous approval-required response." })),
    }),
    async execute(_toolCallId, params) {
      const config = loadConfig();
      const handle = getHandle(params.handle);
      const credential = config.credentials[handle.name];
      if (!credential) throw new Error(`credential ${handle.name} is no longer configured`);
      const method = String(params.method ?? "GET").toUpperCase();
      const { parsed, matchedRule } = assertUrlAllowed(handle.name, credential, params.url, method);
      if (matchedRule?.requiresApproval) {
        const existing = params.approvalId ? approvals.get(params.approvalId) : undefined;
        const approved = existing && existing.handle === handle.id && existing.method === method && existing.url === parsed.toString();
        if (!approved) {
          const approvalId = `appr_${randomBytes(9).toString("base64url")}`;
          const approval = { id: approvalId, handle: handle.id, credential: handle.name, method, url: parsed.toString(), createdAt: Date.now(), expiresAt: Date.now() + 10 * 60 * 1000 };
          approvals.set(approvalId, approval);
          writeAudit({ action: "approval_required", approvalId, credential: handle.name, method, url: parsed.toString() });
          return responseText({
            approvalRequired: true,
            approvalId,
            credential: handle.name,
            method,
            url: parsed.toString(),
            instruction: `Approve from the host pi with: /secret-broker approve ${approvalId}`,
          });
        }
        approvals.delete(params.approvalId!);
      }
      const nonSecretHeaders = { ...(params.headers ?? {}) };
      for (const key of Object.keys(nonSecretHeaders)) {
        if (/authorization|cookie|token|secret|key/i.test(key)) {
          throw new Error(`refusing caller-supplied sensitive header ${key}; configure auth in broker policy instead`);
        }
      }
      const authHeaders = buildAuthHeaders(handle.name, credential, handle.secretValue);
      const response = await fetch(parsed.toString(), {
        method,
        headers: { ...nonSecretHeaders, ...authHeaders },
        body: params.body,
      });
      const text = await response.text();
      const limit = maxBodyChars(credential);
      writeAudit({ action: "http_request", credential: handle.name, method, url: parsed.toString(), status: response.status, ok: response.ok, approvalId: params.approvalId ?? null });
      return responseText({
        url: parsed.toString(),
        method,
        credential: handle.name,
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        headers: redactHeaders(Object.fromEntries(response.headers.entries())),
        body: text.length > limit ? `${text.slice(0, limit)}\n...[truncated ${text.length - limit} chars]` : text,
        expiresAt: new Date(handle.expiresAt).toISOString(),
      });
    },
  });

  pi.registerTool({
    name: "secret_broker_status",
    label: "Credential broker status",
    description: "Show configured credential names and active handle metadata without revealing any secret values.",
    parameters: Type.Object({}),
    async execute() {
      const config = loadConfig();
      purgeExpiredHandles();
      return responseText({
        configuredCredentials: Object.fromEntries(
          Object.entries(config.credentials).map(([name, credential]) => [
            name,
            {
              backend: credential.backend,
              allowedHosts: credential.allowedHosts,
              allowedMethods: credential.allowedMethods ?? null,
              ttlSeconds: credential.ttlSeconds ?? 900,
              authType: credential.auth?.type ?? "bearer",
            },
          ]),
        ),
        activeHandles: [...handles.values()].map((handle) => ({
          handle: handle.id,
          name: handle.name,
          expiresAt: new Date(handle.expiresAt).toISOString(),
        })),
      });
    },
  });
}
