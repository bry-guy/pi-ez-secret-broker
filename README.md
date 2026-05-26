# pi-ez-secret-broker

`pi-ez-secret-broker` is a small pi package that gives pi-chat/Gondolin sessions short-lived **credential handles** backed by host-side secrets.

v0.1 solves the immediate homelab/mobile workflow:

- keep real secrets on the host / 1Password Connect side
- let the agent request a named allowlisted credential at runtime
- return an opaque short-lived handle, not the secret
- perform allowlisted HTTP(S) requests on the host with auth injected by policy
- avoid writing plaintext secrets to `/workspace/.secrets`

This is intentionally narrower than a generic command runner or Vault replacement.

## Install

From a local checkout:

```bash
pi install /path/to/pi-ez-secret-broker
```

Or test for one pi run:

```bash
pi -e /path/to/pi-ez-secret-broker
```

## UX: bootstrap a broker

After installing the package on the host pi process, run one command:

```text
/secret-broker init
```

That writes a global template at:

```text
~/.pi/agent/pi-ez-secret-broker.json
```

Project-local variant:

```text
/secret-broker init --project
```

Overwrite an existing template:

```text
/secret-broker init --force
```

Inspect configured credential names:

```text
/secret-broker status
```

Approve a write/destructive request that matched an approval-required rule:

```text
/secret-broker approve appr_abc123
```

Then edit the generated template on the host to set vault/item names and Proxmox token id. No secret values go in the file; only 1Password Connect locations and allowlist policy.

## Configuration

The broker loads the first existing config from:

- `PI_EZ_SECRET_BROKER_CONFIG=/path/to/config.json`
- project-local `.pi/secret-broker.json`
- global `~/.pi/agent/pi-ez-secret-broker.json`

Example:

```json
{
  "backends": {
    "op-connect": {
      "type": "1password-connect",
      "url": "http://127.0.0.1:8080",
      "tokenEnv": "OP_CONNECT_TOKEN"
    }
  },
  "credentials": {
    "github-delete-token": {
      "backend": "op-connect",
      "vault": "bry-guy",
      "item": "GITHUB_DELETE_REPO_TOKEN",
      "field": "credential",
      "allowedHosts": ["api.github.com"],
      "allowedMethods": ["GET", "DELETE"],
      "ttlSeconds": 900,
      "rules": [
        { "methods": ["GET"], "pathPrefix": "/" },
        { "methods": ["DELETE"], "path": "/repos/bry-guy/clanker", "requiresApproval": true }
      ],
      "auth": { "type": "bearer" }
    },
    "proxmox-api-token": {
      "backend": "op-connect",
      "vault": "bry-guy",
      "item": "PROXMOX_VE_API_TOKEN",
      "field": "password",
      "allowedHosts": ["100.112.146.24"],
      "allowedMethods": ["GET", "POST", "DELETE"],
      "ttlSeconds": 900,
      "rules": [
        { "methods": ["GET"], "pathPrefix": "/api2/json/" },
        { "methods": ["POST", "PUT", "DELETE"], "pathPrefix": "/api2/json/", "requiresApproval": true }
      ],
      "auth": {
        "type": "proxmox-api-token",
        "tokenId": "root@pam!terraform"
      }
    }
  }
}
```

For simple local testing without 1Password Connect, an env backend is also supported:

```json
{
  "backends": {
    "env": { "type": "env" }
  },
  "credentials": {
    "github-token": {
      "backend": "env",
      "env": "GITHUB_TOKEN",
      "allowedHosts": ["api.github.com"],
      "auth": { "type": "bearer" }
    }
  }
}
```

## UX in pi-chat

Once the host worker has the package installed and the config exists, a Discord/chat user can ask the agent to do API work normally. The agent will use these tools when it needs brokered credentials.

For example:

1. Agent calls `secret_broker_request_credential` for `github-api-token`.
2. Broker returns a short-lived opaque handle.
3. Agent calls `secret_broker_http_request` with the handle and the GitHub/Proxmox API URL.
4. Host checks host, method, and optional path rules.
5. If the matching rule has `requiresApproval`, the tool returns an approval id instead of performing the request.
6. The host operator runs `/secret-broker approve <id>` and the agent retries with that `approvalId`.
7. Host injects auth according to allowlist policy.
8. Chat receives only the HTTP result, never the raw secret.

## Tools

### `secret_broker_request_credential`

Resolves an allowlisted credential from the host backend and returns an opaque handle.

Input:

```json
{
  "name": "github-delete-token",
  "reason": "Delete bry-guy/clanker after explicit user approval"
}
```

Output includes:

- `handle`
- `expiresAt`
- `allowedHosts`

It never includes the raw secret.

### `secret_broker_http_request`

Uses a handle to perform an HTTP(S) request on the host. Auth is injected according to policy only after host/method validation.

Example GitHub delete:

```json
{
  "handle": "piez_github_delete_token_...",
  "method": "DELETE",
  "url": "https://api.github.com/repos/bry-guy/clanker",
  "headers": {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  }
}
```

### `secret_broker_status`

Shows configured credential names and active handles without secret values.

## Security posture

This package deliberately does **not** persist plaintext secrets to the mounted workspace.

It writes a simple JSONL audit log to `~/.pi/agent/pi-ez-secret-broker-audit.jsonl` by default. Override with `PI_EZ_SECRET_BROKER_AUDIT_LOG`.

v0.1 is not yet transparent Gondolin HTTP-hook substitution. It uses a pi custom tool as the host-mediated HTTP path, which is enough for today’s GitHub/Proxmox API operations while preserving the same philosophy: host owns secrets, the VM/agent sees handles, and policy scopes use by host and method.

Future work can replace the tool-mediated HTTP path with a mutable Gondolin HTTP hook registry once pi-chat exposes the right integration point.

## Limitations

Not supported in v0.1:

- SSH keys
- OAuth flows
- OCI/private-key request signing
- arbitrary host command execution
- transparent `curl` from inside Gondolin with placeholder substitution
- non-HTTP protocols

Use existing pi-chat runtime secrets only as an explicit fallback when a workflow cannot be represented as brokered HTTP.
