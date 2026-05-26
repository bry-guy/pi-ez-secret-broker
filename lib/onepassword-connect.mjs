function getHeader(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
  };
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value));
}

function encodeFilter(value) {
  return encodeURIComponent(`title eq "${String(value).replaceAll('"', '\\"')}"`);
}

async function fetchJson(url, token) {
  const response = await fetch(url, { headers: getHeader(token) });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`1Password Connect request failed ${response.status} ${response.statusText}: ${body.slice(0, 500)}`);
  }
  return response.json();
}

async function resolveVaultId(baseUrl, token, vault) {
  if (isUuid(vault)) return vault;
  const result = await fetchJson(`${baseUrl}/v1/vaults?filter=${encodeFilter(vault)}`, token);
  const vaults = Array.isArray(result) ? result : result.items ?? [];
  if (vaults.length !== 1) throw new Error(`expected exactly one 1Password vault named ${vault}, found ${vaults.length}`);
  return vaults[0].id;
}

async function resolveItemId(baseUrl, token, vaultId, item) {
  if (isUuid(item)) return item;
  const result = await fetchJson(`${baseUrl}/v1/vaults/${encodeURIComponent(vaultId)}/items?filter=${encodeFilter(item)}`, token);
  const items = Array.isArray(result) ? result : result.items ?? [];
  if (items.length !== 1) throw new Error(`expected exactly one 1Password item named ${item}, found ${items.length}`);
  return items[0].id;
}

function findField(item, fieldName) {
  const fields = item.fields ?? [];
  const field = fields.find((candidate) =>
    candidate.label === fieldName || candidate.id === fieldName || candidate.purpose === fieldName
  );
  if (!field) throw new Error(`1Password item ${item.title ?? item.id} does not contain field ${fieldName}`);
  if (typeof field.value !== "string" || field.value.length === 0) {
    throw new Error(`1Password field ${fieldName} is empty or not a string`);
  }
  return field.value;
}

export async function readOnePasswordConnectSecret(backend, credential) {
  if (!backend || backend.type !== "1password-connect") throw new Error("backend must have type 1password-connect");
  const baseUrl = String(backend.url ?? "").replace(/\/+$/, "");
  if (!baseUrl) throw new Error("1Password Connect backend missing url");
  const tokenEnv = backend.tokenEnv ?? "OP_CONNECT_TOKEN";
  const token = process.env[tokenEnv];
  if (!token) throw new Error(`environment variable ${tokenEnv} is required for 1Password Connect`);
  if (!credential.vault || !credential.item || !credential.field) {
    throw new Error("1Password Connect credentials require vault, item, and field");
  }
  const vaultId = await resolveVaultId(baseUrl, token, credential.vault);
  const itemId = await resolveItemId(baseUrl, token, vaultId, credential.item);
  const item = await fetchJson(`${baseUrl}/v1/vaults/${encodeURIComponent(vaultId)}/items/${encodeURIComponent(itemId)}`, token);
  return findField(item, credential.field);
}
