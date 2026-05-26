const DEFAULT_TTL_SECONDS = 900;
const DEFAULT_MAX_BODY_CHARS = 65536;

export function normalizeCredentialName(name) {
  if (typeof name !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(name)) {
    throw new Error("credential name must be 1-128 chars of letters, numbers, _, ., :, or -");
  }
  return name;
}

export function normalizeConfig(config) {
  if (!config || typeof config !== "object") throw new Error("config must be an object");
  const backends = config.backends ?? {};
  const credentials = config.credentials ?? {};
  if (!Object.keys(credentials).length) throw new Error("config.credentials must define at least one credential");
  for (const [name, credential] of Object.entries(credentials)) {
    normalizeCredentialName(name);
    if (!credential || typeof credential !== "object") throw new Error(`credential ${name} must be an object`);
    if (!credential.backend) throw new Error(`credential ${name} missing backend`);
    if (!backends[credential.backend]) throw new Error(`credential ${name} references unknown backend ${credential.backend}`);
    if (!Array.isArray(credential.allowedHosts) || credential.allowedHosts.length === 0) {
      throw new Error(`credential ${name} must define allowedHosts`);
    }
    if (credential.allowedMethods && !Array.isArray(credential.allowedMethods)) {
      throw new Error(`credential ${name} allowedMethods must be an array`);
    }
  }
  return config;
}

export function hostMatches(pattern, host) {
  const normalizedPattern = String(pattern).toLowerCase();
  const normalizedHost = String(host).toLowerCase();
  if (normalizedPattern === "*") return true;
  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(1); // includes leading dot
    return normalizedHost.endsWith(suffix) && normalizedHost.length > suffix.length;
  }
  return normalizedHost === normalizedPattern;
}

export function matchPathRule(credential, parsedUrl, method = "GET") {
  const rules = credential.rules;
  if (!Array.isArray(rules) || rules.length === 0) return undefined;
  const normalizedMethod = String(method || "GET").toUpperCase();
  const pathAndQuery = `${parsedUrl.pathname}${parsedUrl.search}`;
  for (const rule of rules) {
    const methods = rule.methods?.map((m) => String(m).toUpperCase());
    if (methods && !methods.includes(normalizedMethod)) continue;
    if (rule.path && parsedUrl.pathname !== rule.path) continue;
    if (rule.pathPrefix && !parsedUrl.pathname.startsWith(rule.pathPrefix)) continue;
    if (rule.pathRegex && !new RegExp(rule.pathRegex).test(pathAndQuery)) continue;
    return rule;
  }
  return undefined;
}

export function assertUrlAllowed(credentialName, credential, urlString, method = "GET") {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    throw new Error(`invalid url for ${credentialName}: ${urlString}`);
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`credential ${credentialName} may only be used with http/https URLs`);
  }
  const allowed = credential.allowedHosts.some((pattern) => hostMatches(pattern, parsed.hostname));
  if (!allowed) {
    throw new Error(`credential ${credentialName} is not allowed for host ${parsed.hostname}`);
  }
  const normalizedMethod = String(method || "GET").toUpperCase();
  const allowedMethods = credential.allowedMethods?.map((m) => String(m).toUpperCase());
  if (allowedMethods && !allowedMethods.includes(normalizedMethod)) {
    throw new Error(`credential ${credentialName} is not allowed for method ${normalizedMethod}`);
  }
  const matchedRule = matchPathRule(credential, parsed, normalizedMethod);
  if (Array.isArray(credential.rules) && credential.rules.length > 0 && !matchedRule) {
    throw new Error(`credential ${credentialName} has no matching path rule for ${normalizedMethod} ${parsed.pathname}`);
  }
  return { parsed, matchedRule };
}

export function ttlMillis(credential) {
  const seconds = Number(credential.ttlSeconds ?? DEFAULT_TTL_SECONDS);
  if (!Number.isFinite(seconds) || seconds <= 0) throw new Error("ttlSeconds must be positive");
  return Math.floor(seconds * 1000);
}

export function maxBodyChars(credential) {
  const chars = Number(credential.maxBodyChars ?? DEFAULT_MAX_BODY_CHARS);
  if (!Number.isFinite(chars) || chars <= 0) throw new Error("maxBodyChars must be positive");
  return Math.floor(chars);
}

export function buildAuthHeaders(credentialName, credential, secretValue) {
  const auth = credential.auth ?? { type: "bearer" };
  if (!auth || typeof auth !== "object") throw new Error(`credential ${credentialName} auth must be an object`);
  switch (auth.type ?? "bearer") {
    case "bearer":
      return { Authorization: `Bearer ${secretValue}` };
    case "header": {
      if (!auth.headerName) throw new Error(`credential ${credentialName} header auth requires headerName`);
      const value = auth.headerValueTemplate
        ? String(auth.headerValueTemplate).replaceAll("{{secret}}", secretValue)
        : secretValue;
      return { [auth.headerName]: value };
    }
    case "proxmox-api-token": {
      if (!auth.tokenId) throw new Error(`credential ${credentialName} proxmox-api-token auth requires tokenId`);
      return { Authorization: `PVEAPIToken=${auth.tokenId}=${secretValue}` };
    }
    default:
      throw new Error(`credential ${credentialName} has unsupported auth type ${auth.type}`);
  }
}

export function redactHeaders(headers) {
  const redacted = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (/authorization|token|secret|cookie|key/i.test(key)) redacted[key] = "<redacted>";
    else redacted[key] = value;
  }
  return redacted;
}
