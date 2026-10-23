const { spawn } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { binPath, repoRoot, pgBase } = require("../test/hooks");

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}

function yamlValue(value) {
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    return String(value);
  }
  return JSON.stringify(String(value));
}

function renderConfig(port, dsn, overrides) {
  const security = overrides.security || {};
  const password = security.password || null;
  const mfa = security.mfa || null;
  const registration = overrides.registration || {};
  const allowIPs = security.fetch_allow_ips || [];
  const lines = [
    "server:",
    "  host: \"127.0.0.1\"",
    `  port: ${port}`,
    "database:",
    "  driver: postgres",
    `  dsn: ${JSON.stringify(dsn)}`,
    "  migrations: true",
    "security:",
    `  issuer: "http://127.0.0.1:${port}"`,
    "  hash_algo: \"internal/hashalgo/algo.go\"",
    `  access_token_format: ${yamlValue(security.access_token_format || "opaque")}`,
    `  login_identifier: ${yamlValue(security.login_identifier || "username")}`,
    `  require_pkce: ${yamlValue(Boolean(security.require_pkce))}`,
    `  allow_plain_pkce: ${yamlValue(security.allow_plain_pkce !== false)}`,
    `  oob_helper: ${yamlValue(Boolean(security.oob_helper))}`,
    `  disable_registration: ${yamlValue(Boolean(security.disable_registration))}`,
    `  disable_social_registration: ${yamlValue(Boolean(security.disable_social_registration))}`,
    `  allow_insecure_fetch: ${yamlValue(Boolean(security.allow_insecure_fetch))}`,
    "  fetch_allow_ips:",
  ];
  if (allowIPs.length === 0) {
    lines[lines.length - 1] = "  fetch_allow_ips: []";
  } else {
    for (const ip of allowIPs) {
      lines.push(`    - ${JSON.stringify(ip)}`);
    }
  }
  if (password) {
    lines.push("  password:");
    for (const [key, value] of Object.entries(password)) {
      lines.push(`    ${key}: ${yamlValue(value)}`);
    }
  }
  if (mfa) {
    lines.push("  mfa:");
    lines.push(`    enabled: ${yamlValue(Boolean(mfa.enabled))}`);
    lines.push(`    required: ${yamlValue(Boolean(mfa.required))}`);
    lines.push("    issuer: \"OAuthImplServer\"");
    lines.push("    digits: 6");
    lines.push("    period: 30");
  }
  lines.push("management:");
  lines.push("  client_id: \"e2e-mgmt\"");
  lines.push("  client_secret: \"e2e-mgmt-secret\"");
  lines.push("registration:");
  lines.push(`  dcr_enabled: ${yamlValue(registration.dcr_enabled !== false)}`);
  lines.push(`  cimd_enabled: ${yamlValue(Boolean(registration.cimd_enabled))}`);
  lines.push("oidc:");
  lines.push(`  issuer: "http://127.0.0.1:${port}"`);
  lines.push("  pairwise_salt: \"e2e-pairwise-salt\"");
  const org = overrides.org || {};
  lines.push("org:");
  lines.push(`  enabled: ${yamlValue(Boolean(org.enabled))}`);
  lines.push(`  enabled_domain_based_autolookup: ${yamlValue(Boolean(org.enabled_domain_based_autolookup))}`);
  const push = overrides.push || {};
  lines.push("push:");
  lines.push(`  enabled: ${yamlValue(Boolean(push.enabled))}`);
  lines.push(`  registration_token_ttl: ${yamlValue(push.registration_token_ttl || 300)}`);
  lines.push(`  minimum_interaction_type: ${yamlValue(push.minimum_interaction_type || "boolean")}`);
  lines.push(`  max_devices_per_user: ${yamlValue(push.max_devices_per_user || 5)}`);
  lines.push(`  client_attestation_required: ${yamlValue(Boolean(push.client_attestation_required))}`);
  lines.push(`  ping_enabled: ${yamlValue(Boolean(push.ping_enabled))}`);
  lines.push(`  push_enabled: ${yamlValue(Boolean(push.push_enabled))}`);
  lines.push(`  relay_endpoint: ${yamlValue(push.relay_endpoint || "")}`);
  const aauth = overrides.aauth || {};
  const base = `http://127.0.0.1:${port}`;
  let asIssuer = aauth.as_issuer || "";
  if (aauth.as_path) {
    const suffix = aauth.as_path.startsWith("/") ? aauth.as_path : `/${aauth.as_path}`;
    asIssuer = base + suffix;
  }
  lines.push("aauth:");
  lines.push(`  enabled: ${yamlValue(Boolean(aauth.enabled))}`);
  lines.push(`  ap_issuer: ${yamlValue(aauth.ap_issuer || "")}`);
  lines.push(`  ps_issuer: ${yamlValue(aauth.ps_issuer || "")}`);
  lines.push(`  as_issuer: ${yamlValue(asIssuer)}`);
  lines.push(`  resource_issuer: ${yamlValue(aauth.resource_issuer || "")}`);
  lines.push(`  resource_mode: ${yamlValue(aauth.resource_mode || "as")}`);
  if (overrides.xaa) {
    appendXAA(lines, base, overrides.xaa);
  }
  if (overrides.smtp) {
    const smtp = overrides.smtp;
    lines.push("smtp:");
    lines.push("  enabled: true");
    lines.push(`  host: ${yamlValue(smtp.host || "127.0.0.1")}`);
    lines.push(`  port: ${yamlValue(smtp.port)}`);
    lines.push(`  from: ${yamlValue(smtp.from || "reset@fieldnotes.example")}`);
    lines.push("  starttls: false");
    lines.push("  implicit_tls: false");
  }
  if (overrides.social) {
    const provider = overrides.social;
    lines.push("social:");
    lines.push("  providers:");
    lines.push(`    - id: ${yamlValue(provider.id || "local")}`);
    lines.push("      type: oidc");
    lines.push(`      name: ${yamlValue(provider.name || "Local")}`);
    lines.push("      enabled: true");
    lines.push(`      client_id: ${yamlValue(provider.client_id || "notes-social")}`);
    lines.push(`      client_secret: ${yamlValue(provider.client_secret || "notes-social-secret")}`);
    lines.push(`      issuer: ${yamlValue(provider.issuer)}`);
  }
  return lines.join("\n") + "\n";
}

function appendXAA(lines, base, xaa) {
  const trusts = Array.isArray(xaa.trusts) ? xaa.trusts : [];
  let idps = Array.isArray(xaa.idps) ? xaa.idps : [];
  if (xaa.enabled && idps.length === 0) {
    idps = [{ scopes: xaa.scopes || ["notes.read"] }];
  }
  lines.push("xaa:");
  lines.push(`  enabled: ${yamlValue(Boolean(xaa.enabled))}`);
  if (trusts.length === 0) {
    lines.push("  trusts: []");
  } else {
    lines.push("  trusts:");
    for (const row of trusts) {
      lines.push(`    - client_id: ${yamlValue(row.client_id)}`);
      lines.push(`      audience: ${yamlValue(row.audience || base)}`);
      lines.push(`      resource_client_id: ${yamlValue(row.resource_client_id)}`);
      writeScopes(lines, "      ", row.scopes);
    }
  }
  if (idps.length === 0) {
    lines.push("  idps: []");
  } else {
    lines.push("  idps:");
    for (const row of idps) {
      lines.push(`    - issuer: ${yamlValue(row.issuer || base)}`);
      lines.push(`      jwks_uri: ${yamlValue(row.jwks_uri || `${base}/oidc/jwks`)}`);
      writeScopes(lines, "      ", row.scopes);
    }
  }
}

function writeScopes(lines, indent, scopes) {
  const list = scopes || [];
  if (list.length === 0) {
    lines.push(`${indent}scopes: []`);
    return;
  }
  lines.push(`${indent}scopes:`);
  for (const scope of list) {
    lines.push(`${indent}  - ${yamlValue(scope)}`);
  }
}

async function waitHealth(base) {
  const deadline = Date.now() + 30000;
  let last = "no response";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(base + "/health");
      if (response.ok) {
        return;
      }
      last = `HTTP ${response.status}`;
    } catch (err) {
      last = err.message;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`server did not become healthy: ${last}`);
}

async function newDatabase() {
  const response = await fetch(`${pgBase()}/db`, { method: "POST" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.dsn) {
    throw new Error(`postgres database was not created: ${response.status} ${JSON.stringify(body)}`);
  }
  return body.dsn;
}

async function startServer(overrides = {}) {
  const port = await freePort();
  const dsn = await newDatabase();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "oauth-e2e-"));
  const cfgPath = path.join(dir, "config.yaml");
  fs.writeFileSync(cfgPath, renderConfig(port, dsn, overrides));
  const child = spawn(binPath, ["-config", cfgPath, "-port", String(port)], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let logs = "";
  child.stdout.on("data", (chunk) => {
    logs += chunk;
  });
  child.stderr.on("data", (chunk) => {
    logs += chunk;
  });
  const base = `http://127.0.0.1:${port}`;
  try {
    await waitHealth(base);
  } catch (err) {
    child.kill("SIGKILL");
    throw new Error(`${err.message}\n${logs.slice(-4000)}`);
  }
  return {
    base,
    port,
    logTail() {
      return logs.slice(-4000);
    },
    async stop() {
      if (child.exitCode == null) {
        child.kill("SIGKILL");
        await new Promise((resolve) => child.once("exit", resolve));
      }
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

module.exports = { startServer };
