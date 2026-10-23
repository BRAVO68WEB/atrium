const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { generateKeyPair, exportJWK, SignJWT } = require("jose");
const { startServer } = require("../support/server");
const { newPage, closeBrowser } = require("../support/browser");

function startIdentityProvider() {
  return new Promise((resolve, reject) => {
    generateKeyPair("RS256", { extractable: true }).then(async ({ publicKey, privateKey }) => {
      const jwk = await exportJWK(publicKey);
      jwk.kid = "social-1";
      jwk.alg = "RS256";
      jwk.use = "sig";
      const pending = new Map();
      const server = http.createServer(async (req, res) => {
        const base = `http://127.0.0.1:${server.address().port}`;
        const url = new URL(req.url, base);
        if (url.pathname === "/.well-known/openid-configuration") {
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({
            issuer: base,
            authorization_endpoint: `${base}/authorize`,
            token_endpoint: `${base}/token`,
            userinfo_endpoint: `${base}/userinfo`,
            jwks_uri: `${base}/jwks`,
          }));
          return;
        }
        if (url.pathname === "/jwks") {
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ keys: [jwk] }));
          return;
        }
        if (url.pathname === "/authorize") {
          const code = crypto.randomBytes(16).toString("hex");
          pending.set(code, url.searchParams.get("nonce") || "");
          const back = new URL(url.searchParams.get("redirect_uri"));
          back.searchParams.set("code", code);
          back.searchParams.set("state", url.searchParams.get("state") || "");
          res.writeHead(302, { location: back.toString() });
          res.end();
          return;
        }
        if (url.pathname === "/token" && req.method === "POST") {
          const chunks = [];
          for await (const chunk of req) {
            chunks.push(chunk);
          }
          const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
          const nonce = pending.get(form.get("code"));
          const idToken = await new SignJWT({
            email: "ada-social@fieldnotes.example",
            email_verified: true,
            preferred_username: "ada-social",
            nonce,
          }).setProtectedHeader({ alg: "RS256", kid: "social-1" })
            .setIssuer(base)
            .setSubject("social-subject-1")
            .setAudience(form.get("client_id"))
            .setIssuedAt()
            .setExpirationTime("5m")
            .sign(privateKey);
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({
            access_token: "upstream-access",
            id_token: idToken,
            token_type: "Bearer",
          }));
          return;
        }
        res.writeHead(404);
        res.end();
      });
      server.listen(0, "127.0.0.1", () => {
        resolve({
          base: `http://127.0.0.1:${server.address().port}`,
          close: () => new Promise((done) => server.close(done)),
        });
      });
      server.on("error", reject);
    }).catch(reject);
  });
}

describe("social login", function () {
  let idp;
  let server;

  before(async function () {
    this.timeout(60000);
    idp = await startIdentityProvider();
    server = await startServer({ social: { issuer: idp.base } });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
    if (idp) {
      await idp.close();
    }
  });

  it("creates an account from the identity provider and opens the profile", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/login/social/local?next=/profile`);
    await page.waitForSelector("text=Your account");
    const body = await page.textContent("body");
    assert.match(body, /ada-social/);
    assert.match(body, /ada-social@fieldnotes.example/);
    await page.goto(`${server.base}/login/social/local?next=/profile`);
    await page.waitForSelector("text=Your account");
    const again = await page.textContent("body");
    assert.match(again, /ada-social@fieldnotes.example/);
    await page.context().close();
  });
});

describe("social registration switched off", function () {
  let idp;
  let server;

  before(async function () {
    this.timeout(60000);
    idp = await startIdentityProvider();
    server = await startServer({
      social: { issuer: idp.base },
      security: { disable_social_registration: true },
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
    if (idp) {
      await idp.close();
    }
  });

  it("does not create an account from the identity provider", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/login/social/local?next=/profile`);
    await page.waitForSelector("text=Social registration is disabled");
    await page.context().close();
  });
});
