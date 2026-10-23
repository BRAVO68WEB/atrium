const assert = require("node:assert/strict");
const { TOTP, Secret } = require("otpauth");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, decodeJwt } = require("../support/oauth");
const { newPage, closeBrowser, callbackURL, waitForCallback } = require("../support/browser");

describe("MFA enrollment", function () {
  let server;

  before(async function () {
    this.timeout(60000);
    server = await startServer({
      security: { mfa: { enabled: true, required: true } },
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("enrolls TOTP during the authorization code flow", async function () {
    const user = await createUser(server, { username: shortID("mfa") });
    const redirectURI = await callbackURL();
    const client = await createClient(server, {
      name: "MFA",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid", "profile"],
    });
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const page = await newPage();
    await page.goto(url.toString());
    await page.fill("#username", user.username);
    await page.fill("#password", user.password);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=Set up an authenticator");
    const secret = (await page.locator(".secret-box").textContent()).trim();
    await page.fill("#code", "000000");
    await page.click("button[type=submit]");
    await page.waitForSelector("text=Invalid code. Please try again.");
    const rotated = (await page.locator(".secret-box").textContent()).trim();
    await page.fill("#code", totp(rotated));
    await page.click("button[type=submit]");
    const callback = await finishMFA(page);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: client.id, secret: client.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).sub, user.id);
    await page.context().close();

    const later = pkcePair();
    const next = new URL(url.toString());
    next.searchParams.set("code_challenge", later.challenge);
    const second = await newPage();
    await second.goto(next.toString());
    await second.fill("#username", user.username);
    await second.fill("#password", user.password);
    await second.click("button[type=submit]");
    await second.waitForSelector("text=Enter the code");
    await second.fill("#code", "000000");
    await second.click("button[type=submit]");
    await second.waitForSelector("text=Invalid TOTP code");
    await second.fill("#code", totp(rotated));
    await second.click("button[type=submit]");
    const done = await finishMFA(second);
    const again = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: done.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: later.verifier,
    }, { id: client.id, secret: client.secret });
    assert.equal(again.status, 200, JSON.stringify(again.body));
    await second.context().close();
  });
});

async function finishMFA(page) {
  await page.waitForURL((current) => {
    try {
      const path = new URL(current).pathname;
      return path === "/consent" || path === "/cb" || path.endsWith("/cb");
    } catch {
      return false;
    }
  }, { timeout: 20000 });
  if (page.url().includes("/consent")) {
    await page.locator("button[value=approve]").click();
  }
  return waitForCallback(page);
}

function totp(secret) {
  return new TOTP({
    secret: Secret.fromBase32(secret),
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  }).generate();
}
