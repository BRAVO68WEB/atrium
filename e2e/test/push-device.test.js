const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { startServer } = require("../support/server");
const { createUser, createClient, tokenRequest } = require("../support/oauth");
const { shortID } = require("../support/pkce");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");

describe("push authenticator enrollment", function () {
  let server;
  let user;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ push: { enabled: true } });
    user = await createUser(server, { username: shortID("push"), password: "correct-horse" });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("shows a registration token in the fragment after sign-in", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/push/enroll`);
    if (page.url().includes("/login")) {
      await submitLogin(page, user.username, user.password);
      await page.waitForURL((current) => new URL(current).pathname === "/push/enroll", { timeout: 20000 });
    }
    const token = (await page.locator("#registration-token").innerText()).trim();
    assert.equal(token.split(".").length, 3);
    const shown = await page.locator("#enroll-url").innerText();
    assert.match(shown, /\/push\/enroll#/);
    assert.equal(await page.locator("#enroll-qr").count(), 1);
    await page.context().close();
  });

  it("approves a sign-in on the registered device", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/push/enroll`);
    if (page.url().includes("/login")) {
      await submitLogin(page, user.username, user.password);
      await page.waitForURL((current) => new URL(current).pathname === "/push/enroll", { timeout: 20000 });
    }
    const registrationToken = (await page.locator("#registration-token").innerText()).trim();
    const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const registered = await fetch(`${server.base}/push/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        registration_token: registrationToken,
        public_key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        interaction_types: ["boolean", "number_choose", "input_manual"],
        platform: "browser",
      }),
    });
    assert.equal(registered.status, 201, await registered.text());

    const client = await createClient(server, {
      name: "Shop",
      grant_types: ["urn:openid:params:grant-type:ciba"],
      scopes: ["openid"],
    });
    const started = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({
        login_hint: user.username,
        scope: "openid",
        binding_message: "42",
      }),
    });
    const pending = await started.json();
    assert.equal(started.status, 200, JSON.stringify(pending));
    assert.ok(pending.auth_req_id);

    await page.goto(`${server.base}/push/approve`);
    await page.locator("button[value=approve]").click();
    await page.locator("#push-approved").waitFor({ timeout: 20000 });

    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: pending.auth_req_id,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    await page.context().close();
  });
});
