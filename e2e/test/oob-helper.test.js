const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest } = require("../support/oauth");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");
const { recover } = require("../support/oobcode");

describe("combined-code helper", function () {
  let server;
  let user;
  let client;
  let redirectURI;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ security: { oob_helper: true } });
    user = await createUser(server, { username: shortID("helper") });
    redirectURI = `${server.base}/oauth/oob`;
    client = await createClient(server, {
      name: "Helper",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid"],
      token_endpoint_auth_method: "none",
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("rejects a helper request that omits code or state", async function () {
    const missing = await fetch(`${server.base}/oauth/oob`);
    assert.equal(missing.status, 400);
    assert.match(await missing.text(), /code and state/);
    const failed = await fetch(`${server.base}/oauth/oob?error=access_denied&error_description=nope&state=xyz`);
    const html = await failed.text();
    assert.equal(failed.status, 200);
    assert.match(failed.headers.get("cache-control") || "", /no-store/);
    assert.match(html, /access_denied/);
    assert.equal(html.includes('id="combined-code"'), false);
  });

  it("shows one combined value and exchanges the recovered code", async function () {
    const pkce = pkcePair();
    const state = "helper-state";
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const page = await newPage();
    await page.goto(url.toString());
    if (page.url().includes("/login")) {
      await submitLogin(page, user.username, user.password);
      await page.waitForURL((current) => new URL(current).pathname === "/consent", { timeout: 20000 });
    }
    await Promise.all([
      page.waitForURL((current) => new URL(current).pathname === "/oauth/oob", { timeout: 20000 }),
      page.locator("button[value=approve]").click(),
    ]);
    const combined = await page.locator("#combined-code").inputValue();
    const asCode = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: combined,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: client.id });
    assert.notEqual(asCode.status, 200, JSON.stringify(asCode.body));
    const code = recover(combined, state);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: client.id });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    await page.context().close();
  });
});

describe("combined-code helper switched off", function () {
  let server;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("returns 404", async function () {
    const response = await fetch(`${server.base}/oauth/oob?code=abc&state=xyz`);
    assert.equal(response.status, 404);
  });
});
