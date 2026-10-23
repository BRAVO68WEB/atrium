const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, decodeJwt } = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

describe("account profile", function () {
  let server;
  let user;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("profile") });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("shows the signed-in account", async function () {
    const page = await newPage();
    await signInToProfile(page, server.base, user.username, user.password);
    const body = await page.textContent("body");
    assert.match(body, new RegExp(user.username));
    await page.context().close();
  });

  it("changes the password and rejects the old one", async function () {
    const page = await newPage();
    await signInToProfile(page, server.base, user.username, user.password);
    const next = `${user.password}-next`;
    await page.fill("#current_password", user.password);
    await page.fill("#new_password", next);
    await page.locator('form[action="/profile/password"] button[type=submit]').click();
    await page.waitForSelector("text=Password updated.");
    await page.context().close();

    const stale = await newPage();
    await stale.goto(`${server.base}/login?next=/profile`);
    await stale.fill("#username", user.username);
    await stale.fill("#password", user.password);
    await stale.click("button[type=submit]");
    await stale.waitForSelector("text=Invalid credentials");
    await stale.context().close();

    const fresh = await newPage();
    await signInToProfile(fresh, server.base, user.username, next);
    user.password = next;
    await fresh.context().close();
  });

  it("asks for consent again after the grant is removed", async function () {
    const redirectURI = await callbackURL();
    const client = await createClient(server, {
      name: "Notes",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid"],
    });
    const pkce = pkcePair();
    const url = authorizeURL(server, client, redirectURI, pkce);
    const page = await newPage();
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).sub, user.id);

    await page.goto(`${server.base}/profile`);
    await page.locator('form[action="/profile/consents"] button[type=submit]').click();
    await page.waitForSelector("text=Access removed.");

    const again = authorizeURL(server, client, redirectURI, pkcePair());
    let sawConsent = false;
    await authorize(page, again.toString(), {
      ...user,
      onConsent() {
        sawConsent = true;
      },
    });
    assert.equal(sawConsent, true);
    await page.context().close();
  });

  it("signs out another browser", async function () {
    const first = await newPage();
    const second = await newPage();
    await signInToProfile(first, server.base, user.username, user.password);
    await signInToProfile(second, server.base, user.username, user.password);
    await first.reload();
    while (await first.locator('form[action="/profile/sessions"] button[type=submit]').count() > 0) {
      await first.locator('form[action="/profile/sessions"] button[type=submit]').first().click();
      await first.waitForSelector("text=That browser was signed out.");
    }
    await second.goto(`${server.base}/profile`);
    await second.waitForSelector("#username");
    await first.context().close();
    await second.context().close();
  });
});

async function signInToProfile(page, base, username, password) {
  await page.goto(`${base}/login?next=/profile`);
  await page.fill("#username", username);
  await page.fill("#password", password);
  await page.click("button[type=submit]");
  await page.waitForSelector("text=Your account");
}

function authorizeURL(server, client, redirectURI, pkce) {
  const url = new URL(`${server.base}/oauth/authorize`);
  url.searchParams.set("client_id", client.id);
  url.searchParams.set("redirect_uri", redirectURI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid");
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", pkce.method);
  return url;
}
