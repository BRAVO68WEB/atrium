const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest } = require("../support/oauth");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");

const OOB = "urn:ietf:wg:oauth:2.0:oob";
const OOB_AUTO = "urn:ietf:wg:oauth:2.0:oob:auto";

function authorizeURL(server, client, redirectURI, pkce, responseType) {
  const url = new URL(`${server.base}/oauth/authorize`);
  url.searchParams.set("client_id", client.id);
  url.searchParams.set("redirect_uri", redirectURI);
  url.searchParams.set("response_type", responseType || "code");
  url.searchParams.set("scope", "openid");
  url.searchParams.set("state", "oob-state");
  if (pkce) {
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
  }
  return url;
}

async function signIn(page, url, user) {
  await page.goto(url);
  if (page.url().includes("/login")) {
    await submitLogin(page, user.username, user.password);
  }
  await page.waitForURL((current) => {
    const path = new URL(current).pathname;
    return path === "/consent" || path === "/oauth/authorize";
  }, { timeout: 20000 });
}

async function showCode(page) {
  if (new URL(page.url()).pathname === "/consent") {
    const [response] = await Promise.all([
      page.waitForResponse((res) => {
        try {
          return res.status() === 200 && new URL(res.url()).pathname === "/oauth/authorize";
        } catch {
          return false;
        }
      }, { timeout: 20000 }),
      page.locator("button[value=approve]").click(),
    ]);
    assert.match(response.headers()["cache-control"] || "", /no-store/);
  }
  await page.waitForSelector("#authorization-code", { timeout: 20000 });
  return page.locator("#authorization-code").inputValue();
}

describe("out-of-band authorization code", function () {
  let server;
  let user;
  let client;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("oob") });
    client = await createClient(server, {
      name: "CLI",
      redirect_uris: [OOB, OOB_AUTO],
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

  it("rejects a request that is not an authorization code", async function () {
    const pkce = pkcePair();
    const response = await fetch(authorizeURL(server, client, OOB, pkce, "token"));
    const body = await response.json();
    assert.equal(response.status, 400);
    assert.match(body.error_description, /response_type code/);
  });

  it("shows the code for the oob URN and rejects the other URN at the token endpoint", async function () {
    const pkce = pkcePair();
    const page = await newPage();
    await signIn(page, authorizeURL(server, client, OOB, pkce).toString(), user);
    const code = await showCode(page);
    assert.ok(code);
    assert.match(await page.locator("body").innerText(), /oob-state/);

    const wrong = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: OOB_AUTO,
      code_verifier: pkce.verifier,
    }, { id: client.id });
    assert.equal(wrong.status, 400, JSON.stringify(wrong.body));
    assert.match(wrong.body.error_description, /redirect_uri/);

    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: OOB,
      code_verifier: pkce.verifier,
    }, { id: client.id });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    const replay = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: OOB,
      code_verifier: pkce.verifier,
    }, { id: client.id });
    assert.notEqual(replay.status, 200);
    await page.context().close();
  });

  it("shows the code for the auto URN", async function () {
    const pkce = pkcePair();
    const page = await newPage();
    await signIn(page, authorizeURL(server, client, OOB_AUTO, pkce).toString(), user);
    const code = await showCode(page);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: OOB_AUTO,
      code_verifier: pkce.verifier,
    }, { id: client.id });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });

  it("shows access_denied on the page when consent is denied", async function () {
    const pkce = pkcePair();
    const page = await newPage();
    const url = authorizeURL(server, client, OOB, pkce);
    url.searchParams.set("prompt", "consent");
    await signIn(page, url.toString(), user);
    await page.locator("button[value=deny]").click();
    await page.waitForSelector("text=access_denied", { timeout: 20000 });
    assert.equal(await page.locator("#authorization-code").count(), 0);
    await page.context().close();
  });
});
