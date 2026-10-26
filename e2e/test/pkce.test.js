const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, redirectError } = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

describe("PKCE required", function () {
  let server;
  let user;
  let client;
  let redirectURI;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ security: { require_pkce: true, allow_plain_pkce: false } });
    user = await createUser(server, { username: shortID("pkce") });
    redirectURI = await callbackURL();
    client = await createClient(server, {
      name: "PKCE",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid", "profile"],
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("rejects an authorization request without a code challenge", async function () {
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    const response = await fetch(url, { redirect: "manual" });
    const body = redirectError(response);
    assert.equal(body.status, 302);
    assert.equal(body.error, "invalid_request");
    assert.match(body.error_description, /code_challenge/);
  });

  it("completes the browser flow when S256 is used", async function () {
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const page = await newPage();
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: client.id, secret: client.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });

  it("rejects the plain code challenge method", async function () {
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("code_challenge", "plain-verifier");
    url.searchParams.set("code_challenge_method", "plain");
    const response = await fetch(url, { redirect: "manual" });
    const body = redirectError(response);
    assert.equal(body.status, 302);
    assert.match(body.error_description, /plain PKCE is disabled/);
  });
});

describe("plain PKCE allowed", function () {
  let server;
  let user;
  let client;
  let redirectURI;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ security: { allow_plain_pkce: true } });
    user = await createUser(server, { username: shortID("plain") });
    redirectURI = await callbackURL();
    client = await createClient(server, {
      name: "Plain PKCE",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid"],
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("exchanges a plain verifier", async function () {
    const verifier = "a".repeat(43);
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("code_challenge", verifier);
    url.searchParams.set("code_challenge_method", "plain");
    const page = await newPage();
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: verifier,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });
});
