const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const {
  createUser, createClient, tokenRequest, readBody, jwtHeader, managementToken,
} = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

describe("token rotation", function () {
  let server;
  let user;
  let passwordApp;
  let web;
  let redirectURI;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("rotate") });
    redirectURI = await callbackURL();
    passwordApp = await createClient(server, {
      name: "Refresh",
      grant_types: ["password", "refresh_token"],
      scopes: ["openid", "profile"],
    });
    web = await createClient(server, {
      name: "Web",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile"],
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("revokes the refresh family when a used refresh token is presented again", async function () {
    const first = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, { id: passwordApp.id, secret: passwordApp.secret });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const rotated = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: first.body.refresh_token,
    }, { id: passwordApp.id, secret: passwordApp.secret });
    assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
    assert.notEqual(rotated.body.refresh_token, first.body.refresh_token);

    const reused = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: first.body.refresh_token,
    }, { id: passwordApp.id, secret: passwordApp.secret });
    assert.equal(reused.status, 400);
    assert.equal(reused.body.error, "invalid_grant");

    const family = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: rotated.body.refresh_token,
    }, { id: passwordApp.id, secret: passwordApp.secret });
    assert.equal(family.status, 400);
    assert.equal(family.body.error, "invalid_grant");

    const fresh = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, passwordApp);
    assert.equal(fresh.status, 200, JSON.stringify(fresh.body));
    const other = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: fresh.body.refresh_token,
    }, web);
    assert.equal(other.status, 401);
    assert.equal(other.body.error, "invalid_client");
  });

  it("keeps a retired signing key in JWKS and still accepts its ID token", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: web.id, secret: web.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const oldKid = jwtHeader(issued.body.id_token).kid;

    const token = await managementToken(server);
    const rotated = await readBody(await fetch(`${server.base}/api/keys/rotate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    }));
    assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
    assert.equal(JSON.stringify(rotated.body).toLowerCase().includes("private"), false);

    const jwks = await readBody(await fetch(`${server.base}/oidc/jwks`));
    const rsa = jwks.body.keys.filter((key) => key.alg === "RS256");
    assert.ok(rsa.length >= 2);
    assert.ok(rsa.some((key) => key.kid === oldKid));

    const logout = await fetch(`${server.base}/oauth/logout?id_token_hint=${encodeURIComponent(issued.body.id_token)}`);
    const pageText = await logout.text();
    assert.equal(logout.status, 200);
    assert.match(pageText, /session has ended/i);
    await page.context().close();
  });
});
