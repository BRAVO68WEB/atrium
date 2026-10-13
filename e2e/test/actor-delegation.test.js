const assert = require("node:assert/strict");
const { createRemoteJWKSet, jwtVerify } = require("jose");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const {
  MGMT_ID, MGMT_SECRET, createUser, createClient, tokenRequest, introspect,
} = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL, waitForCallback } = require("../support/browser");

function authorizeURL(server, client, redirectURI, pkce, extra) {
  const url = new URL(`${server.base}/oauth/authorize`);
  url.searchParams.set("client_id", client.id);
  url.searchParams.set("redirect_uri", redirectURI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid");
  url.searchParams.set("state", "actor-state");
  if (pkce) {
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
  }
  for (const [key, value] of Object.entries(extra || {})) {
    url.searchParams.set(key, value);
  }
  return url;
}

describe("on-behalf-of delegation", function () {
  let server;
  let user;
  let app;
  let actor;
  let redirectURI;
  let actorToken;
  let jwks;
  const resource = "https://api.example/finance";

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("actor") });
    redirectURI = await callbackURL();
    app = await createClient(server, {
      name: "Assistant",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid"],
      token_endpoint_auth_method: "none",
    });
    actor = await createClient(server, {
      name: "Finance Agent",
      redirect_uris: ["https://agent.example/cb"],
      grant_types: ["client_credentials"],
      scopes: ["openid"],
    });
    const issued = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
    }, { id: actor.id, secret: actor.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    actorToken = issued.body.access_token;
    jwks = createRemoteJWKSet(new URL(`${server.base}/oidc/jwks`));
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("rejects a request that is not S256 code for a known agent", async function () {
    const pkce = pkcePair();
    const missing = await fetch(authorizeURL(server, app, redirectURI, null, { requested_actor: actor.id }));
    const missingBody = await missing.json();
    assert.equal(missing.status, 400);
    assert.match(missingBody.error_description, /S256/);

    const implicit = authorizeURL(server, app, redirectURI, pkce, { requested_actor: actor.id });
    implicit.searchParams.set("response_type", "token");
    const rejected = await fetch(implicit);
    const rejectedBody = await rejected.json();
    assert.equal(rejected.status, 400);
    assert.match(rejectedBody.error_description, /response_type code/);

    const unknown = await fetch(authorizeURL(server, app, redirectURI, pkce, { requested_actor: "not-an-agent" }));
    const unknownBody = await unknown.json();
    assert.equal(unknown.status, 400);
    assert.match(unknownBody.error_description, /not recognized/);
  });

  it("names the agent on the consent page and issues a JWT that refresh keeps", async function () {
    const pkce = pkcePair();
    const page = await newPage();
    const url = authorizeURL(server, app, redirectURI, pkce, {
      requested_actor: actor.id,
      resource,
    });
    const callback = await authorize(page, url.toString(), {
      ...user,
      onConsent: async (consentPage) => {
        const text = await consentPage.locator("body").innerText();
        assert.match(text, /Finance Agent/);
        assert.match(text, /act on your behalf/);
      },
    });
    assert.equal(callback.searchParams.get("state"), "actor-state");
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const missing = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: app.id });
    assert.equal(missing.status, 400, JSON.stringify(missing.body));
    assert.match(missing.body.error_description, /actor_token/);

    const wrong = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
      actor_token: "not-a-token",
    }, { id: app.id });
    assert.equal(wrong.status, 400, JSON.stringify(wrong.body));

    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
      actor_token: actorToken,
    }, { id: app.id });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const verified = await jwtVerify(issued.body.access_token, jwks, {
      issuer: server.base,
      audience: resource,
      typ: "at+jwt",
    });
    assert.equal(verified.payload.sub, user.id);
    assert.equal(verified.payload.client_id, app.id);
    assert.equal(verified.payload.azp, app.id);
    assert.equal(verified.payload.act.sub, actor.id);
    assert.equal(issued.body.access_token.includes("."), true);
    assert.equal(issued.body.refresh_token.includes("."), false);

    const active = await introspect(server.base, { id: MGMT_ID, secret: MGMT_SECRET }, issued.body.access_token);
    assert.equal(active.body.active, true);
    assert.equal(active.body.act.sub, actor.id);

    const refreshed = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: issued.body.refresh_token,
    }, { id: app.id });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    const next = await jwtVerify(refreshed.body.access_token, jwks, {
      issuer: server.base,
      audience: resource,
      typ: "at+jwt",
    });
    assert.equal(next.payload.act.sub, actor.id);
    assert.notEqual(refreshed.body.access_token, issued.body.access_token);
    await page.context().close();
  });

  it("asks for consent again and rejects an actor token on an ordinary code", async function () {
    const pkce = pkcePair();
    const page = await newPage();
    const first = authorizeURL(server, app, redirectURI, pkce, { requested_actor: actor.id });
    await authorize(page, first.toString(), user);

    const cookies = await page.context().cookies();
    const silent = authorizeURL(server, app, redirectURI, pkcePair(), {
      requested_actor: actor.id,
      prompt: "none",
    });
    const quiet = await fetch(silent, {
      headers: { cookie: cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ") },
      redirect: "manual",
    });
    const quietBody = await quiet.json();
    assert.equal(quiet.status, 302);
    assert.equal(quietBody.error, "consent_required");

    await page.goto(authorizeURL(server, app, redirectURI, pkcePair(), { requested_actor: actor.id }).toString());
    await page.waitForURL((current) => new URL(current).pathname === "/consent", { timeout: 20000 });
    assert.match(await page.locator("body").innerText(), /Finance Agent/);

    const plainPKCE = pkcePair();
    await page.goto(authorizeURL(server, app, redirectURI, plainPKCE).toString());
    const callback = await waitForCallback(page);
    const stray = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: plainPKCE.verifier,
      actor_token: actorToken,
    }, { id: app.id });
    assert.equal(stray.status, 400, JSON.stringify(stray.body));
    assert.match(stray.body.error_description, /not allowed/);
    await page.context().close();
  });
});
