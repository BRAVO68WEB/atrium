const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair } = require("../support/pkce");
const {
  createUser, createClient, tokenRequest, introspect, readBody, decodeJwt, jwtHeader,
} = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

const APP_ID = "field-notes";
const API_ID = "notes-api";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const ID_JAG = "urn:ietf:params:oauth:token-type:id-jag";
const ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";

describe("cross-app access", function () {
  let server;
  let user;
  let app;
  let api;
  let redirectURI;

  before(async function () {
    this.timeout(90000);
    server = await startServer({
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
      xaa: {
        enabled: true,
        trusts: [{
          client_id: APP_ID,
          resource_client_id: API_ID,
          scopes: ["notes.read"],
        }],
        idps: [{ scopes: ["notes.read"] }],
      },
    });
    redirectURI = await callbackURL();
    user = await createUser(server, { username: "ada-xaa" });
    app = await createClient(server, {
      id: APP_ID,
      name: "Field Notes",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code", EXCHANGE],
      scopes: ["openid", "email", "notes.read"],
    });
    api = await createClient(server, {
      id: API_ID,
      name: "Notes API",
      grant_types: [JWT_BEARER],
      scopes: ["notes.read"],
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("signs in once and redeems the ID-JAG at this server", async function () {
    const discovery = await readBody(await fetch(`${server.base}/.well-known/openid-configuration`));
    assert.equal(discovery.status, 200, JSON.stringify(discovery.body));
    assert.ok(discovery.body.grant_types_supported.includes(JWT_BEARER));
    assert.deepEqual(discovery.body.authorization_grant_profiles_supported, [
      "urn:ietf:params:oauth:grant-profile:id-jag",
    ]);

    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", app.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email");
    url.searchParams.set("state", "xaa-state");
    url.searchParams.set("nonce", "xaa-nonce");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), user);
    assert.equal(callback.searchParams.get("state"), "xaa-state");

    const signedIn = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: app.id, secret: app.secret });
    assert.equal(signedIn.status, 200, JSON.stringify(signedIn.body));
    const idToken = signedIn.body.id_token;
    assert.equal(decodeJwt(idToken).email, user.email);

    const exchanged = await tokenRequest(server.base, {
      grant_type: EXCHANGE,
      requested_token_type: ID_JAG,
      subject_token: idToken,
      subject_token_type: ID_TOKEN,
      audience: server.base,
      scope: "notes.read",
    }, { id: app.id, secret: app.secret });
    assert.equal(exchanged.status, 200, JSON.stringify(exchanged.body));
    assert.equal(exchanged.body.issued_token_type, ID_JAG);
    assert.equal(exchanged.body.token_type, "N_A");
    assert.equal(exchanged.body.refresh_token, undefined);
    assert.equal(jwtHeader(exchanged.body.access_token).typ, "oauth-id-jag+jwt");
    const jag = decodeJwt(exchanged.body.access_token);
    assert.equal(jag.aud, server.base);
    assert.equal(jag.client_id, API_ID);
    assert.equal(jag.email, user.email);
    assert.equal(jag.sub, decodeJwt(idToken).sub);

    const again = await tokenRequest(server.base, {
      grant_type: EXCHANGE,
      requested_token_type: ID_JAG,
      subject_token: idToken,
      subject_token_type: ID_TOKEN,
      audience: server.base,
      scope: "notes.read",
    }, { id: app.id, secret: app.secret });
    assert.equal(again.status, 400, JSON.stringify(again.body));
    assert.equal(again.body.error, "invalid_grant");

    const redeemed = await tokenRequest(server.base, {
      grant_type: JWT_BEARER,
      assertion: exchanged.body.access_token,
    }, { id: api.id, secret: api.secret });
    assert.equal(redeemed.status, 200, JSON.stringify(redeemed.body));
    assert.equal(redeemed.body.token_type, "Bearer");
    assert.equal(redeemed.body.refresh_token, undefined);
    assert.equal(redeemed.body.access_token.includes("."), false);
    const active = await introspect(server.base, api, redeemed.body.access_token);
    assert.equal(active.body.active, true);
    assert.equal(active.body.sub, user.id);
    assert.equal(active.body.scope, "notes.read");

    const replay = await tokenRequest(server.base, {
      grant_type: JWT_BEARER,
      assertion: exchanged.body.access_token,
    }, { id: api.id, secret: api.secret });
    assert.equal(replay.status, 400, JSON.stringify(replay.body));
    assert.equal(replay.body.error, "invalid_grant");
  });
});
