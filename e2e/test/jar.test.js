const assert = require("node:assert/strict");
const { generateKeyPair, exportJWK, SignJWT } = require("jose");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, decodeJwt } = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

describe("signed authorization request", function () {
  let server;
  let redirectURI;
  let client;
  let privateKey;
  let user;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    redirectURI = await callbackURL();
    user = await createUser(server, { username: shortID("jar-user") });
    const keys = await generateKeyPair("RS256", { extractable: true });
    privateKey = keys.privateKey;
    const jwk = await exportJWK(keys.publicKey);
    jwk.kid = "jar-1";
    jwk.alg = "RS256";
    jwk.use = "sig";
    client = await createClient(server, {
      name: shortID("jar"),
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid"],
      jwks: JSON.stringify({ keys: [jwk] }),
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("opens the login page for a signed request and rejects an unsigned one", async function () {
    const pkce = pkcePair();
    const request = await new SignJWT({
      client_id: client.id,
      response_type: "code",
      redirect_uri: redirectURI,
      scope: "openid",
      state: "jar-state",
      nonce: "jar-nonce",
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
    }).setProtectedHeader({ alg: "RS256", kid: "jar-1" })
      .setIssuer(client.id)
      .setAudience(server.base)
      .setExpirationTime("5m")
      .sign(privateKey);

    const page = await newPage();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("request", request);
    const callback = await authorize(page, url.toString(), user);
    assert.equal(callback.searchParams.get("state"), "jar-state");
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).nonce, "jar-nonce");

    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({
      client_id: client.id,
      response_type: "code",
      redirect_uri: redirectURI,
    })).toString("base64url");
    const unsigned = new URL(`${server.base}/oauth/authorize`);
    unsigned.searchParams.set("client_id", client.id);
    unsigned.searchParams.set("request", `${header}.${payload}.`);
    const refused = await fetch(unsigned);
    assert.equal(refused.status, 400);
    await page.context().close();
  });

  it("keeps the code challenge from the signed request", async function () {
    const inside = pkcePair();
    const outside = pkcePair();
    const request = await new SignJWT({
      client_id: client.id,
      response_type: "code",
      redirect_uri: redirectURI,
      scope: "openid",
      state: "jar-challenge",
      nonce: "jar-challenge-nonce",
      code_challenge: inside.challenge,
      code_challenge_method: "S256",
    }).setProtectedHeader({ alg: "RS256", kid: "jar-1" })
      .setIssuer(client.id)
      .setAudience(server.base)
      .setExpirationTime("5m")
      .sign(privateKey);
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("request", request);
    url.searchParams.set("code_challenge", outside.challenge);
    url.searchParams.set("code_challenge_method", "S256");
    const page = await newPage();
    const callback = await authorize(page, url.toString(), user);
    const rejected = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: outside.verifier,
    }, client);
    assert.equal(rejected.status, 400, JSON.stringify(rejected.body));
    assert.equal(rejected.body.error, "invalid_grant");

    const again = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: again.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: inside.verifier,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });
});
