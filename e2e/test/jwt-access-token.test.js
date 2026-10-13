const assert = require("node:assert/strict");
const { createRemoteJWKSet, jwtVerify } = require("jose");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const {
  createUser, createClient, tokenRequest, userInfo, introspect, revoke,
} = require("../support/oauth");

describe("JWT access tokens", function () {
  let server;
  let user;
  let client;
  let jwks;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ security: { access_token_format: "jwt" } });
    user = await createUser(server, { username: shortID("jwt") });
    client = await createClient(server, {
      name: "JWT",
      grant_types: ["password", "refresh_token"],
      scopes: ["openid", "profile"],
    });
    jwks = createRemoteJWKSet(new URL(`${server.base}/oidc/jwks`));
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("issues a verifiable access token and rotates it on refresh", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid profile",
    }, { id: client.id, secret: client.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(issued.body.access_token.split(".").length, 3);
    assert.equal(issued.body.refresh_token.includes("."), false);

    const verified = await jwtVerify(issued.body.access_token, jwks, {
      issuer: server.base,
      audience: server.base,
      typ: "at+jwt",
    });
    assert.equal(verified.payload.sub, user.id);
    assert.equal(verified.payload.client_id, client.id);
    assert.equal(verified.payload.azp, client.id);
    assert.ok(verified.protectedHeader.kid);

    const info = await userInfo(server.base, issued.body.access_token);
    assert.equal(info.status, 200, JSON.stringify(info.body));
    assert.equal(info.body.sub, user.id);
    const active = await introspect(server.base, client, issued.body.access_token);
    assert.equal(active.body.active, true);

    const refreshed = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: issued.body.refresh_token,
    }, { id: client.id, secret: client.secret });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    assert.equal(refreshed.body.access_token.split(".").length, 3);
    assert.notEqual(refreshed.body.access_token, issued.body.access_token);
    assert.equal(refreshed.body.refresh_token.includes("."), false);
    const next = await jwtVerify(refreshed.body.access_token, jwks, {
      issuer: server.base,
      audience: server.base,
      typ: "at+jwt",
    });
    assert.equal(next.payload.sub, user.id);
    assert.equal(next.payload.azp, client.id);

    const revoked = await revoke(server.base, client, refreshed.body.access_token);
    assert.equal(revoked.status, 200);
    const after = await userInfo(server.base, refreshed.body.access_token);
    assert.equal(after.status, 401);
    const inactive = await introspect(server.base, client, refreshed.body.access_token);
    assert.equal(inactive.body.active, false);
  });

  it("uses the resource as aud for a client-credentials token", async function () {
    const api = await createClient(server, {
      name: "JWT API",
      grant_types: ["client_credentials"],
      scopes: ["openid"],
    });
    const resource = "https://api.example/finance";
    const issued = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
      resource,
    }, { id: api.id, secret: api.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const verified = await jwtVerify(issued.body.access_token, jwks, {
      issuer: server.base,
      audience: resource,
      typ: "at+jwt",
    });
    assert.equal(verified.payload.sub, api.id);
    assert.equal(verified.payload.azp, api.id);
    assert.equal(verified.payload.act, undefined);
  });
});
