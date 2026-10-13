const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { readBody } = require("../support/oauth");

const documents = [
  "aauth-agent.json",
  "aauth-person.json",
  "aauth-access.json",
  "aauth-resource.json",
];

async function getJSON(url) {
  return readBody(await fetch(url));
}

describe("AAuth discovery switched off", function () {
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

  it("does not publish AAuth metadata and keeps OpenID discovery", async function () {
    for (const name of documents) {
      const response = await fetch(`${server.base}/.well-known/${name}`);
      assert.equal(response.status, 404, name);
    }
    const jwks = await fetch(`${server.base}/aauth/jwks`);
    assert.equal(jwks.status, 404);
    const discovery = await getJSON(`${server.base}/.well-known/openid-configuration`);
    assert.equal(discovery.status, 200);
    assert.match(discovery.body.jwks_uri, /\/oidc\/jwks$/);
  });
});

describe("AAuth discovery", function () {
  let server;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ aauth: { enabled: true, as_path: "/as" } });
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("publishes the four documents and an Ed25519 key", async function () {
    const person = await getJSON(`${server.base}/.well-known/aauth-person.json`);
    assert.equal(person.status, 200, JSON.stringify(person.body));
    assert.equal(person.body.issuer, server.base);
    assert.equal(person.body.person_token_endpoint, `${server.base}/aauth/person-token`);
    assert.equal(person.body.auth_token_endpoint, `${server.base}/aauth/auth-token`);
    assert.equal(person.body.revocation_endpoint, `${server.base}/aauth/revoke`);

    const agent = await getJSON(`${server.base}/.well-known/aauth-agent.json`);
    assert.equal(agent.body.issuer, server.base);
    assert.equal(agent.body.jwks_uri, `${server.base}/aauth/jwks`);

    const resource = await getJSON(`${server.base}/.well-known/aauth-resource.json`);
    assert.equal(resource.body.authorization_endpoint, `${server.base}/aauth/authorize`);

    const access = await getJSON(`${server.base}/as/.well-known/aauth-access.json`);
    assert.equal(access.status, 200, JSON.stringify(access.body));
    assert.equal(access.body.issuer, `${server.base}/as`);
    assert.equal(access.body.jwks_uri, `${server.base}/as/aauth/jwks`);
    assert.equal(access.body.auth_token_endpoint, `${server.base}/as/aauth/auth-token`);

    const keys = await getJSON(`${server.base}/aauth/jwks`);
    assert.equal(keys.status, 200);
    assert.equal(keys.body.keys.length, 1);
    const key = keys.body.keys[0];
    assert.equal(key.kty, "OKP");
    assert.equal(key.crv, "Ed25519");
    assert.ok(key.x);
    assert.ok(key.kid);
    const pathKeys = await getJSON(`${server.base}/as/aauth/jwks`);
    assert.equal(pathKeys.body.keys[0].kid, key.kid);

    const oidc = await getJSON(`${server.base}/oidc/jwks`);
    assert.equal(oidc.body.keys.some((item) => item.kid === key.kid), false);

    const reserved = await fetch(`${server.base}/aauth/person-token`, { method: "POST" });
    assert.equal(reserved.status, 404);
  });
});
