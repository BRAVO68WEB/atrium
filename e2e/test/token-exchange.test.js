const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { createUser, createClient, tokenRequest } = require("../support/oauth");

const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

describe("token exchange", function () {
  let server;
  let user;
  let owner;
  let other;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: "ada-exchange" });
    owner = await createClient(server, {
      name: "Field Notes",
      grant_types: ["password", EXCHANGE],
      scopes: ["openid"],
    });
    other = await createClient(server, {
      name: "Other App",
      grant_types: [EXCHANGE],
      scopes: ["openid"],
    });
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("refuses another client's access token and a wider scope", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, { id: owner.id, secret: owner.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));

    const stolen = await tokenRequest(server.base, {
      grant_type: EXCHANGE,
      subject_token: issued.body.access_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    }, { id: other.id, secret: other.secret });
    assert.equal(stolen.status, 400, JSON.stringify(stolen.body));
    assert.equal(stolen.body.error, "invalid_grant");

    const widened = await tokenRequest(server.base, {
      grant_type: EXCHANGE,
      subject_token: issued.body.access_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      scope: "admin",
    }, { id: owner.id, secret: owner.secret });
    assert.equal(widened.status, 400, JSON.stringify(widened.body));
    assert.equal(widened.body.error, "invalid_scope");

    const again = await tokenRequest(server.base, {
      grant_type: EXCHANGE,
      subject_token: issued.body.access_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    }, { id: owner.id, secret: owner.secret });
    assert.equal(again.status, 200, JSON.stringify(again.body));
    assert.equal(again.body.scope, issued.body.scope);
    assert.equal(again.body.issued_token_type, "urn:ietf:params:oauth:token-type:access_token");
  });
});
