const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { createUser, createClient, tokenRequest, introspect, revoke } = require("../support/oauth");

describe("revocation", function () {
  let server;
  let user;
  let owner;
  let other;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: "ada-revoke" });
    owner = await createClient(server, {
      name: "Field Notes",
      grant_types: ["password"],
      scopes: ["openid"],
      redirect_uris: ["http://localhost:8080/field", "http://localhost:8080/other"],
    });
    other = await createClient(server, {
      name: "Other App",
      grant_types: ["password"],
      scopes: ["openid"],
    });
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("hides another client's token and still revokes with the wrong hint", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, { id: owner.id, secret: owner.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));

    const foreign = await revoke(server.base, other, issued.body.access_token);
    assert.equal(foreign.status, 200, JSON.stringify(foreign.body));
    const still = await introspect(server.base, owner, issued.body.access_token);
    assert.equal(still.body.active, true);

    const hinted = await revoke(server.base, owner, issued.body.refresh_token);
    assert.equal(hinted.status, 200, JSON.stringify(hinted.body));
    const refreshed = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: issued.body.refresh_token,
    }, { id: owner.id, secret: owner.secret });
    assert.equal(refreshed.status, 400, JSON.stringify(refreshed.body));
    assert.equal(refreshed.body.error, "invalid_grant");
  });
});
