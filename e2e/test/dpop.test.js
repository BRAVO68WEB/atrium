const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, userInfo } = require("../support/oauth");
const { dpopKey, dpopProof } = require("../support/dpop");

describe("forced DPoP", function () {
  let server;
  let user;
  let client;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("dpop") });
    client = await createClient(server, {
      name: "DPoP",
      grant_types: ["password"],
      scopes: ["openid", "profile"],
      dpop_bound_access_tokens: true,
    });
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("rejects a token and UserInfo without a proof, then accepts both with one", async function () {
    const params = {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid profile",
    };
    const missing = await tokenRequest(server.base, params, { id: client.id, secret: client.secret });
    assert.equal(missing.status, 400);
    assert.equal(missing.body.error, "invalid_dpop_proof");

    const tokenURL = `${server.base}/oauth/token`;
    const key = await dpopKey();
    const proof = await dpopProof("POST", tokenURL, undefined, { key });
    const issued = await tokenRequest(server.base, params, { id: client.id, secret: client.secret }, { DPoP: proof });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(issued.body.token_type, "DPoP");

    const bearer = await userInfo(server.base, issued.body.access_token, "Bearer");
    assert.equal(bearer.status, 401);

    const infoURL = `${server.base}/oidc/userinfo`;
    const infoProof = await dpopProof("GET", infoURL, issued.body.access_token, { key });
    const bareProof = await dpopProof("GET", infoURL, issued.body.access_token, { ath: false, key });
    const bare = await fetch(infoURL, {
      headers: {
        Authorization: `DPoP ${issued.body.access_token}`,
        DPoP: bareProof,
      },
    });
    assert.equal(bare.status, 401);

    const info = await fetch(infoURL, {
      headers: {
        Authorization: `DPoP ${issued.body.access_token}`,
        DPoP: infoProof,
      },
    });
    const body = await info.json();
    assert.equal(info.status, 200, JSON.stringify(body));
    assert.equal(body.sub, user.id);
  });
});
