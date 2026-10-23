const assert = require("node:assert/strict");
const http = require("node:http");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, decodeJwt } = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

function startSink() {
  const bodies = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      bodies.push(Buffer.concat(chunks).toString("utf8"));
      res.writeHead(204);
      res.end();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}/logout`,
        bodies,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

describe("back-channel logout", function () {
  let sink;
  let server;
  let user;
  let client;
  let redirectURI;

  before(async function () {
    this.timeout(60000);
    sink = await startSink();
    server = await startServer({
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
    });
    redirectURI = await callbackURL();
    user = await createUser(server, { username: shortID("logout") });
    client = await createClient(server, {
      name: "Field Notes",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid"],
      backchannel_logout_uri: sink.url,
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
    if (sink) {
      await sink.close();
    }
  });

  it("posts a logout token when the browser session ends", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("state", "logout-state");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    await authorize(page, url.toString(), user);
    const cookies = await page.context().cookies();
    const sid = cookies.find((cookie) => cookie.name === "session_id");
    assert.ok(sid);
    const quiet = await startSink();
    await createClient(server, {
      name: "Quiet",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid"],
      backchannel_logout_uri: quiet.url,
    });
    await page.goto(`${server.base}/oauth/logout`);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=session has ended");
    const deadline = Date.now() + 5000;
    while (sink.bodies.length === 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(sink.bodies.length > 0, true, "logout token was not delivered");
    const params = new URLSearchParams(sink.bodies[0]);
    const claims = decodeJwt(params.get("logout_token"));
    assert.ok(claims.events["http://schemas.openid.net/event/backchannel-logout"]);
    assert.equal(claims.sid, sid.value);
    assert.equal(claims.aud, client.id);
    assert.equal(quiet.bodies.length, 0);
    await quiet.close();
    await page.context().close();
  });
});
