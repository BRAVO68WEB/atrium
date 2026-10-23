const assert = require("node:assert/strict");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, tokenRequest } = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

function metadataServer() {
  const key = fs.readFileSync(path.join(__dirname, "../fixtures/cimd.key"));
  const cert = fs.readFileSync(path.join(__dirname, "../fixtures/cimd.crt"));
  let hits = 0;
  let url = "";
  let redirectURI = "http://localhost/cb";
  const server = https.createServer({ key, cert }, (request, response) => {
    hits += 1;
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({
      client_id: url,
      client_name: "Metadata App",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scope: "openid",
    }));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      url = `https://127.0.0.1:${server.address().port}/`;
      resolve({
        url,
        hits: () => hits,
        setRedirect(value) {
          redirectURI = value;
        },
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

describe("CIMD", function () {
  let server;
  let metadata;

  before(async function () {
    this.timeout(60000);
    metadata = await metadataServer();
    server = await startServer({
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
      registration: { cimd_enabled: true },
    });
  });

  after(async function () {
    await closeBrowser();
    if (metadata) {
      await metadata.close();
    }
    if (server) {
      await server.stop();
    }
  });

  it("fetches the metadata document once and sends the browser to login", async function () {
    const redirectURI = await callbackURL();
    metadata.setRedirect(redirectURI);
    const authorizeURL = new URL(`${server.base}/oauth/authorize`);
    authorizeURL.searchParams.set("client_id", metadata.url);
    authorizeURL.searchParams.set("redirect_uri", redirectURI);
    authorizeURL.searchParams.set("response_type", "code");
    authorizeURL.searchParams.set("scope", "openid");
    const first = await fetch(authorizeURL, { redirect: "manual" });
    assert.equal(first.status, 302, await first.text());
    assert.match(first.headers.get("location"), /\/login/);
    assert.equal(metadata.hits(), 1);

    const second = await fetch(authorizeURL, { redirect: "manual" });
    assert.equal(second.status, 302);
    assert.equal(metadata.hits(), 1);

    const user = await createUser(server, { username: shortID("cimd") });
    const page = await newPage();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", metadata.url);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
    }, { id: metadata.url });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    const before = metadata.hits();
    await authorize(page, url.toString(), user);
    assert.equal(metadata.hits(), before);
    await page.context().close();
  });
});
