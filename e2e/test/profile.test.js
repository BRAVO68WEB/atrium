const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser } = require("../support/oauth");
const { newPage, closeBrowser } = require("../support/browser");

describe("account profile", function () {
  let server;
  let user;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("profile") });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("shows the signed-in account", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/login?next=/profile`);
    await page.fill("#username", user.username);
    await page.fill("#password", user.password);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=Your account");
    const body = await page.textContent("body");
    assert.match(body, new RegExp(user.username));
    await page.context().close();
  });
});
