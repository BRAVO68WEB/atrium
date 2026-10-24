const assert = require("node:assert/strict");
const net = require("node:net");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser } = require("../support/oauth");
const { newPage, closeBrowser } = require("../support/browser");
const { settled } = require("../support/wait");

function startSMTP() {
  const messages = [];
  const server = net.createServer((socket) => {
    socket.write("220 localhost ESMTP\r\n");
    let buf = "";
    let collecting = false;
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (collecting) {
        const end = buf.indexOf("\r\n.\r\n");
        if (end === -1) {
          return;
        }
        messages.push(buf.slice(0, end));
        buf = buf.slice(end + 5);
        collecting = false;
        socket.write("250 queued\r\n");
      }
      const lines = buf.split("\r\n");
      buf = lines.pop();
      for (const line of lines) {
        const cmd = line.toUpperCase();
        if (cmd.startsWith("EHLO") || cmd.startsWith("HELO")) {
          socket.write("250-localhost\r\n250 OK\r\n");
        } else if (cmd === "DATA") {
          collecting = true;
          socket.write("354 send\r\n");
        } else if (cmd === "QUIT") {
          socket.write("221 bye\r\n");
          socket.end();
        } else {
          socket.write("250 ok\r\n");
        }
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: server.address().port,
        messages,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

describe("password reset", function () {
  let smtp;
  let server;
  let user;

  before(async function () {
    this.timeout(60000);
    smtp = await startSMTP();
    server = await startServer({ smtp: { port: smtp.port } });
    user = await createUser(server, { username: shortID("reset") });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
    if (smtp) {
      await smtp.close();
    }
  });

  it("emails a link and accepts the new password", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/forgot`);
    await page.fill("#username", user.username);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=reset link is on its way");
    const deadline = Date.now() + 5000;
    while (smtp.messages.length === 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(smtp.messages.length > 0, true, "reset mail did not arrive");
    const link = smtp.messages.join("\n").match(/https?:\/\/\S+\/reset\?token=\S+/);
    assert.ok(link, smtp.messages.join("\n"));
    await page.goto(link[0].replace(/[>\s].*$/, ""));
    await page.fill("#password", "correct-horse-2");
    await page.click("button[type=submit]");
    await page.waitForSelector("text=password has been updated");
    await page.goto(link[0].replace(/[>\s].*$/, ""));
    await page.fill("#password", "correct-horse-3");
    await page.click("button[type=submit]");
    await page.waitForSelector("text=already been used");
    await page.goto(`${server.base}/login?next=/profile`);
    await page.fill("#username", user.username);
    await page.fill("#password", user.password);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=Invalid credentials");
    await page.goto(`${server.base}/login?next=/profile`);
    await page.fill("#username", user.username);
    await page.fill("#password", "correct-horse-2");
    await page.click("button[type=submit]");
    await page.waitForSelector("text=Your account");
    await page.context().close();
  });

  it("does not send mail for an unknown account", async function () {
    await settled(() => smtp.messages.length);
    const before = smtp.messages.length;
    const page = await newPage();
    await page.goto(`${server.base}/forgot`);
    await page.fill("#username", "nobody-no-such-user");
    await page.click("button[type=submit]");
    await page.waitForSelector("text=reset link is on its way");
    await settled(() => smtp.messages.length);
    assert.equal(smtp.messages.length, before);
    await page.context().close();
  });
});
