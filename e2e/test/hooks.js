const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const { spawn } = require("node:child_process");

const root = path.resolve(__dirname, "../..");
const bin = path.join(root, "e2e/.cache/atrium");
const pgBin = path.join(root, "e2e/.cache/pgserve");

let pgProc;
let pgBase = "";

function startPostgres() {
  pgProc = spawn(pgBin, [], { cwd: root, stdio: ["ignore", "pipe", "inherit"] });
  return new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error("pgserve did not listen")), 180000);
    pgProc.stdout.on("data", (chunk) => {
      buf += chunk.toString();
      const match = buf.match(/listen (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) {
        clearTimeout(timer);
        pgBase = match[1];
        resolve(pgBase);
      }
    });
    pgProc.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`pgserve exited ${code}`));
    });
  });
}

exports.mochaHooks = {
  async beforeAll() {
    this.timeout(180000);
    fs.mkdirSync(path.dirname(bin), { recursive: true });
    execFileSync("go", ["build", "-o", bin, "./cmd/atrium"], {
      cwd: root,
      stdio: "inherit",
    });
    execFileSync("go", ["build", "-o", pgBin, "./e2e/pgserve"], {
      cwd: root,
      stdio: "inherit",
    });
    await startPostgres();
  },
  async afterAll() {
    if (pgProc && pgProc.exitCode == null) {
      pgProc.kill("SIGTERM");
      await new Promise((resolve) => pgProc.once("exit", resolve));
    }
  },
};

exports.binPath = bin;
exports.repoRoot = root;
exports.pgBase = () => pgBase;
