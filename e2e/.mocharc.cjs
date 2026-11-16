const ci = Boolean(process.env.CI);

const config = {
  timeout: 60000,
  spec: "test/**/*.test.js",
  require: ["./test/hooks.js"],
  exit: true,
};

if (ci) {
  config.reporter = "mocha-multi-reporters";
  config.reporterOption = ["configFile=reporter.json"];
}

module.exports = config;
