const crypto = require("node:crypto");

const info = "draft-richer-oauth-oob-authcode";

function recover(combined, state) {
  const checksum = Buffer.from(combined.slice(0, 4), "base64url");
  const encoded = Buffer.from(combined.slice(4), "base64url");
  if (checksum.length !== 3 || encoded.length === 0) {
    throw new Error("combined code is invalid");
  }
  const key = Buffer.from(crypto.hkdfSync(
    "sha256",
    Buffer.from(state),
    Buffer.alloc(0),
    Buffer.from(info),
    encoded.length,
  ));
  const raw = Buffer.alloc(encoded.length);
  for (let i = 0; i < encoded.length; i += 1) {
    raw[i] = encoded[i] ^ key[i];
  }
  const sum = crypto.createHash("sha256").update(raw).digest().subarray(0, 3);
  if (!sum.equals(checksum)) {
    throw new Error("combined code checksum mismatch");
  }
  return raw.toString();
}

module.exports = { recover };
