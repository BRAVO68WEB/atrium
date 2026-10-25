package hashalgo

// Argon2Template is the algo.go body written by `atrium-cli init --hash argon2id`.
// New passwords use argon2id. Existing bcrypt passwords still verify, and a
// successful login stores a new argon2id hash. Memory is 64 MiB.
const Argon2Template = "" +
	"package hashalgo\n" +
	"\n" +
	"import \"github.com/bravo68web/atrium/pkg/passhash\"\n" +
	"\n" +
	"// Hash is the only exported function in this file.\n" +
	"// Replace the body. Keep the name, the signature, and the package.\n" +
	"//\n" +
	"// New passwords use argon2id. Existing bcrypt passwords still verify,\n" +
	"// and a successful login stores a new argon2id hash.\n" +
	"// Memory is 64 MiB. Lower Memory if login stalls.\n" +
	"// Use subtle.ConstantTimeCompare for any raw digest you compare yourself.\n" +
	"func Hash() passhash.Hasher {\n" +
	"\treturn passhash.Fallback(\n" +
	"\t\tpasshash.Argon2id(passhash.DefaultArgon2),\n" +
	"\t\tpasshash.Bcrypt(passhash.DefaultBcryptCost),\n" +
	"\t)\n" +
	"}\n"

// BcryptTemplate is the shipped algo.go. init writes these bytes for --hash bcrypt.
func BcryptTemplate() string {
	return string(embeddedAlgo)
}
