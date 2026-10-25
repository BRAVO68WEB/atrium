package hashalgo

import "github.com/bravo68web/atrium/pkg/passhash"

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// Cutover, not a migration. A stored bcrypt hash does not verify.
// Memory is 64 MiB.
func Hash() passhash.Hasher {
	return passhash.Argon2id(passhash.DefaultArgon2)
}
