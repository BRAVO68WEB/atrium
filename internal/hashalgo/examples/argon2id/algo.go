package hashalgo

import "github.com/bravo68web/atrium/pkg/passhash"

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// New passwords use argon2id. Existing bcrypt passwords still verify,
// and a successful login stores a new argon2id hash.
// Memory is 64 MiB. Lower Memory if login stalls.
// Use subtle.ConstantTimeCompare for any raw digest you compare yourself.
func Hash() passhash.Hasher {
	return passhash.Fallback(
		passhash.Argon2id(passhash.DefaultArgon2),
		passhash.Bcrypt(passhash.DefaultBcryptCost),
	)
}
