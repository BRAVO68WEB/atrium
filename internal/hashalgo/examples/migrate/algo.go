package hashalgo

import "github.com/bravo68web/atrium/pkg/passhash"

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// New passwords use argon2id at 64 MiB. A hash from the 19 MiB setting
// or from bcrypt still verifies, and a successful login rewrites it.
func Hash() passhash.Hasher {
	small := passhash.Argon2id(passhash.Argon2Params{
		Memory:      19 * 1024,
		Iterations:  2,
		Parallelism: 1,
	})
	return passhash.Fallback(
		passhash.Argon2id(passhash.DefaultArgon2),
		passhash.Fallback(small, passhash.Bcrypt(passhash.DefaultBcryptCost)),
	)
}
