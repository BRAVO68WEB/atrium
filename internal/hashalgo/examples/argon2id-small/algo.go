package hashalgo

import "github.com/bravo68web/oauth-impl/pkg/passhash"

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// 19 MiB is the smaller-machine setting. The argon2id example uses 64 MiB.
// Existing bcrypt passwords still verify, and a successful login stores
// a new hash at these parameters.
func Hash() passhash.Hasher {
	return passhash.Fallback(
		passhash.Argon2id(passhash.Argon2Params{
			Memory:      19 * 1024,
			Iterations:  2,
			Parallelism: 1,
		}),
		passhash.Bcrypt(passhash.DefaultBcryptCost),
	)
}
