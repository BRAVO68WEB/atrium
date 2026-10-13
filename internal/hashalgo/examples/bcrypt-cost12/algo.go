package hashalgo

import "github.com/bravo68web/oauth-impl/pkg/passhash"

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// Cost 12 is slower than the shipped default. A hash stored at another
// bcrypt cost still verifies, and a successful login stores a cost-12 hash.
func Hash() passhash.Hasher {
	return passhash.Bcrypt(12)
}
