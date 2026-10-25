package hashalgo

import "github.com/bravo68web/atrium/pkg/passhash"

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// Use subtle.ConstantTimeCompare for any raw digest you compare yourself.
// The built-in hashers already compare in constant time.
func Hash() passhash.Hasher {
	return passhash.Bcrypt(passhash.DefaultBcryptCost)
}
