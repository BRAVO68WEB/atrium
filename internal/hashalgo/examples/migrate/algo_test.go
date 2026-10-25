package hashalgo

import (
	"testing"

	"github.com/bravo68web/atrium/pkg/passhash"
)

func TestRoundTrip(t *testing.T) {
	h := Hash()
	encoded, err := h.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(encoded, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(encoded, "wrong horse"); err == nil {
		t.Fatal("accepted a wrong password")
	}
	older, err := passhash.Bcrypt(passhash.DefaultBcryptCost).Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(older, "correct horse"); err != nil {
		t.Fatal("bcrypt password should still verify")
	}
	small, err := passhash.Argon2id(passhash.Argon2Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1}).Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(small, "correct horse"); err != nil {
		t.Fatal("small argon2id password should still verify")
	}
}
