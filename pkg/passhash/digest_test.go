package passhash

import "testing"

func TestDigestAndPBKDF2RoundTrip(t *testing.T) {
	hashers := []Hasher{
		MD5(),
		SHA256(),
		SHA512(),
		SHA3512(),
		SHA2_128(),
		PBKDF2(PBKDF2Params{Iterations: 2}),
	}
	for _, hasher := range hashers {
		encoded, err := hasher.Hash("correct horse")
		if err != nil {
			t.Fatalf("%s hash: %v", hasher.ID(), err)
		}
		if !Accepts(hasher, encoded) {
			t.Fatalf("%s did not recognize %s", hasher.ID(), encoded)
		}
		if err := hasher.Verify(encoded, "correct horse"); err != nil {
			t.Fatalf("%s verify: %v", hasher.ID(), err)
		}
		if err := hasher.Verify(encoded, "wrong"); err == nil {
			t.Fatalf("%s accepted a wrong password", hasher.ID())
		}
	}
}

func TestPBKDF2NeedsRehashWhenIterationsChange(t *testing.T) {
	slow := PBKDF2(PBKDF2Params{Iterations: 2})
	encoded, err := slow.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	fast := PBKDF2(PBKDF2Params{Iterations: 3}).(Rehasher)
	if !fast.NeedsRehash(encoded) {
		t.Fatal("expected a rehash when the iteration count differs")
	}
	if err := PBKDF2(PBKDF2Params{Iterations: 3}).Verify(encoded, "correct horse"); err != nil {
		t.Fatal(err)
	}
}
