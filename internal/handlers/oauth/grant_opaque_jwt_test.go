package oauth

import "testing"

func TestCustomClaims(t *testing.T) {
	got, err := customClaims(`{"tenant":"acme","level":2,"admin":false}`)
	if err != nil || got["tenant"] != "acme" || got["level"].(float64) != 2 || got["admin"] != false {
		t.Fatalf("claims %+v %v", got, err)
	}
	if _, err := customClaims(""); err != nil {
		t.Fatal(err)
	}
	if _, err := customClaims(`{"sub":"other"}`); err == nil {
		t.Fatal("reserved claim accepted")
	}
	if _, err := customClaims(`["nope"]`); err == nil {
		t.Fatal("array accepted")
	}
	if _, err := customClaims(`{"nest":{"a":1}}`); err == nil {
		t.Fatal("object accepted")
	}
}
