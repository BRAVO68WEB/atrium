package oidc

import (
	"strings"
	"testing"
	"time"
)

func TestSigningKeysListAndRotate(t *testing.T) {
	set, err := LoadKeySet(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := set.SigningKeys()
	if len(keys) != 2 {
		t.Fatalf("keys %+v", keys)
	}
	algs := map[string]string{}
	for _, key := range keys {
		if key.Status != "active" || key.Kid == "" || key.CreatedAt == "" {
			t.Fatalf("key %+v", key)
		}
		algs[key.Alg] = key.Kty
		if strings.Contains(key.Kid, "PRIVATE") {
			t.Fatal(key.Kid)
		}
	}
	if algs["RS256"] != "RSA" || algs["ES256"] != "EC" {
		t.Fatalf("algs %v", algs)
	}
	if err := set.Rotate(time.Hour); err != nil {
		t.Fatal(err)
	}
	active, retiring := 0, 0
	for _, key := range set.SigningKeys() {
		switch key.Status {
		case "active":
			active++
		case "retiring":
			retiring++
			if key.RetireAt == "" {
				t.Fatalf("retiring key %+v", key)
			}
		default:
			t.Fatalf("status %+v", key)
		}
	}
	if active != 2 || retiring != 2 {
		t.Fatalf("active %d retiring %d", active, retiring)
	}
}
