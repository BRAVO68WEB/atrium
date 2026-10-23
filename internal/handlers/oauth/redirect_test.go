package oauth

import "testing"

func TestRedirectMustBeRegistered(t *testing.T) {
	if isValidRedirectURI("https://evil.example/cb", nil) {
		t.Fatal("empty registration accepted an attacker redirect")
	}
	if isValidRedirectURI("https://evil.example/cb", []string{"https://app.example/cb"}) {
		t.Fatal("unregistered redirect was accepted")
	}
	if !isValidRedirectURI("https://app.example/cb", []string{"https://app.example/cb"}) {
		t.Fatal("registered redirect was rejected")
	}
}

func TestClientGrantGatesResponseType(t *testing.T) {
	grants := []string{"client_credentials"}
	if clientAllowsResponseType(grants, "code") {
		t.Fatal("client credentials client was allowed an authorization code")
	}
	if !clientAllowsResponseType([]string{"authorization_code"}, "code") {
		t.Fatal("authorization code client was rejected")
	}
	if !clientAllowsResponseType(nil, "code") {
		t.Fatal("a client with no stored grants was rejected")
	}
	if clientAllowsResponseType([]string{"authorization_code"}, "id_token") {
		t.Fatal("code client was allowed an implicit response")
	}
	if responseHas("id_token", "token") {
		t.Fatal("id_token was treated as an access token")
	}
	if !responseHas("code id_token token", "token") || !responseHas("code id_token token", "id_token") || !responseHas("code id_token token", "code") {
		t.Fatal("hybrid response type was split wrong")
	}
}
