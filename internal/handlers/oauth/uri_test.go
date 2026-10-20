package oauth

import "testing"

func TestRedirectURIRejectsALookalikeHostAndAFragment(t *testing.T) {
	if isValidURI("http://localhost.evil.com/cb") {
		t.Fatal("accepted a host that only starts with localhost")
	}
	if isValidURI("https://app.example/cb#code") {
		t.Fatal("accepted a fragment")
	}
	if !isValidURI("http://localhost:8080/cb") {
		t.Fatal("rejected localhost")
	}
	if !isValidURI("https://app.example/cb") {
		t.Fatal("rejected https")
	}
}
