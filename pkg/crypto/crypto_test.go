package crypto

import (
	"strings"
	"testing"
)

func TestGenerateRandomBytes(t *testing.T) {
	bytes1, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	bytes2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	if len(bytes1) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(bytes1))
	}

	if string(bytes1) == string(bytes2) {
		t.Error("Random bytes should be different")
	}
}

func TestGenerateRandomString(t *testing.T) {
	str1, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("GenerateRandomString failed: %v", err)
	}

	str2, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("GenerateRandomString failed: %v", err)
	}

	if len(str1) == 0 {
		t.Error("Random string should not be empty")
	}

	if str1 == str2 {
		t.Error("Random strings should be different")
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token1 == token2 {
		t.Error("Tokens should be different")
	}

	if len(token1) == 0 {
		t.Error("Token should not be empty")
	}
}

func TestGenerateAuthorizationCode(t *testing.T) {
	code, err := GenerateAuthorizationCode()
	if err != nil {
		t.Fatalf("GenerateAuthorizationCode failed: %v", err)
	}

	if len(code) == 0 {
		t.Error("Authorization code should not be empty")
	}
}

func TestGenerateUserCode(t *testing.T) {
	code, err := GenerateUserCode()
	if err != nil {
		t.Fatalf("GenerateUserCode failed: %v", err)
	}

	if len(code) == 0 {
		t.Error("User code should not be empty")
	}

	if !strings.Contains(code, "-") {
		t.Error("User code should contain dash separator")
	}
}

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier failed: %v", err)
	}

	if !ValidateCodeVerifier(verifier) {
		t.Error("Generated verifier should be valid")
	}
}

func TestValidateCodeVerifier(t *testing.T) {
	tests := []struct {
		name     string
		verifier string
		valid    bool
	}{
		{"valid short", strings.Repeat("a", 43), true},
		{"valid long", strings.Repeat("a", 128), true},
		{"invalid too short", strings.Repeat("a", 42), false},
		{"invalid too long", strings.Repeat("a", 129), false},
		{"invalid special chars", "abc!@#$%^&*()", false},
		{"valid with unreserved", "abc-._~DEF" + strings.Repeat("a", 33), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCodeVerifier(tt.verifier)
			if result != tt.valid {
				t.Errorf("ValidateCodeVerifier(%q) = %v, want %v", tt.verifier, result, tt.valid)
			}
		})
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := GenerateCodeChallenge(verifier)

	if challenge == "" {
		t.Error("Code challenge should not be empty")
	}

	if challenge == verifier {
		t.Error("Code challenge should be different from verifier")
	}
}

func TestValidateCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := GenerateCodeChallenge(verifier)

	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		valid     bool
	}{
		{"valid S256", verifier, challenge, "S256", true},
		{"invalid S256", verifier, "wrong_challenge", "S256", false},
		{"valid plain", verifier, verifier, "plain", true},
		{"invalid plain", verifier, "wrong", "plain", false},
		{"short verifier", "abc", "abc", "plain", false},
		{"unsupported method", verifier, challenge, "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCodeChallenge(tt.verifier, tt.challenge, tt.method)
			if result != tt.valid {
				t.Errorf("ValidateCodeChallenge(%q, %q, %q) = %v, want %v",
					tt.verifier, tt.challenge, tt.method, result, tt.valid)
			}
		})
	}
}

func TestNormalizeScopes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"empty", "", nil},
		{"single", "openid", []string{"openid"}},
		{"multiple", "openid profile email", []string{"openid", "profile", "email"}},
		{"with duplicates", "openid profile openid email", []string{"openid", "profile", "email"}},
		{"with spaces", "  openid   profile  ", []string{"openid", "profile"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeScopes(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("NormalizeScopes(%q) returned %d items, want %d",
					tt.input, len(result), len(tt.expected))
				return
			}
			for i, s := range result {
				if s != tt.expected[i] {
					t.Errorf("NormalizeScopes(%q)[%d] = %q, want %q",
						tt.input, i, s, tt.expected[i])
				}
			}
		})
	}
}

func TestJoinScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected string
	}{
		{"empty", nil, ""},
		{"single", []string{"openid"}, "openid"},
		{"multiple", []string{"openid", "profile", "email"}, "openid profile email"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := JoinScopes(tt.scopes)
			if result != tt.expected {
				t.Errorf("JoinScopes(%v) = %q, want %q", tt.scopes, result, tt.expected)
			}
		})
	}
}

func TestBase64URLEncodeDecode(t *testing.T) {
	data := []byte("Hello, World!")
	encoded := Base64URLEncode(data)

	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("Base64URLDecode failed: %v", err)
	}

	if string(decoded) != string(data) {
		t.Errorf("Decoded data doesn't match original: got %q, want %q", decoded, data)
	}
}

func TestGenerateRequestURI(t *testing.T) {
	uri, err := GenerateRequestURI()
	if err != nil {
		t.Fatalf("GenerateRequestURI failed: %v", err)
	}

	if !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("Request URI should start with urn:ietf:params:oauth:request_uri:, got %q", uri)
	}
}
