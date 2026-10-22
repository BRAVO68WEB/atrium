package service

import (
	"net/http"
	"testing"
)

func TestClientIPIgnoresForwardedHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	if got := ClientIP(req, nil); got != "203.0.113.9" {
		t.Fatalf("ip %q", got)
	}
}

func TestClientIPUsesForwardedHeaderFromTrustedProxy(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.4, 10.1.1.1")
	got := ClientIP(req, []string{"10.0.0.0/8"})
	if got != "198.51.100.4" {
		t.Fatalf("ip %q", got)
	}
	req.Header.Set("X-Forwarded-For", "click.evil.example, 198.51.100.4")
	if got := ClientIP(req, []string{"10.0.0.0/8"}); got != "198.51.100.4" {
		t.Fatalf("non-ip forwarded value %q", got)
	}
	if err := ValidateTrustedProxies([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected invalid CIDR")
	}
}
