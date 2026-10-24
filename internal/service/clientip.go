package service

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

func ValidateTrustedProxies(values []string) error {
	defer telemetry.Step("service.ValidateTrustedProxies")()
	for _, value := range values {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("trusted proxy %q is not a CIDR", value)
		}
	}
	return nil
}

func ClientIP(r *http.Request, trusted []string) string {
	defer telemetry.Step("service.ClientIP")()
	if r == nil {
		return ""
	}
	peer := canonicalIP(r.RemoteAddr)
	nets := trustedNets(trusted)
	if peer != "" && !ipInNets(peer, nets) {
		return peer
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := canonicalIP(parts[i])
			if ip == "" {
				continue
			}
			if !ipInNets(ip, nets) {
				return ip
			}
		}
	}
	if real := canonicalIP(r.Header.Get("X-Real-IP")); real != "" {
		return real
	}
	return peer
}

func canonicalIP(value string) string {
	defer telemetry.Step("service.canonicalIP")()
	parsed := net.ParseIP(hostOnly(value))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func trustedNets(values []string) []*net.IPNet {
	defer telemetry.Step("service.trustedNets")()
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err == nil {
			out = append(out, network)
		}
	}
	return out
}

func ipInNets(ip string, nets []*net.IPNet) bool {
	defer telemetry.Step("service.ipInNets")()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range nets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func hostOnly(value string) string {
	defer telemetry.Step("service.hostOnly")()
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return strings.Trim(value, "[]")
}
