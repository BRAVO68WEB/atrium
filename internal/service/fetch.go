package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const fetchLimit = 1 << 20

// FetchSafe performs an outbound GET or POST that cannot reach private networks.
// Redirects are not followed. The body is capped at 1 MiB.
func FetchSafe(ctx context.Context, cfg *config.Config, method, rawURL string, body io.Reader, header http.Header) ([]byte, int, error) {
	defer telemetry.Step("service.FetchSafe")()
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, 0, fmt.Errorf("url is not absolute")
	}
	if err := validateFetchURL(cfg, u); err != nil {
		return nil, 0, err
	}
	ips, err := resolveFetchIPs(ctx, cfg, u.Hostname())
	if err != nil {
		return nil, 0, err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	target := net.JoinHostPort(ips[0].String(), port)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg != nil && cfg.Security.AllowInsecureFetch {
		tlsConfig.InsecureSkipVerify = true
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target)
		},
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if !isValidRedirectURL(cfg, rawURL) {
		return nil, 0, fmt.Errorf("url is not allowed")
	}
	ctx, end := telemetry.Start(ctx, "http.client")
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("server.address", u.Hostname()),
		attribute.String("http.request.method", method),
	)
	var httpStatus int
	defer func() {
		if httpStatus != 0 {
			span.SetAttributes(attribute.Int("http.response.status_code", httpStatus))
		}
		end()
	}()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, 0, err
	}
	for k, values := range header {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	httpStatus = resp.StatusCode
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, fetchLimit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(payload) > fetchLimit {
		return nil, resp.StatusCode, fmt.Errorf("response exceeds 1MiB")
	}
	return payload, resp.StatusCode, nil
}

// ValidateFetchTarget rejects URLs that FetchSafe would refuse, without dialing.
func ValidateFetchTarget(cfg *config.Config, raw string) error {
	defer telemetry.Step("service.ValidateFetchTarget")()
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("url must be absolute http or https")
	}
	if err := validateFetchURL(cfg, u); err != nil {
		return err
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !ipAllowed(cfg, ip) {
		return fmt.Errorf("url host is not allowed")
	}
	return nil
}

// isValidRedirectURL reports whether an absolute URL may be requested.
// The name is the check used immediately before the outbound call.
func isValidRedirectURL(cfg *config.Config, rawURL string) bool {
	defer telemetry.Step("service.isValidRedirectURL")()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	return validateFetchURL(cfg, parsed) == nil
}

func validateFetchURL(cfg *config.Config, u *url.URL) error {
	defer telemetry.Step("service.validateFetchURL")()
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if cfg != nil && cfg.Security.AllowInsecureFetch && isLoopbackHost(host) {
			return nil
		}
		return fmt.Errorf("only https urls can be fetched")
	default:
		return fmt.Errorf("only https urls can be fetched")
	}
}

func resolveFetchIPs(ctx context.Context, cfg *config.Config, host string) ([]netip.Addr, error) {
	defer telemetry.Step("service.resolveFetchIPs")()
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ipAllowed(cfg, ip) {
			return nil, fmt.Errorf("url host is not allowed")
		}
		return []netip.Addr{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	found, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var allowed []netip.Addr
	for _, ip := range found {
		if ipAllowed(cfg, ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("url host is not allowed")
	}
	return allowed, nil
}

func ipAllowed(cfg *config.Config, ip netip.Addr) bool {
	defer telemetry.Step("service.ipAllowed")()
	if cfg != nil {
		for _, raw := range cfg.Security.FetchAllowIPs {
			if allowed, err := netip.ParseAddr(raw); err == nil && allowed == ip {
				return true
			}
		}
	}
	return !isBlockedIP(ip)
}

func isBlockedIP(ip netip.Addr) bool {
	defer telemetry.Step("service.isBlockedIP")()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || isMetadataIP(ip)
}

func isMetadataIP(ip netip.Addr) bool {
	defer telemetry.Step("service.isMetadataIP")()
	meta := netip.MustParseAddr("169.254.169.254")
	return ip == meta
}

func isLoopbackHost(host string) bool {
	defer telemetry.Step("service.isLoopbackHost")()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
