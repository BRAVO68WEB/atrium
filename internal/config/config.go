package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Database     DatabaseConfig     `yaml:"database"`
	Redis        RedisConfig        `yaml:"redis"`
	Cache        CacheConfig        `yaml:"cache"`
	Security     SecurityConfig     `yaml:"security"`
	Queue        QueueConfig        `yaml:"queue"`
	Notify       NotifyConfig       `yaml:"notify"`
	OIDC         OIDCConfig         `yaml:"oidc"`
	Management   ManagementConfig   `yaml:"management"`
	SMTP         SMTPConfig         `yaml:"smtp"`
	Email        EmailConfig        `yaml:"email"`
	Branding     BrandingConfig     `yaml:"branding"`
	Social       SocialConfig       `yaml:"social"`
	Registration RegistrationConfig `yaml:"registration"`
	Telemetry    TelemetryConfig    `yaml:"telemetry"`
	Log          LogConfig          `yaml:"log"`
	Org          OrgConfig          `yaml:"org"`
	Push         PushConfig         `yaml:"push"`
	AAuth        AAuthConfig        `yaml:"aauth"`
	XAA          XAAConfig          `yaml:"xaa"`
	Debug        DebugConfig        `yaml:"debug"`
}

// DebugConfig turns on developer-only routes. UI is the auth-page preview.
type DebugConfig struct {
	UI bool `yaml:"ui"`
}

// PushConfig is authenticator-device registration. Enabled stays false
// unless set, so a default server does not publish the push document.
type PushConfig struct {
	Enabled                bool   `yaml:"enabled"`
	RegistrationTokenTTL   int    `yaml:"registration_token_ttl"`
	MinimumInteractionType string `yaml:"minimum_interaction_type"`
	MaxDevicesPerUser      int    `yaml:"max_devices_per_user"`
	ClientAttestation      bool   `yaml:"client_attestation_required"`
	GracePeriodSeconds     int    `yaml:"grace_period_seconds"`
	PingEnabled            bool   `yaml:"ping_enabled"`
	PushEnabled            bool   `yaml:"push_enabled"`
	RelayEndpoint          string `yaml:"relay_endpoint"`
}

// AAuthConfig is the agent authorization protocol. Enabled stays false
// unless set, so a default server does not publish AAuth metadata.
type AAuthConfig struct {
	Enabled        bool   `yaml:"enabled"`
	APIssuer       string `yaml:"ap_issuer"`
	PSIssuer       string `yaml:"ps_issuer"`
	ASIssuer       string `yaml:"as_issuer"`
	ResourceIssuer string `yaml:"resource_issuer"`
	ResourceMode   string `yaml:"resource_mode"`
}

// OrgConfig turns organizations on. Both flags stay false unless set, so a
// default server never selects an organization.
type OrgConfig struct {
	Enabled                      bool `yaml:"enabled"`
	EnabledDomainBasedAutolookup bool `yaml:"enabled_domain_based_autolookup"`
}

// LogConfig selects the process log format. Empty and text print a
// human line. json prints one JSON object per record.
type LogConfig struct {
	Format string `yaml:"format"`
}

// TelemetryConfig controls OpenTelemetry traces. Enabled is false unless
// the operator sets it, so a default server does not dial a collector.
type TelemetryConfig struct {
	Enabled      bool    `yaml:"enabled"`
	ServiceName  string  `yaml:"service_name"`
	OTLPEndpoint string  `yaml:"otlp_endpoint"`
	Insecure     bool    `yaml:"insecure"`
	SampleRatio  float64 `yaml:"sample_ratio"`
}

type ServerConfig struct {
	Host string    `yaml:"host"`
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ClientCA   string `yaml:"client_ca"`
	ClientAuth string `yaml:"client_auth"`
	CRLFile    string `yaml:"crl_file"`
}

type DatabaseConfig struct {
	Driver     string `yaml:"driver"`
	Path       string `yaml:"path"`
	DSN        string `yaml:"dsn"`
	Migrations bool   `yaml:"migrations"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	Prefix   string `yaml:"prefix"`
}

type CacheConfig struct {
	Provider string `yaml:"provider"`
}

type SecurityConfig struct {
	AccessTokenLifetime       time.Duration       `yaml:"access_token_lifetime"`
	RefreshTokenLifetime      time.Duration       `yaml:"refresh_token_lifetime"`
	AuthorizationCodeLifetime time.Duration       `yaml:"authorization_code_lifetime"`
	DeviceCodeLifetime        time.Duration       `yaml:"device_code_lifetime"`
	CIBARequestLifetime       time.Duration       `yaml:"ciba_request_lifetime"`
	RequestURILifetime        time.Duration       `yaml:"request_uri_lifetime"`
	RequirePKCE               bool                `yaml:"require_pkce"`
	AllowPlainPKCE            bool                `yaml:"allow_plain_pkce"`
	AccessTokenFormat         string              `yaml:"access_token_format"`
	Issuer                    string              `yaml:"issuer"`
	HashAlgo                  string              `yaml:"hash_algo"`
	SessionLifetime           time.Duration       `yaml:"session_lifetime"`
	ResetTokenLifetime        time.Duration       `yaml:"reset_token_lifetime"`
	TrustedProxies            []string            `yaml:"trusted_proxies"`
	LoginIdentifier           string              `yaml:"login_identifier"`
	DisableRegistration       bool                `yaml:"disable_registration"`
	DisableSocialRegistration bool                `yaml:"disable_social_registration"`
	AllowInsecureFetch        bool                `yaml:"allow_insecure_fetch"`
	FetchAllowIPs             []string            `yaml:"fetch_allow_ips"`
	OOBHelper                 bool                `yaml:"oob_helper"`
	Password                  PasswordPolicy      `yaml:"password"`
	BotProtection             BotProtectionConfig `yaml:"bot_protection"`
	MFA                       MFAConfig           `yaml:"mfa"`
	MTLS                      MTLSConfig          `yaml:"mtls"`
	DPoP                      DPoPConfig          `yaml:"dpop"`
}

type ManagementConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// EmailConfig points at optional message files. An empty directory keeps
// the built-in text.
type EmailConfig struct {
	TemplatesDir string `yaml:"templates_dir"`
}

type SMTPConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	From        string `yaml:"from"`
	StartTLS    bool   `yaml:"starttls"`
	ImplicitTLS bool   `yaml:"implicit_tls"`
}

// BrandingConfig paints the browser auth pages. ShowRegister and
// ShowForgotPassword stay nil when the YAML key is missing; Normalize turns
// that into true so an older config keeps both links.
type BrandingConfig struct {
	ProductName        string `yaml:"product_name"`
	LoginTitle         string `yaml:"login_title"`
	UsernameLabel      string `yaml:"username_label"`
	PasswordLabel      string `yaml:"password_label"`
	SubmitLabel        string `yaml:"submit_label"`
	AssetsDir          string `yaml:"assets_dir"`
	LogoFile           string `yaml:"logo_file"`
	FaviconFile        string `yaml:"favicon_file"`
	BackgroundFile     string `yaml:"background_file"`
	PrimaryColor       string `yaml:"primary_color"`
	BackgroundColor    string `yaml:"background_color"`
	TextColor          string `yaml:"text_color"`
	FooterText         string `yaml:"footer_text"`
	SupportURL         string `yaml:"support_url"`
	PrivacyURL         string `yaml:"privacy_url"`
	TermsURL           string `yaml:"terms_url"`
	ShowRegister       *bool  `yaml:"show_register"`
	ShowForgotPassword *bool  `yaml:"show_forgot_password"`
	Templates          string `yaml:"templates"`
}

// SocialProvider is one upstream OAuth app. Type is google, github, facebook, oidc, or oauth2.
type SocialProvider struct {
	ID                    string   `yaml:"id"`
	Type                  string   `yaml:"type"`
	Name                  string   `yaml:"name"`
	Enabled               bool     `yaml:"enabled"`
	ClientID              string   `yaml:"client_id"`
	ClientSecret          string   `yaml:"client_secret"`
	Scopes                []string `yaml:"scopes"`
	Issuer                string   `yaml:"issuer"`
	AuthorizationEndpoint string   `yaml:"authorization_endpoint"`
	TokenEndpoint         string   `yaml:"token_endpoint"`
	UserinfoEndpoint      string   `yaml:"userinfo_endpoint"`
	SubjectField          string   `yaml:"subject_field"`
	EmailField            string   `yaml:"email_field"`
	UsernameField         string   `yaml:"username_field"`
	EmailVerifiedField    string   `yaml:"email_verified_field"`
}

type SocialConfig struct {
	Providers []SocialProvider `yaml:"providers"`
}

type MFAConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Required bool   `yaml:"required"`
	Issuer   string `yaml:"issuer"`
	Digits   int    `yaml:"digits"`
	Period   uint   `yaml:"period"`
}

type MTLSConfig struct {
	Enabled          bool `yaml:"enabled"`
	CertBinding      bool `yaml:"cert_binding"`
	BindRefreshToken bool `yaml:"bind_refresh_token"`
	RequireForToken  bool `yaml:"require_for_token"`
}

type PasswordPolicy struct {
	MinLength        int  `yaml:"min_length"`
	MaxLength        int  `yaml:"max_length"`
	RequireUppercase bool `yaml:"require_uppercase"`
	RequireLowercase bool `yaml:"require_lowercase"`
	RequireNumber    bool `yaml:"require_number"`
	RequireSymbol    bool `yaml:"require_symbol"`
	BlockUsername    bool `yaml:"block_username"`
}

type BotProtectionConfig struct {
	Provider  string `yaml:"provider"`
	SiteKey   string `yaml:"site_key"`
	SecretKey string `yaml:"secret_key"`
}

type ClaimMapping struct {
	Claim  string   `yaml:"claim"`
	Source string   `yaml:"source"`
	Scopes []string `yaml:"scopes"`
}

type RegistrationConfig struct {
	DCREnabled  bool `yaml:"dcr_enabled"`
	CIMDEnabled bool `yaml:"cimd_enabled"`
}

type DPoPConfig struct {
	Enabled       bool `yaml:"enabled"`
	ProofLifetime int  `yaml:"proof_lifetime"`
	NonceRequired bool `yaml:"nonce_required"`
	NonceLifetime int  `yaml:"nonce_lifetime"`
}

type QueueConfig struct {
	Type         string        `yaml:"type"`
	PollInterval time.Duration `yaml:"poll_interval"`
	MaxPending   int           `yaml:"max_pending"`
}

// NotifyConfig selects the retry queue for webhook and mail delivery.
// Type is memory, redis, or rabbitmq. memory is the default and drops
// jobs when the process exits.
type NotifyConfig struct {
	Type     string         `yaml:"type"`
	RabbitMQ RabbitMQConfig `yaml:"rabbitmq"`
}

// RabbitMQConfig is the broker used when notify.type is rabbitmq.
type RabbitMQConfig struct {
	URL      string `yaml:"url"`
	Exchange string `yaml:"exchange"`
	Queue    string `yaml:"queue"`
}

type OIDCConfig struct {
	Issuer               string         `yaml:"issuer"`
	SigningKey           string         `yaml:"signing_key"`
	SupportedScopes      []string       `yaml:"supported_scopes"`
	SupportedClaims      []string       `yaml:"supported_claims"`
	SupportedGrantTypes  []string       `yaml:"supported_grant_types"`
	SupportedAuthMethods []string       `yaml:"supported_auth_methods"`
	ClaimMappings        []ClaimMapping `yaml:"claim_mappings"`
	KeyRotationInterval  time.Duration  `yaml:"key_rotation_interval"`
	KeyRetain            time.Duration  `yaml:"key_retain"`
	PairwiseSalt         string         `yaml:"pairwise_salt"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
			TLS: TLSConfig{
				Enabled:    false,
				ClientAuth: "none",
			},
		},
		Database: DatabaseConfig{
			Driver:     "sqlite",
			Path:       "./atrium.db",
			Migrations: true,
		},
		Redis: RedisConfig{Prefix: "atrium"},
		Cache: CacheConfig{Provider: "memory"},
		Security: SecurityConfig{
			AccessTokenLifetime:       3600 * time.Second,
			RefreshTokenLifetime:      86400 * time.Second,
			AuthorizationCodeLifetime: 600 * time.Second,
			DeviceCodeLifetime:        1800 * time.Second,
			CIBARequestLifetime:       120 * time.Second,
			RequestURILifetime:        60 * time.Second,
			RequirePKCE:               false,
			AllowPlainPKCE:            true,
			AccessTokenFormat:         "opaque",
			Issuer:                    "http://localhost:8080",
			HashAlgo:                  "internal/hashalgo/algo.go",
			SessionLifetime:           8 * time.Hour,
			ResetTokenLifetime:        30 * time.Minute,
			DisableRegistration:       false,
			DisableSocialRegistration: false,
			OOBHelper:                 false,
			Password: PasswordPolicy{
				MinLength:     8,
				MaxLength:     128,
				BlockUsername: true,
			},
			MFA: MFAConfig{
				Enabled:  false,
				Required: false,
				Issuer:   "Atrium",
				Digits:   6,
				Period:   30,
			},
			MTLS: MTLSConfig{
				Enabled:          false,
				CertBinding:      false,
				BindRefreshToken: false,
				RequireForToken:  false,
			},
			DPoP: DPoPConfig{
				Enabled:       false,
				ProofLifetime: 300,
				NonceRequired: false,
				NonceLifetime: 300,
			},
		},
		Queue: QueueConfig{
			Type:         "memory",
			PollInterval: 5 * time.Second,
			MaxPending:   100,
		},
		Notify: NotifyConfig{
			Type: "memory",
			RabbitMQ: RabbitMQConfig{
				Exchange: "oauth.notify",
				Queue:    "oauth.notify",
			},
		},
		Management: ManagementConfig{},
		SMTP: SMTPConfig{
			Port:     587,
			StartTLS: true,
		},
		Branding:     defaultBranding(),
		Social:       SocialConfig{Providers: []SocialProvider{}},
		Registration: RegistrationConfig{DCREnabled: true},
		OIDC: OIDCConfig{
			Issuer:    "http://localhost:8080",
			KeyRetain: 48 * time.Hour,
			SupportedScopes: []string{
				"openid", "profile", "email", "address", "phone", "offline_access",
			},
			SupportedClaims: []string{
				"sub", "name", "given_name", "family_name", "middle_name",
				"nickname", "preferred_username", "profile", "picture",
				"website", "email", "email_verified", "gender", "birthdate",
				"zoneinfo", "locale", "phone_number", "phone_number_verified",
				"address", "updated_at", "sid",
			},
			SupportedGrantTypes: []string{
				"authorization_code",
				"client_credentials",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:device_code",
				"urn:openid:params:grant-type:ciba",
				"urn:ietf:params:oauth:grant-type:token-exchange",
			},
			SupportedAuthMethods: []string{
				"client_secret_basic",
				"client_secret_post",
				"client_secret_jwt",
				"private_key_jwt",
				"none",
				"tls_client_auth",
				"self_signed_tls_client_auth",
			},
		},
		Telemetry: TelemetryConfig{
			ServiceName: "atrium",
			SampleRatio: 1,
		},
		Push: PushConfig{
			Enabled:                false,
			RegistrationTokenTTL:   300,
			MinimumInteractionType: "boolean",
			MaxDevicesPerUser:      5,
			ClientAttestation:      false,
			GracePeriodSeconds:     300,
		},
		AAuth: AAuthConfig{
			Enabled:      false,
			ResourceMode: "as",
		},
		XAA: XAAConfig{
			Enabled: false,
			Trusts:  []XAATrust{},
			IDPs:    []XAAIdentityProvider{},
		},
		Debug: DebugConfig{UI: false},
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		cfg.Normalize()
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.Normalize()
	if err := ValidateBranding(cfg); err != nil {
		return nil, err
	}
	if err := ValidateSocial(cfg); err != nil {
		return nil, err
	}
	if err := ValidatePlatform(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func defaultBranding() BrandingConfig {
	showRegister := true
	showForgot := true
	return BrandingConfig{
		ProductName:        "Atrium",
		LoginTitle:         "Sign In",
		UsernameLabel:      "Username",
		PasswordLabel:      "Password",
		SubmitLabel:        "Sign In",
		PrimaryColor:       "#0066ff",
		ShowRegister:       &showRegister,
		ShowForgotPassword: &showForgot,
	}
}

// Normalize fills branding copy that was left empty and turns a missing
// show_register or show_forgot_password key into true.
func (c *Config) Normalize() {
	if c == nil {
		return
	}
	b := &c.Branding
	if b.ProductName == "" {
		b.ProductName = "Atrium"
	}
	if b.LoginTitle == "" {
		b.LoginTitle = "Sign In"
	}
	if b.UsernameLabel == "" {
		b.UsernameLabel = "Username"
	}
	if b.PasswordLabel == "" {
		b.PasswordLabel = "Password"
	}
	if b.SubmitLabel == "" {
		b.SubmitLabel = "Sign In"
	}
	if b.PrimaryColor == "" {
		b.PrimaryColor = "#0066ff"
	}
	if b.ShowRegister == nil {
		v := true
		b.ShowRegister = &v
	}
	if b.ShowForgotPassword == nil {
		v := true
		b.ShowForgotPassword = &v
	}
	c.Security.LoginIdentifier = strings.ToLower(strings.TrimSpace(c.Security.LoginIdentifier))
	if c.Security.LoginIdentifier == "" {
		c.Security.LoginIdentifier = "username"
	}
	c.Notify.Type = strings.ToLower(strings.TrimSpace(c.Notify.Type))
	if c.Notify.Type == "" {
		c.Notify.Type = "memory"
	}
	if strings.TrimSpace(c.Notify.RabbitMQ.Exchange) == "" {
		c.Notify.RabbitMQ.Exchange = "oauth.notify"
	}
	if strings.TrimSpace(c.Notify.RabbitMQ.Queue) == "" {
		c.Notify.RabbitMQ.Queue = "oauth.notify"
	}
	if c.Telemetry.ServiceName == "" {
		c.Telemetry.ServiceName = "atrium"
	}
	if c.Telemetry.SampleRatio == 0 {
		c.Telemetry.SampleRatio = 1
	}
	if c.Push.RegistrationTokenTTL <= 0 {
		c.Push.RegistrationTokenTTL = 300
	}
	if c.Push.MaxDevicesPerUser <= 0 {
		c.Push.MaxDevicesPerUser = 5
	}
	c.Push.MinimumInteractionType = strings.ToLower(strings.TrimSpace(c.Push.MinimumInteractionType))
	if c.Push.MinimumInteractionType == "" {
		c.Push.MinimumInteractionType = "boolean"
	}
	if c.Push.GracePeriodSeconds <= 0 {
		c.Push.GracePeriodSeconds = 300
	}

	fallback := strings.TrimRight(strings.TrimSpace(c.Security.Issuer), "/")
	c.AAuth.APIssuer = aauthIssuer(c.AAuth.APIssuer, fallback)
	c.AAuth.PSIssuer = aauthIssuer(c.AAuth.PSIssuer, fallback)
	c.AAuth.ASIssuer = aauthIssuer(c.AAuth.ASIssuer, fallback)
	c.AAuth.ResourceIssuer = aauthIssuer(c.AAuth.ResourceIssuer, fallback)
	c.AAuth.ResourceMode = strings.ToLower(strings.TrimSpace(c.AAuth.ResourceMode))
	if c.AAuth.ResourceMode == "" {
		c.AAuth.ResourceMode = "as"
	}
	c.normalizeXAA()
}

// ValidatePush checks the interaction floor when push devices are on.
func ValidatePush(c *Config) error {
	if c == nil || !c.Push.Enabled {
		return nil
	}
	switch c.Push.MinimumInteractionType {
	case "boolean", "number_choose", "input_manual":
		return nil
	default:
		return fmt.Errorf("push.minimum_interaction_type must be boolean, number_choose, or input_manual")
	}
}

func aauthIssuer(value, fallback string) string {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	if value == "" {
		return fallback
	}
	return value
}

// ValidateAAuth checks the flag's issuers. A disabled block is left alone.
func ValidateAAuth(c *Config) error {
	if c == nil || !c.AAuth.Enabled {
		return nil
	}
	switch c.AAuth.ResourceMode {
	case "ps", "as":
	default:
		return fmt.Errorf("aauth.resource_mode must be ps or as")
	}
	for _, iss := range []string{c.AAuth.APIssuer, c.AAuth.PSIssuer, c.AAuth.ASIssuer, c.AAuth.ResourceIssuer} {
		parsed, err := url.Parse(iss)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("aauth issuer %q is not an absolute url", iss)
		}
	}
	return nil
}

var brandColorPattern = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

var brandAssetTypes = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".svg":  "image/svg+xml",
	".ico":  "image/x-icon",
	".css":  "text/css; charset=utf-8",
}

// BrandAssetType returns the Content-Type for a branding file name, or ""
// when the extension is not served.
func BrandAssetType(name string) string {
	return brandAssetTypes[strings.ToLower(filepath.Ext(name))]
}

// MaxBrandAssetBytes is the largest file served from branding.assets_dir.
const MaxBrandAssetBytes = 1 << 20

// ValidateBranding rejects colors, URLs, file names, and directories that
// would break the auth pages or escape the asset directory.
func ValidateBranding(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	b := cfg.Branding
	if err := checkBrandColor(b.PrimaryColor, "primary_color", true); err != nil {
		return err
	}
	if err := checkBrandColor(b.BackgroundColor, "background_color", false); err != nil {
		return err
	}
	if err := checkBrandColor(b.TextColor, "text_color", false); err != nil {
		return err
	}
	if err := checkBrandURL(b.SupportURL, "support_url"); err != nil {
		return err
	}
	if err := checkBrandURL(b.PrivacyURL, "privacy_url"); err != nil {
		return err
	}
	if err := checkBrandURL(b.TermsURL, "terms_url"); err != nil {
		return err
	}
	if err := checkBrandDir(b.AssetsDir, "assets_dir"); err != nil {
		return err
	}
	if err := checkBrandDir(b.Templates, "templates"); err != nil {
		return err
	}
	if err := checkBrandAssetRef(b.AssetsDir, b.LogoFile, "logo_file"); err != nil {
		return err
	}
	if err := checkBrandAssetRef(b.AssetsDir, b.FaviconFile, "favicon_file"); err != nil {
		return err
	}
	if err := checkBrandAssetRef(b.AssetsDir, b.BackgroundFile, "background_file"); err != nil {
		return err
	}
	if err := checkBrandBackgroundExt(b.BackgroundFile); err != nil {
		return err
	}
	return nil
}

func checkBrandBackgroundExt(name string) error {
	if name == "" {
		return nil
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg":
		return nil
	default:
		return fmt.Errorf("branding.background_file must be a png, jpg, jpeg, gif, webp, or svg file")
	}
}

func checkBrandColor(value, field string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("branding.%s is required", field)
		}
		return nil
	}
	if !brandColorPattern.MatchString(value) {
		return fmt.Errorf("branding.%s must be #rgb or #rrggbb", field)
	}
	return nil
}

func checkBrandURL(raw, field string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("branding.%s must be an absolute http or https URL", field)
	}
	return nil
}

func checkBrandDir(path, field string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("branding.%s: %w", field, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("branding.%s is not a directory", field)
	}
	return nil
}

func checkBrandAssetRef(dir, name, field string) error {
	if name == "" {
		return nil
	}
	if name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("branding.%s must be a file name", field)
	}
	if BrandAssetType(name) == "" {
		return fmt.Errorf("branding.%s must be a png, jpg, jpeg, gif, webp, svg, ico, or css file", field)
	}
	if dir == "" {
		return fmt.Errorf("branding.assets_dir is required when %s is set", field)
	}
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return fmt.Errorf("branding.%s: %w", field, err)
	}
	if info.IsDir() {
		return fmt.Errorf("branding.%s is a directory", field)
	}
	if info.Size() > MaxBrandAssetBytes {
		return fmt.Errorf("branding.%s is larger than 1MiB", field)
	}
	return nil
}

var socialIDPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

var socialTypes = map[string]bool{
	"google": true, "github": true, "facebook": true, "oidc": true, "oauth2": true,
}

// ValidateSocial checks provider ids, types, and the endpoints an enabled app needs.
func ValidateSocial(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	seen := map[string]bool{}
	for _, p := range cfg.Social.Providers {
		if !socialIDPattern.MatchString(p.ID) {
			return fmt.Errorf("social provider id %q must match [a-z0-9_-]+", p.ID)
		}
		if seen[p.ID] {
			return fmt.Errorf("social provider id %q is duplicated", p.ID)
		}
		seen[p.ID] = true
		if !socialTypes[p.Type] {
			return fmt.Errorf("social provider %q has unknown type %q", p.ID, p.Type)
		}
		if !p.Enabled {
			continue
		}
		if p.ClientID == "" || p.ClientSecret == "" {
			return fmt.Errorf("social provider %q is enabled but client_id and client_secret are required", p.ID)
		}
		switch p.Type {
		case "oidc":
			if !absoluteHTTP(p.Issuer) {
				return fmt.Errorf("social provider %q requires an absolute http or https issuer", p.ID)
			}
		case "oauth2":
			if !absoluteHTTP(p.AuthorizationEndpoint) || !absoluteHTTP(p.TokenEndpoint) || !absoluteHTTP(p.UserinfoEndpoint) {
				return fmt.Errorf("social provider %q requires absolute authorization, token, and userinfo endpoints", p.ID)
			}
		}
		for _, raw := range []string{p.AuthorizationEndpoint, p.TokenEndpoint, p.UserinfoEndpoint} {
			if raw != "" && !absoluteHTTP(raw) {
				return fmt.Errorf("social provider %q has an endpoint that is not an absolute http or https URL", p.ID)
			}
		}
	}
	return nil
}

var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true,
	"nonce": true, "sid": true, "auth_time": true, "org_id": true, "org_slug": true, "org_role": true,
}

var claimSources = map[string]bool{
	"sub": true, "username": true, "email": true, "email_verified": true,
	"phone": true, "given_name": true, "family_name": true,
}

// ValidatePlatform checks password bounds, bot protection, and claim mappings.
func ValidatePlatform(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	p := cfg.Security.Password
	if p.MinLength < 0 || p.MaxLength < 0 || (p.MaxLength > 0 && p.MinLength > p.MaxLength) {
		return fmt.Errorf("security.password length bounds are invalid")
	}
	switch cfg.Security.AccessTokenFormat {
	case "", "opaque", "jwt":
	default:
		return fmt.Errorf("security.access_token_format must be opaque or jwt")
	}
	switch cfg.Security.LoginIdentifier {
	case "", "username", "email":
	default:
		return fmt.Errorf("security.login_identifier must be username or email")
	}
	bot := cfg.Security.BotProtection.Provider
	switch bot {
	case "", "recaptcha", "turnstile":
	default:
		return fmt.Errorf("security.bot_protection.provider must be recaptcha or turnstile")
	}
	if bot != "" && (cfg.Security.BotProtection.SiteKey == "" || cfg.Security.BotProtection.SecretKey == "") {
		return fmt.Errorf("security.bot_protection requires site_key and secret_key")
	}
	switch cfg.Database.Driver {
	case "", "sqlite", "postgres":
	default:
		return fmt.Errorf("database.driver must be sqlite or postgres")
	}
	if cfg.Database.Driver == "postgres" && strings.TrimSpace(cfg.Database.DSN) == "" {
		return fmt.Errorf("database.dsn is required for postgres")
	}
	if (cfg.Database.Driver == "" || cfg.Database.Driver == "sqlite") && strings.TrimSpace(cfg.Database.Path) == "" {
		return fmt.Errorf("database.path is required for sqlite")
	}
	switch cfg.Cache.Provider {
	case "", "memory", "redis":
	default:
		return fmt.Errorf("cache.provider must be memory or redis")
	}
	switch cfg.Queue.Type {
	case "", "memory", "redis":
	default:
		return fmt.Errorf("queue.type must be memory or redis")
	}
	if (cfg.Cache.Provider == "redis" || cfg.Queue.Type == "redis" || cfg.Notify.Type == "redis") && strings.TrimSpace(cfg.Redis.Addr) == "" {
		return fmt.Errorf("redis.addr is required when cache.provider, queue.type, or notify.type is redis")
	}
	switch cfg.Notify.Type {
	case "", "memory", "redis", "rabbitmq":
	default:
		return fmt.Errorf("notify.type must be memory, redis, or rabbitmq")
	}
	if cfg.Notify.Type == "rabbitmq" && strings.TrimSpace(cfg.Notify.RabbitMQ.URL) == "" {
		return fmt.Errorf("notify.rabbitmq.url is required when notify.type is rabbitmq")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Log.Format)) {
	case "", "text", "json":
	default:
		return fmt.Errorf("log.format must be text or json")
	}
	if cfg.Telemetry.Enabled {
		if strings.TrimSpace(cfg.Telemetry.OTLPEndpoint) == "" {
			return fmt.Errorf("telemetry.otlp_endpoint is required when telemetry.enabled is true")
		}
		if cfg.Telemetry.SampleRatio <= 0 || cfg.Telemetry.SampleRatio > 1 {
			return fmt.Errorf("telemetry.sample_ratio must be greater than 0 and at most 1")
		}
	}
	if cfg.Org.EnabledDomainBasedAutolookup && !cfg.Org.Enabled {
		return fmt.Errorf("org.enabled_domain_based_autolookup requires org.enabled")
	}
	for _, m := range cfg.OIDC.ClaimMappings {
		if m.Claim == "" || reservedClaims[m.Claim] {
			return fmt.Errorf("oidc claim %q is reserved or empty", m.Claim)
		}
		src := m.Source
		switch {
		case claimSources[src]:
		case strings.HasPrefix(src, "const:"):
		case strings.HasPrefix(src, "attr.") && len(src) > len("attr."):
		default:
			return fmt.Errorf("oidc claim %q has unknown source %q", m.Claim, src)
		}
	}
	return nil
}

func absoluteHTTP(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
