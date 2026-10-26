package models

import (
	"time"
)

type Client struct {
	ID                                         string    `json:"id"`
	Secret                                     string    `json:"secret,omitempty"`
	Name                                       string    `json:"name"`
	RedirectURIs                               []string  `json:"redirect_uris"`
	GrantTypes                                 []string  `json:"grant_types"`
	Scopes                                     []string  `json:"scopes"`
	TokenEndpointAuthMethod                    string    `json:"token_endpoint_auth_method"`
	DPoPBoundAccessTokens                      bool      `json:"dpop_bound_access_tokens"`
	RequirePushedAuthorizationRequests         bool      `json:"require_pushed_authorization_requests"`
	BackchannelTokenDeliveryMode               string    `json:"backchannel_token_delivery_mode,omitempty"`
	BackchannelClientNotificationEndpoint      string    `json:"backchannel_client_notification_endpoint,omitempty"`
	BackchannelAuthenticationRequestSigningAlg string    `json:"backchannel_authentication_request_signing_alg,omitempty"`
	BackchannelLogoutURI                       string    `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired           bool      `json:"backchannel_logout_session_required"`
	PostLogoutRedirectURIs                     []string  `json:"post_logout_redirect_uris,omitempty"`
	JWKS                                       string    `json:"jwks,omitempty"`
	JWKSUri                                    string    `json:"jwks_uri,omitempty"`
	RequestObjectSigningAlg                    string    `json:"request_object_signing_alg,omitempty"`
	RegistrationSource                         string    `json:"registration_source,omitempty"`
	DCREnabled                                 bool      `json:"dcr_enabled"`
	CIMDEnabled                                bool      `json:"cimd_enabled"`
	SubjectType                                string    `json:"subject_type,omitempty"`
	SectorIdentifierURI                        string    `json:"sector_identifier_uri,omitempty"`
	IDTokenEncryptedResponseAlg                string    `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc                string    `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoEncryptedResponseAlg               string    `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc               string    `json:"userinfo_encrypted_response_enc,omitempty"`
	OrgID                                      string    `json:"org_id,omitempty"`
	CreatedAt                                  time.Time `json:"created_at"`
	UpdatedAt                                  time.Time `json:"updated_at"`
}

type User struct {
	ID            string            `json:"id"`
	Username      string            `json:"username"`
	PasswordHash  string            `json:"-"`
	Email         string            `json:"email,omitempty"`
	PhoneNumber   string            `json:"phone_number,omitempty"`
	GivenName     string            `json:"given_name,omitempty"`
	FamilyName    string            `json:"family_name,omitempty"`
	EmailVerified bool              `json:"email_verified"`
	Disabled      bool              `json:"disabled"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	UserMetadata  map[string]string `json:"user_metadata,omitempty"`
	LastLoginAt   *time.Time        `json:"last_login_at,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	Resource            string    `json:"resource,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	FamilyID            string    `json:"-"`
	SessionID           string    `json:"-"`
	AuthTime            time.Time `json:"-"`
	OrgID               string    `json:"org_id,omitempty"`
	RequestedActor      string    `json:"requested_actor,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}

type Organization struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	LogoURL   string    `json:"logo_url,omitempty"`
	Domains   []string  `json:"domains,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type OrgMembership struct {
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type AccessToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id,omitempty"`
	Scopes    []string  `json:"scopes"`
	Resource  string    `json:"resource,omitempty"`
	TokenType string    `json:"token_type"`
	DPoPJKT   string    `json:"dpop_jkt,omitempty"`
	IssuedAt  time.Time `json:"iat,omitempty"`
	JTI       string    `json:"jti,omitempty"`
	OrgID     string    `json:"org_id,omitempty"`
	Act       string    `json:"act,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

type RefreshToken struct {
	ID          string    `json:"id,omitempty"`
	Token       string    `json:"token,omitempty"`
	AccessToken string    `json:"access_token,omitempty"`
	ClientID    string    `json:"client_id"`
	UserID      string    `json:"user_id,omitempty"`
	Scopes      []string  `json:"scopes"`
	Resource    string    `json:"resource,omitempty"`
	FamilyID    string    `json:"family_id,omitempty"`
	IssuedAt    time.Time `json:"iat,omitempty"`
	JTI         string    `json:"jti,omitempty"`
	OrgID       string    `json:"org_id,omitempty"`
	Act         string    `json:"act,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revoked     bool      `json:"revoked"`
}

type DeviceCode struct {
	DeviceCode string    `json:"device_code"`
	UserCode   string    `json:"user_code"`
	ClientID   string    `json:"client_id"`
	UserID     string    `json:"user_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	AuthTime   time.Time `json:"-"`
	Scopes     []string  `json:"scopes"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expires_at"`
	Interval   int       `json:"interval"`
}

type BrowserSession struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	AuthTime    time.Time `json:"auth_time"`
	MFAVerified bool      `json:"mfa_verified"`
	UserAgent   string    `json:"user_agent,omitempty"`
	IP          string    `json:"ip,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revoked     bool      `json:"revoked"`
}

type LoginEvent struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Success   bool      `json:"success"`
	MFA       bool      `json:"mfa"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type PushedAuthRequest struct {
	RequestURI    string    `json:"request_uri"`
	ClientID      string    `json:"client_id"`
	RequestParams string    `json:"request_params"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type CIBARequest struct {
	AuthReqID               string    `json:"auth_req_id"`
	ClientID                string    `json:"client_id"`
	UserID                  string    `json:"user_id,omitempty"`
	BindingMessage          string    `json:"binding_message,omitempty"`
	UserCode                string    `json:"user_code,omitempty"`
	Scopes                  []string  `json:"scopes,omitempty"`
	Status                  string    `json:"status"`
	DeliveryMode            string    `json:"delivery_mode"`
	ExpiresAt               time.Time `json:"expires_at"`
	Interval                int       `json:"interval"`
	ClientNotificationToken string    `json:"client_notification_token,omitempty"`
}

type DPoPProof struct {
	JTI       string    `json:"jti"`
	HTM       string    `json:"htm"`
	HTU       string    `json:"htu"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OIDCNonce struct {
	Nonce     string    `json:"nonce"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TokenIntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	JTI       string   `json:"jti,omitempty"`
}

type Consent struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	ClientID  string     `json:"client_id"`
	Scopes    []string   `json:"scopes"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type Scope struct {
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	ResourceServer string    `json:"resource_server,omitempty"`
	IsDefault      bool      `json:"is_default"`
	CreatedAt      time.Time `json:"created_at"`
}

type Resource struct {
	URI         string    `json:"uri"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Scopes      []string  `json:"scopes,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}
