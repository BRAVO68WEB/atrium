// Package mgmtclient calls the management API with a client-credentials token.
package mgmtclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client is one management API caller. Token is cached until ClearToken.
type Client struct {
	ServerURL      string
	ClientID       string
	ClientSecret   string
	ConfigPath     string
	ServerExplicit bool
	HTTP           *http.Client
	token          string
}

// ClearToken forgets the cached access token.
func (c *Client) ClearToken() {
	if c != nil {
		c.token = ""
	}
}

// Token returns a management-scoped access token.
func (c *Client) Token() (string, error) {
	if c.token != "" {
		return c.token, nil
	}
	if err := c.ensureCreds(); err != nil {
		return "", err
	}
	body := "grant_type=client_credentials&scope=management"
	req, err := http.NewRequest(http.MethodPost, c.ServerURL+"/oauth/token", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("management token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("management token: %v", result["error_description"])
	}
	token, _ := result["access_token"].(string)
	if token == "" {
		return "", fmt.Errorf("management token: empty access_token")
	}
	c.token = token
	return token, nil
}

func (c *Client) ensureCreds() error {
	return c.Resolve(c.ServerExplicit)
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	token, err := c.Token()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.http().Do(req)
}

// Get sends an authorized GET request.
func (c *Client) Get(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// Put sends an authorized PUT request.
func (c *Client) Put(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, rawURL, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.do(req)
}

// Post sends an authorized POST request.
func (c *Client) Post(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.do(req)
}

// PostForm sends an authorized form POST.
func (c *Client) PostForm(rawURL string, data url.Values) (*http.Response, error) {
	if data == nil {
		data = url.Values{}
	}
	return c.Post(rawURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
