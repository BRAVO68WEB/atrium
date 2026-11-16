package dashboard

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// IssueClientCredentials calls the token handler in-process and returns the
// access token. The status and detail are the token endpoint's error.
func IssueClientCredentials(token http.HandlerFunc, id, secret string) (string, int, string) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "management")
	req, err := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", http.StatusInternalServerError, "Failed to build token request"
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	req.RemoteAddr = "127.0.0.1:0"
	rec := newRecorder()
	token(rec, req)
	if rec.code != http.StatusOK {
		var body struct {
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(rec.buf.Bytes(), &body)
		if body.Description == "" {
			body.Description = "Invalid client credentials"
		}
		status := rec.code
		if status == 0 {
			status = http.StatusUnauthorized
		}
		return "", status, body.Description
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.buf.Bytes(), &out); err != nil || out.AccessToken == "" {
		return "", http.StatusBadGateway, "Token response was empty"
	}
	return out.AccessToken, http.StatusOK, ""
}
