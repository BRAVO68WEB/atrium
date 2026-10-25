package main

import (
	"io"
	"net/http"
	"net/url"

	"github.com/bravo68web/atrium/internal/mgmtclient"
)

var (
	mgmtClientID     string
	mgmtClientSecret string
	configPath       string
	mgmt             = &mgmtclient.Client{}
)

func syncMgmt() {
	mgmt.ServerURL = serverURL
	mgmt.ClientID = mgmtClientID
	mgmt.ClientSecret = mgmtClientSecret
	mgmt.ConfigPath = configPath
}

func withManagement(req *http.Request) (*http.Response, error) {
	syncMgmt()
	token, err := mgmt.Token()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

func apiGet(rawURL string) (*http.Response, error) {
	syncMgmt()
	return mgmt.Get(rawURL)
}

func apiPut(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	syncMgmt()
	return mgmt.Put(rawURL, contentType, body)
}

func apiPost(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	syncMgmt()
	return mgmt.Post(rawURL, contentType, body)
}

func apiPostForm(rawURL string, data url.Values) (*http.Response, error) {
	syncMgmt()
	return mgmt.PostForm(rawURL, data)
}
