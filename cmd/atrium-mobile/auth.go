package main

import (
	"io"
	"net/http"

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

func apiGet(rawURL string) (*http.Response, error) {
	syncMgmt()
	return mgmt.Get(rawURL)
}

func apiPost(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	syncMgmt()
	return mgmt.Post(rawURL, contentType, body)
}
