package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/oobcode"
)

func TestFlowPasteExchangesPastedCode(t *testing.T) {
	var got url.Values
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		calls++
		_ = r.ParseForm()
		got = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-1",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "openid",
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	rawErr := runPaste(t, []string{"--client-id", "cli-app"}, func(authorizeURL string) string {
		if !strings.Contains(authorizeURL, "response_type=code") || !strings.Contains(authorizeURL, "code_challenge_method=S256") {
			t.Fatalf("authorize URL %s", authorizeURL)
		}
		if !strings.Contains(authorizeURL, "redirect_uri="+url.QueryEscape("urn:ietf:wg:oauth:2.0:oob")) {
			t.Fatalf("redirect %s", authorizeURL)
		}
		return "pasted-code"
	})
	if rawErr != nil {
		t.Fatal(rawErr)
	}
	if got.Get("code") != "pasted-code" || got.Get("redirect_uri") != "urn:ietf:wg:oauth:2.0:oob" || got.Get("client_id") != "cli-app" || got.Get("code_verifier") == "" {
		t.Fatalf("raw token form %v", got)
	}

	helperErr := runPaste(t, []string{"--client-id", "cli-app", "--redirect-uri", srv.URL + "/oauth/oob"}, func(authorizeURL string) string {
		parsed, err := url.Parse(authorizeURL)
		if err != nil {
			t.Fatal(err)
		}
		return srv.URL + "/oauth/oob?code=helper-code&state=" + parsed.Query().Get("state")
	})
	if helperErr != nil {
		t.Fatal(helperErr)
	}
	if got.Get("code") != "helper-code" || got.Get("redirect_uri") != srv.URL+"/oauth/oob" {
		t.Fatalf("helper token form %v", got)
	}

	combinedErr := runPaste(t, []string{"--client-id", "cli-app", "--combined"}, func(authorizeURL string) string {
		parsed, err := url.Parse(authorizeURL)
		if err != nil {
			t.Fatal(err)
		}
		combined, err := oobcode.Combine("secret-code", parsed.Query().Get("state"))
		if err != nil {
			t.Fatal(err)
		}
		return combined
	})
	if combinedErr != nil {
		t.Fatal(combinedErr)
	}
	if got.Get("code") != "secret-code" {
		t.Fatalf("combined token form %v", got)
	}

	callsBefore := calls
	mismatch := runPaste(t, []string{"--client-id", "cli-app", "--redirect-uri", srv.URL + "/oauth/oob"}, func(authorizeURL string) string {
		return srv.URL + "/oauth/oob?code=helper-code&state=nope"
	})
	if mismatch == nil || !strings.Contains(mismatch.Error(), "state mismatch") {
		t.Fatalf("mismatch err %v", mismatch)
	}
	if calls != callsBefore {
		t.Fatalf("token endpoint calls %d, want %d", calls, callsBefore)
	}
}

func TestFlowPasteRequiresClientID(t *testing.T) {
	cmd := flowCmd()
	cmd.SetArgs([]string{"paste"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "client-id") {
		t.Fatalf("err %v", err)
	}
}

func runPaste(t *testing.T, args []string, paste func(authorizeURL string) string) error {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin = inR
	os.Stdout = outW
	defer func() {
		os.Stdin = oldIn
		os.Stdout = oldOut
		_ = inR.Close()
		_ = inW.Close()
		_ = outR.Close()
		_ = outW.Close()
	}()

	errCh := make(chan error, 1)
	go func() {
		cmd := flowCmd()
		cmd.SetArgs(append([]string{"paste"}, args...))
		errCh <- cmd.Execute()
	}()

	urlCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(outR)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "/oauth/authorize?") {
				urlCh <- line
				return
			}
		}
		urlCh <- ""
	}()

	var authorizeURL string
	select {
	case authorizeURL = <-urlCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the authorize URL")
	}
	if authorizeURL == "" {
		t.Fatal("authorize URL was not printed")
	}
	if _, err := io.WriteString(inW, paste(authorizeURL)+"\n"); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	select {
	case err := <-errCh:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("paste command did not finish")
	}
	return nil
}
