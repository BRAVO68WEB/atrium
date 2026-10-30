package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

type recorder struct {
	header http.Header
	buf    bytes.Buffer
	code   int
}

func newRecorder() *recorder {
	return &recorder{header: make(http.Header)}
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.code == 0 {
		r.code = status
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.buf.Write(p)
}

func (r *recorder) flush(w http.ResponseWriter, path, method string) {
	body := redact(path, method, r.buf.Bytes())
	dst := w.Header()
	for key, values := range r.header {
		if hop(key) {
			continue
		}
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	if r.code == 0 {
		r.code = http.StatusOK
	}
	w.WriteHeader(r.code)
	_, _ = w.Write(body)
}

func hop(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func redact(path, method string, body []byte) []byte {
	if !secretPath(path) || keepCreateSecret(path, method) || len(bytes.TrimSpace(body)) == 0 {
		return body
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	stripSecret(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

func secretPath(path string) bool {
	switch {
	case path == "/api/clients" || strings.HasPrefix(path, "/api/clients/"):
		return true
	case path == "/api/webhooks" || strings.HasPrefix(path, "/api/webhooks/"):
		return true
	default:
		return false
	}
}

func keepCreateSecret(path, method string) bool {
	if method == http.MethodPost && (path == "/api/clients" || path == "/api/webhooks") {
		return true
	}
	// The application page copies the saved secret and shows a new one after reset.
	// The client list still has the secret removed.
	if method == http.MethodGet && strings.HasPrefix(path, "/api/clients/") && !strings.Contains(strings.TrimPrefix(path, "/api/clients/"), "/") {
		return true
	}
	return method == http.MethodPost && strings.HasPrefix(path, "/api/clients/") && strings.HasSuffix(path, "/secret")
}

func stripSecret(doc any) {
	switch item := doc.(type) {
	case map[string]any:
		delete(item, "secret")
	case []any:
		for _, child := range item {
			stripSecret(child)
		}
	}
}
