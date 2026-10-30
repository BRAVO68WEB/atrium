package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookie = "atrium_dashboard"
	csrfCookie    = "atrium_dashboard_csrf"
)

type session struct {
	Token    string
	ClientID string
	CSRF     string
	Expires  time.Time
}

// Store is the in-memory console session. A process restart drops it.
type Store struct {
	mu    sync.Mutex
	items map[string]session
	ttl   time.Duration
}

func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	return &Store{items: map[string]session{}, ttl: ttl}
}

func (s *Store) Put(token, clientID, csrf string) (string, time.Time) {
	id := randomID()
	exp := time.Now().Add(s.ttl)
	s.mu.Lock()
	s.items[id] = session{Token: token, ClientID: clientID, CSRF: csrf, Expires: exp}
	s.mu.Unlock()
	return id, exp
}

func (s *Store) Get(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return session{}, false
	}
	if time.Now().After(item.Expires) {
		delete(s.items, id)
		return session{}, false
	}
	return item, true
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
}

func randomID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func csrfOK(r *http.Request, want string) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" || want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (h *Handler) setCookies(w http.ResponseWriter, id, csrf string, exp time.Time) {
	maxAge := int(time.Until(exp).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/dashboard",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: h.secure, MaxAge: maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: csrf, Path: "/dashboard",
		HttpOnly: false, SameSite: http.SameSiteStrictMode, Secure: h.secure, MaxAge: maxAge,
	})
}

func clearCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/dashboard",
			HttpOnly: name == sessionCookie, SameSite: http.SameSiteStrictMode,
			Secure: secure, MaxAge: -1,
		})
	}
}

func readCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
