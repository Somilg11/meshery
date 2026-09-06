package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meshery/meshery/server/models"
)

// stubProvider implements only the part of models.Provider these tests
// exercise. The embedded interface is nil, so any other method call panics -
// which is the intent: it pins exactly which methods the /auth/redirect guard
// is allowed to depend on.
type stubProvider struct {
	models.Provider

	// accept is the single token value this provider considers a valid session.
	accept string
	// seen records the token the provider was actually asked about.
	seen string
}

func (s *stubProvider) GetSession(req *http.Request) error {
	ck, err := req.Cookie(models.TokenCookieName)
	if err != nil {
		return errors.New("no session token on request")
	}
	s.seen = ck.Value
	if ck.Value != s.accept {
		return errors.New("token rejected")
	}
	return nil
}

func TestProviderAcceptsToken(t *testing.T) {
	const good = "provider-issued-token"

	t.Run("rejects a token the provider does not accept", func(t *testing.T) {
		p := &stubProvider{accept: good}
		req := httptest.NewRequest(http.MethodGet, "/auth/redirect?token=unverified-token", nil)

		if providerAcceptsToken(p, req, "unverified-token") {
			t.Fatal("accepted a token the provider rejected; /auth/redirect would install an unverified session cookie")
		}
	})

	t.Run("accepts a token the provider verifies", func(t *testing.T) {
		p := &stubProvider{accept: good}
		req := httptest.NewRequest(http.MethodGet, "/auth/redirect?token="+good, nil)

		if !providerAcceptsToken(p, req, good) {
			t.Fatal("rejected a token the provider verified; the post-authentication bounce would not log the user in")
		}
	})

	// The regression that matters. GetSession reads the token off the request
	// rather than taking it as an argument, so a request that already carries a
	// valid cookie would validate that cookie and report success for a candidate
	// the provider never inspected - which would leave the guard doing nothing
	// on exactly the requests it exists to check.
	t.Run("an inbound valid cookie does not vouch for the candidate", func(t *testing.T) {
		p := &stubProvider{accept: good}
		req := httptest.NewRequest(http.MethodGet, "/auth/redirect?token=unverified-token", nil)
		req.AddCookie(&http.Cookie{Name: models.TokenCookieName, Value: good})

		if providerAcceptsToken(p, req, "unverified-token") {
			t.Fatal("the request's own cookie vouched for an unrelated candidate token")
		}
		if p.seen != "unverified-token" {
			t.Fatalf("provider validated %q, want the candidate %q", p.seen, "unverified-token")
		}
	})

	t.Run("leaves the caller's request untouched", func(t *testing.T) {
		p := &stubProvider{accept: good}
		req := httptest.NewRequest(http.MethodGet, "/auth/redirect?token=unverified-token", nil)
		req.AddCookie(&http.Cookie{Name: models.TokenCookieName, Value: good})

		providerAcceptsToken(p, req, "unverified-token")

		ck, err := req.Cookie(models.TokenCookieName)
		if err != nil {
			t.Fatalf("probe stripped the caller's cookie: %v", err)
		}
		if ck.Value != good {
			t.Fatalf("probe rewrote the caller's cookie to %q, want %q", ck.Value, good)
		}
	})
}
