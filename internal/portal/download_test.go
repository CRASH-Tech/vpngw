package portal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"vpngw/internal/testutil"
)

func TestSignedProfileLink(t *testing.T) {
	env := testutil.NewEnv(t, nil)
	s, err := New(Deps{Core: env.Core, Cfg: env.Cfg, Store: env.Store})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := env.Login(t)
	link := s.signedDownloadURL(u, "mobileconfig", u.Username+"@vpn-dc1", "vpn.test")
	session := func(link, kind string) *Session {
		r := httptest.NewRequest(http.MethodGet, link, nil)
		r.SetPathValue("kind", kind)
		return s.linkSession(r)
	}
	if sess := session(link, "mobileconfig"); sess == nil || sess.User.ID != u.ID || sess.Web == nil {
		t.Fatalf("valid link refused: %+v", sess)
	}
	if session(link, "ovpn") != nil {
		t.Fatal("a signed link works only for the profile without secrets")
	}
	if session(strings.Replace(link, "vpn-dc1", "vpn-internet", 1), "mobileconfig") != nil {
		t.Fatal("a link for another login must fail")
	}
	q, _ := url.ParseQuery(link[strings.Index(link, "?")+1:])
	q.Set("exp", "1")
	if session("/download/mobileconfig?"+q.Encode(), "mobileconfig") != nil {
		t.Fatal("a changed expiry must fail")
	}
	q.Set("exp", "1")
	q.Set("sig", s.profileLinkMAC(u, "mobileconfig", q.Get("login"), q.Get("ep"), "1"))
	if session("/download/mobileconfig?"+q.Encode(), "mobileconfig") != nil {
		t.Fatal("an expired link must fail")
	}
	if _, err := env.Core.ReissuePassword(u.ID, "test", ""); err != nil {
		t.Fatal(err)
	}
	if session(link, "mobileconfig") != nil {
		t.Fatal("a reissued password must invalidate the link")
	}
	// Without a session and a valid link: the sign-in page, as before.
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, link, nil))
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login?") {
		t.Fatalf("got %d %s", w.Code, w.Header().Get("Location"))
	}
}
