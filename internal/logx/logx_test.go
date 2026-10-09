package logx

import "testing"

func TestScrub(t *testing.T) {
	AddRedaction("SuperSecretValue123")
	cases := map[string]string{
		"client_secret=abc123&x=1":                     "client_secret=***&x=1",
		`{"refresh_token":"eyJabc"}`:                   `{"refresh_token":"***"}`,
		"id_token: oidc: malformed jwt":                "id_token: oidc: malformed jwt",
		"pw SuperSecretValue123 leaked":                "pw *** leaked",
		"bearer eyJhbGciOiJ.eyJzdWIiOiIx.c2lnbmF0dXJl": "bearer ***",
	}
	for in, want := range cases {
		if got := Scrub(in); got != want {
			t.Errorf("Scrub(%q) = %q, want %q", in, got, want)
		}
	}
}
