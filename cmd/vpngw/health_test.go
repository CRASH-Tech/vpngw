package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vpngw/internal/config"
	"vpngw/internal/core"
)

func TestMetricsAuth(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	cases := []struct {
		env    map[string]string
		remote string
		token  string
		want   int
	}{
		{nil, "127.0.0.1:5000", "", 200},
		{nil, "10.0.0.5:5000", "", 403},
		{map[string]string{"METRICS_TOKEN": "t"}, "10.0.0.5:5000", "t", 200},
		{map[string]string{"METRICS_ALLOWED_NETWORKS": "10.0.0.0/24"}, "10.0.0.5:5000", "", 200},
		{map[string]string{"METRICS_ALLOWED_NETWORKS": "10.0.0.0/24"}, "10.0.1.5:5000", "", 403},
		{map[string]string{"METRICS_ALLOWED_NETWORKS": "10.0.0.0/24", "METRICS_TOKEN": "t"}, "10.0.0.5:5000", "", 403},
		{map[string]string{"METRICS_ALLOWED_NETWORKS": "10.0.0.0/24", "METRICS_TOKEN": "t"}, "10.0.0.5:5000", "t", 200},
		{map[string]string{"METRICS_ALLOWED_NETWORKS": "10.0.0.0/24", "METRICS_TOKEN": "t"}, "10.9.0.5:5000", "t", 403},
	}
	for i, c := range cases {
		h := metricsAuth(config.NewFromMap(c.env), ok)
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.RemoteAddr = c.remote
		if c.token != "" {
			r.Header.Set("Authorization", "Bearer "+c.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("case %d (%v from %s): %d, want %d", i, c.env, c.remote, w.Code, c.want)
		}
	}
}

func TestUserMetricsFormat(t *testing.T) {
	var b strings.Builder
	writeUserMetrics(&b, []core.UserStat{{Username: `a"b`, Protocol: "openvpn", Connections: 2, BytesIn: 5, BytesOut: 7}}, nil)
	out := b.String()
	for _, want := range []string{
		`vpngw_user_connections_total{user="a\"b",protocol="openvpn"} 2`,
		`vpngw_user_traffic_bytes_total{user="a\"b",protocol="openvpn",direction="received"} 5`,
		`vpngw_user_traffic_bytes_total{user="a\"b",protocol="openvpn",direction="sent"} 7`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
