package portal

import (
	"log/slog"
	"mime"
	"net/http"
	"path"

	"vpngw/internal/clients"
)

// clientGroups returns the downloadable clients of the enabled protocols
// (and of protocols the gateway does not know, e.g. "other").
func (s *Server) clientGroups(enabled map[string]bool) []clients.Group {
	groups, err := s.Clients.Groups()
	if err != nil {
		slog.Warn("clients catalog", "dir", s.Cfg.Str("CLIENTS_DIR"), "err", err)
	}
	out := groups[:0:0]
	for _, g := range groups {
		if on, known := enabled[g.Protocol]; known && !on {
			continue
		}
		out = append(out, g)
	}
	return out
}

// handleClient sends a client installer listed in info.txt.
func (s *Server) handleClient(w http.ResponseWriter, r *http.Request) {
	f, it, err := s.Clients.Open(r.PathValue("file"))
	if err != nil {
		s.Error(w, r, http.StatusNotFound, "No such client.")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		s.Error(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if t := mime.TypeByExtension(path.Ext(it.File)); t != "" {
		w.Header().Set("Content-Type", t)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": it.Name()}))
	w.Header().Set("Cache-Control", "private, max-age=86400")
	slog.Info("client download", "file", it.File, "user", s.CurrentSession(r).Username)
	http.ServeContent(w, r, "", st.ModTime(), f)
}
