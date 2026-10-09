package clients

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalog(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "ac"), 0o755)
	os.WriteFile(filepath.Join(dir, "ac", "win.msi"), []byte("12345"), 0o644)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, InfoFile), []byte(`
openvpn:
  - description: Windows
    os: Windows
    link: https://example.com/ovpn
anyconnect:
  - description: Windows client
    os: windows
    file: ac/win.msi   
  - description: iOS client
    os: iOS
    link: https://apps.apple.com/app/x/id1
  - description: gone
    os: macos
    file: ac/missing.dmg
  - description: escape
    os: linux
    file: ../etc/passwd
  - description: no os
    link: https://example.com/x
`), 0o644)
	c := &Catalog{Dir: func() string { return dir }}
	groups, err := c.Groups()
	if err == nil || !strings.Contains(err.Error(), "missing.dmg") || !strings.Contains(err.Error(), "../etc/passwd") || !strings.Contains(err.Error(), "no os") {
		t.Fatalf("problems must be reported: %v", err)
	}
	if len(groups) != 2 || groups[0].Protocol != "anyconnect" || groups[1].Protocol != "openvpn" {
		t.Fatalf("groups: %+v", groups)
	}
	ac := groups[0].Items
	if len(ac) != 2 || ac[0].File != "ac/win.msi" || ac[0].Size != 5 || ac[0].Name() != "win.msi" || ac[1].Store() != "App Store" {
		t.Fatalf("items: %+v", ac)
	}
	if w := For(groups, "anyconnect", "windows"); len(w) != 1 || w[0].File != "ac/win.msi" {
		t.Fatalf("anyconnect windows: %+v", w)
	}
	if i := For(groups, "openvpn", "ios"); len(i) != 0 {
		t.Fatalf("openvpn ios: %+v", i)
	}
	if w := For(groups, "openvpn", "windows"); len(w) != 1 {
		t.Fatalf("os must be case-insensitive: %+v", w)
	}
	if f, _, err := c.Open("ac/win.msi"); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	for _, name := range []string{"secret.txt", InfoFile, "../etc/passwd", "ac/missing.dmg"} {
		if _, _, err := c.Open(name); err == nil {
			t.Fatalf("%s must not be served", name)
		}
	}
}

func TestCatalogMissing(t *testing.T) {
	c := &Catalog{Dir: func() string { return filepath.Join(t.TempDir(), "none") }}
	if g, err := c.Groups(); err != nil || len(g) != 0 {
		t.Fatal(g, err)
	}
}
