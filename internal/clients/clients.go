// Package clients lists VPN client installers offered for download in the
// portal. The directory holds the files and info.txt (YAML):
//
//	anyconnect:
//	  - description: Cisco Secure Client
//	    os: windows
//	    file: anyconnect/client.msi
//	  - description: Cisco Secure Client
//	    os: ios
//	    link: https://apps.apple.com/app/...
//
// Top-level keys are protocols (anyconnect, openvpn, ikev2); os is one of
// OSes; file is relative to the directory, link is an external page (an
// app store).
package clients

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// InfoFile is the catalog file name inside the directory.
const InfoFile = "info.txt"

// Item is one client: a file to download or an external link.
type Item struct {
	Description string `yaml:"description"`
	OS          string `yaml:"os"`
	File        string `yaml:"file"`
	Link        string `yaml:"link"`
	Size        uint64 `yaml:"-"`
}

// OSes are the operating systems of the portal's instruction tabs.
var OSes = []string{"windows", "macos", "linux", "ios", "android"}

var osAlias = map[string]string{"win": "windows", "mac": "macos", "osx": "macos", "darwin": "macos", "iphone": "ios", "ipad": "ios", "ipados": "ios"}

func normOS(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if a, ok := osAlias[s]; ok {
		s = a
	}
	for _, o := range OSes {
		if s == o {
			return s, true
		}
	}
	return "", false
}

// Store names the app store of a link ("App Store", "Google Play", ...).
func (i Item) Store() string {
	u, err := url.Parse(i.Link)
	if err != nil {
		return ""
	}
	switch h := strings.ToLower(u.Hostname()); {
	case h == "apps.apple.com" || h == "itunes.apple.com":
		return "App Store"
	case h == "play.google.com":
		return "Google Play"
	case strings.HasSuffix(h, "microsoft.com"):
		return "Microsoft Store"
	}
	return ""
}

// Name is the file name of a downloadable item.
func (i Item) Name() string { return path.Base(i.File) }

// Group is the clients of one protocol.
type Group struct {
	Protocol string
	Items    []Item
}

// Catalog reads the directory, re-reading info.txt when it changes.
type Catalog struct {
	Dir func() string

	mu     sync.Mutex
	dir    string
	mtime  time.Time
	groups []Group
	err    error
}

// order puts known protocols first, in the portal's tab order.
var order = map[string]int{"anyconnect": 0, "openvpn": 1, "ikev2": 2}

// Groups returns the catalog. A missing directory or info.txt is an empty
// catalog, not an error.
func (c *Catalog) Groups() ([]Group, error) {
	dir := c.Dir()
	c.mu.Lock()
	defer c.mu.Unlock()
	if dir == "" {
		return nil, nil
	}
	st, err := os.Stat(filepath.Join(dir, InfoFile))
	if errors.Is(err, fs.ErrNotExist) {
		c.dir, c.groups, c.err = "", nil, nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if dir == c.dir && st.ModTime().Equal(c.mtime) && c.groups != nil {
		return c.groups, c.err
	}
	c.groups, c.err = load(dir)
	c.dir, c.mtime = dir, st.ModTime()
	return c.groups, c.err
}

func load(dir string) ([]Group, error) {
	raw, err := os.ReadFile(filepath.Join(dir, InfoFile))
	if err != nil {
		return nil, err
	}
	var m map[string][]Item
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return []Group{}, fmt.Errorf("%s: %w", InfoFile, err)
	}
	var problems []string
	groups := []Group{}
	for proto, items := range m {
		g := Group{Protocol: strings.ToLower(strings.TrimSpace(proto))}
		for _, it := range items {
			it.Description = strings.TrimSpace(it.Description)
			it.File = strings.TrimSpace(it.File)
			it.Link = strings.TrimSpace(it.Link)
			sys, ok := normOS(it.OS)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s %q: os %q is not one of %s", proto, it.Description, it.OS, strings.Join(OSes, ", ")))
				continue
			}
			it.OS = sys
			switch {
			case it.File != "" && it.Link != "":
				problems = append(problems, fmt.Sprintf("%s %q: both file and link", proto, it.Description))
				continue
			case it.File != "":
				p, ok := clean(it.File)
				if !ok {
					problems = append(problems, fmt.Sprintf("%s %q: bad file path %q", proto, it.Description, it.File))
					continue
				}
				st, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p)))
				if err != nil || !st.Mode().IsRegular() {
					problems = append(problems, fmt.Sprintf("%s %q: file %s not found", proto, it.Description, p))
					continue
				}
				it.File, it.Size = p, uint64(st.Size())
			case it.Link != "":
				u, err := url.Parse(it.Link)
				if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
					problems = append(problems, fmt.Sprintf("%s %q: bad link %q", proto, it.Description, it.Link))
					continue
				}
			default:
				problems = append(problems, fmt.Sprintf("%s %q: neither file nor link", proto, it.Description))
				continue
			}
			if it.Description == "" {
				it.Description = path.Base(it.File + it.Link)
			}
			g.Items = append(g.Items, it)
		}
		if len(g.Items) > 0 {
			groups = append(groups, g)
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		oi, ki := order[groups[i].Protocol]
		oj, kj := order[groups[j].Protocol]
		if ki != kj {
			return ki
		}
		if oi != oj {
			return oi < oj
		}
		return groups[i].Protocol < groups[j].Protocol
	})
	if len(problems) > 0 {
		return groups, fmt.Errorf("%s: %s", InfoFile, strings.Join(problems, "; "))
	}
	return groups, nil
}

// clean accepts a relative slash path that stays inside the directory.
func clean(p string) (string, bool) {
	p = strings.ReplaceAll(p, "\\", "/")
	c := path.Clean(p)
	if c == "." || path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") || c == InfoFile {
		return "", false
	}
	return c, true
}

// For returns the clients of a protocol for an operating system.
func For(groups []Group, protocol, system string) []Item {
	var out []Item
	for _, g := range groups {
		if g.Protocol != protocol {
			continue
		}
		for _, it := range g.Items {
			if it.OS == system {
				out = append(out, it)
			}
		}
	}
	return out
}

// Open opens a file listed in the catalog; anything else is not found.
func (c *Catalog) Open(name string) (*os.File, Item, error) {
	groups, _ := c.Groups()
	for _, g := range groups {
		for _, it := range g.Items {
			if it.File != "" && it.File == name {
				f, err := os.Open(filepath.Join(c.Dir(), filepath.FromSlash(it.File)))
				return f, it, err
			}
		}
	}
	return nil, Item{}, fs.ErrNotExist
}
