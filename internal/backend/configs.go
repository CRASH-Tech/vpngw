// Package backend contains helpers shared by the VPN server adapters.
package backend

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"text/template"

	"vpngw/internal/store"
	"vpngw/templates"
)

// ConfigFile is a generated configuration file that an administrator may
// override in the admin panel.
type ConfigFile struct {
	Name     string // unique id, e.g. "ocserv.conf"
	Backend  string // protocol
	Path     string // where it is written
	Mode     os.FileMode
	Secret   bool // contains secrets: never shown in full
	Generate func() (string, error)
}

// Configs is the registry of config files.
type Configs struct {
	st    *store.Store
	mu    sync.Mutex
	files map[string]*ConfigFile
}

// NewConfigs creates a registry.
func NewConfigs(st *store.Store) *Configs {
	return &Configs{st: st, files: map[string]*ConfigFile{}}
}

// Register adds a file.
func (c *Configs) Register(f *ConfigFile) {
	c.mu.Lock()
	c.files[f.Name] = f
	c.mu.Unlock()
}

// Files lists registered files sorted by name.
func (c *Configs) Files() []*ConfigFile {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*ConfigFile, 0, len(c.files))
	for _, f := range c.files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a file definition.
func (c *Configs) Get(name string) (*ConfigFile, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.files[name]
	return f, ok
}

// Effective returns the content that is (or will be) written: the admin
// override if present, otherwise the generated content.
func (c *Configs) Effective(name string) (content string, overridden bool, err error) {
	f, ok := c.Get(name)
	if !ok {
		return "", false, fmt.Errorf("unknown config %s", name)
	}
	ov, err := c.st.ConfigOverrides()
	if err != nil {
		return "", false, err
	}
	if o, ok := ov[name]; ok {
		return o.Content, true, nil
	}
	s, err := f.Generate()
	return s, false, err
}

// Write renders a file to disk.
func (c *Configs) Write(name string) error {
	f, ok := c.Get(name)
	if !ok {
		return fmt.Errorf("unknown config %s", name)
	}
	content, _, err := c.Effective(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
		return err
	}
	mode := f.Mode
	if mode == 0 {
		mode = 0o644
	}
	tmp := f.Path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(tmp, f.Path)
}

// WriteBackend renders all files of a backend.
func (c *Configs) WriteBackend(proto string) error {
	for _, f := range c.Files() {
		if f.Backend == proto {
			if err := c.Write(f.Name); err != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
		}
	}
	return nil
}

// Render executes an embedded config template.
func Render(name string, data any) (string, error) {
	t, err := template.ParseFS(templates.Config, "config/"+name)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
