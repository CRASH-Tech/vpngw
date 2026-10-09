// Package templates embeds backend config templates and web assets.
package templates

import "embed"

// Config holds text/template sources of backend configuration files.
//
//go:embed config/*.tmpl
var Config embed.FS

// Web holds HTML templates, client profile templates and static assets.
//
//go:embed web
var Web embed.FS
