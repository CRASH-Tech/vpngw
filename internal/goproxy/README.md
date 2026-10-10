# goproxy

The goproxy node: keys, Noise handshake, transports, tunnel interfaces and
routing between sites. vpngw drives it through its Go API from
`internal/tunnels` and has its own admin panel, so goproxy's web UI and main
package are not here. This is the only copy of the code; change it here.
