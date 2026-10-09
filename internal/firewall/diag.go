package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// SessionDiag is the kernel's view of one VPN session, read live from
// nftables (not from the manager's memory).
type SessionDiag struct {
	InFirewall bool   // the address is in the sess map
	Chain      string // profile chain its traffic jumps to
	Mark       string // routing mark from sessmark
	Accepted   string // packets/bytes the profile chain accepted (all its sessions)
	Error      string
}

var (
	reVerdict = regexp.MustCompile(`:\s*jump\s+(\S+)`)
	reMark    = regexp.MustCompile(`:\s*(0x[0-9a-f]+)`)
	reCounter = regexp.MustCompile(`counter packets (\d+) bytes (\d+) accept`)
)

// DiagnoseSession reads the session's firewall state.
func (m *Manager) DiagnoseSession(ip netip.Addr) SessionDiag {
	var d SessionDiag
	ctx := context.Background()
	out, err := m.run(ctx, "nft", "", "get", "element", "inet", table, "sess", "{", ip.String(), "}")
	if err != nil {
		d.Error = "not in the firewall: all its traffic is dropped"
		return d
	}
	if mm := reVerdict.FindStringSubmatch(out); mm != nil {
		d.InFirewall, d.Chain = true, mm[1]
	}
	if out, err := m.run(ctx, "nft", "", "get", "element", "inet", table, "sessmark", "{", ip.String(), "}"); err == nil {
		if mm := reMark.FindStringSubmatch(out); mm != nil {
			d.Mark = mm[1]
		}
	}
	if d.Chain != "" {
		if out, err := m.run(ctx, "nft", "", "list", "chain", "inet", table, d.Chain); err == nil {
			if mm := reCounter.FindStringSubmatch(out); mm != nil {
				d.Accepted = mm[1] + " packets, " + mm[2] + " bytes"
			}
		}
	}
	return d
}

// RouteDiag is where the kernel sends a packet with a session's mark.
type RouteDiag struct {
	Dev, Via, Table string
	Local           bool // one of this site's own networks (host routes)
	Error           string
}

// DiagnoseRoute asks the kernel how it routes dst for traffic with mark
// (policy rules included).
func (m *Manager) DiagnoseRoute(dst netip.Addr, mark string) RouteDiag {
	// Mirror the steer chain: this site's own networks drop the gateway.
	local := false
	for _, p := range m.localNets() {
		if p.Contains(dst) {
			local = true
		}
	}
	if local && strings.HasPrefix(mark, fmt.Sprintf("0x%x", markBase>>16)) {
		mark = fmt.Sprintf("0x%x", markBase)
	}
	args := []string{"-j", "route", "get", dst.String()}
	if mark != "" {
		args = append(args, "mark", mark)
	}
	out, err := m.run(context.Background(), "ip", "", args...)
	if err != nil {
		// "ip ...: exit status 2: RTNETLINK answers: Network is unreachable"
		msg := err.Error()
		if i := strings.LastIndex(msg, ": "); i >= 0 {
			msg = msg[i+2:]
		}
		return RouteDiag{Error: msg}
	}
	var r []struct {
		Type    string `json:"type"`
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
		Table   any    `json:"table"`
	}
	if json.Unmarshal([]byte(out), &r) != nil || len(r) == 0 {
		return RouteDiag{Error: "unexpected output: " + strings.TrimSpace(out)}
	}
	d := RouteDiag{Dev: r[0].Dev, Via: r[0].Gateway, Local: local}
	if r[0].Table != nil {
		d.Table = fmt.Sprint(r[0].Table)
	}
	if r[0].Type == "unreachable" || r[0].Type == "blackhole" || r[0].Type == "prohibit" {
		d.Error = r[0].Type
	}
	return d
}
