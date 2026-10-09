package portal

import (
	"strings"
	"testing"
)

func TestNamesCarryTheDomain(t *testing.T) {
	host := "vpn.example.com"
	if got := ProfileName(host, "alice@vpn-dc1"); got != "vpn.example.com (vpn-dc1)" {
		t.Errorf("ProfileName = %q", got)
	}
	if got := ProfileName(host, "alice"); got != host {
		t.Errorf("ProfileName without group = %q", got)
	}
	if got := FileBase(host, "alice@vpn-dc1"); got != "vpn.example.com-vpn-dc1" {
		t.Errorf("FileBase = %q", got)
	}
	if got := ConnName(host, "alice@vpn dc1"); got != "vpn-example-com-vpn-dc1" {
		t.Errorf("ConnName = %q", got)
	}
	for name, body := range map[string]string{
		"ps1":          string(WindowsScript(host, "alice@vpn-dc1", nil)),
		"mobileconfig": string(MobileConfig(host, "example.com", "alice@vpn-dc1", nil)),
		"sswan":        string(SSwan(host, "example.com", "alice@vpn-dc1", nil)),
	} {
		if !strings.Contains(body, "vpn.example.com (vpn-dc1)") {
			t.Errorf("%s profile lacks the connection name with the domain", name)
		}
	}
	if sw := string(LinuxSwanctl(host, "example.com", "alice@vpn-dc1")); !strings.Contains(sw, "  vpn-example-com-vpn-dc1 {") || !strings.Contains(sw, "eap-vpn-example-com-vpn-dc1 {") {
		t.Errorf("swanctl connection name:\n%s", sw)
	}
}

func TestWindowsSetupRunsOnDoubleClick(t *testing.T) {
	body := string(WindowsSetup("vpn.example.com", "alice@vpn-dc1", nil))
	first, rest, _ := strings.Cut(body, "\r\n")
	if !strings.HasPrefix(first, "@powershell ") || !strings.Contains(first, "-ExecutionPolicy Bypass") || !strings.Contains(first, "-Skip 1") ||
		!strings.HasSuffix(first, "& exit /b") {
		t.Fatalf("launcher line: %q", first)
	}
	if !strings.Contains(rest, "Add-VpnConnection") || !strings.Contains(rest, "-DHGroup ECP384") || strings.Contains(rest, "\n@") {
		t.Fatalf("script body:\n%s", rest)
	}
	if strings.Contains(body, "\n") && strings.Count(body, "\r\n") != strings.Count(body, "\n") {
		t.Fatal("cmd files need CRLF line endings")
	}
}
