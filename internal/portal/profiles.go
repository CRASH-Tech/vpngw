package portal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"vpngw/internal/policy"
)

// uuidFrom returns a deterministic UUID for stable profile identifiers.
func uuidFrom(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// ProfileName is how a connection is shown on the device: the server's
// domain and the group, so it is clear what the profile connects to.
func ProfileName(host, login string) string {
	if _, g := policy.SplitLogin(login); g != "" {
		return host + " (" + g + ")"
	}
	return host
}

// FileBase is the download file name without extension: domain and group.
func FileBase(host, login string) string {
	name := host
	if _, g := policy.SplitLogin(login); g != "" {
		name += "-" + g
	}
	return safeName(name, ".")
}

// ConnName is an identifier for config sections (no dots): domain-group.
func ConnName(host, login string) string {
	return safeName(strings.ReplaceAll(FileBase(host, login), ".", "-"), "")
}

func safeName(s, extra string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || strings.ContainsRune(extra, r) {
			return r
		}
		return '-'
	}, s)
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// MobileConfig renders an Apple configuration profile for IKEv2/EAP.
// The password is not embedded; the device asks for it.
func MobileConfig(host, remoteID, login string, p *policy.Profile) []byte {
	id := uuidFrom("mobileconfig", host, login)
	vpnID := uuidFrom("mobileconfig-vpn", host, login)
	name := ProfileName(host, login)
	sa := `<dict>
					<key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key><string>SHA2-384</string>
					<key>DiffieHellmanGroup</key><integer>20</integer>
					<key>LifeTimeInMinutes</key><integer>1440</integer>
				</dict>`
	includeAll := "<false/>"
	if p != nil && p.FullTunnel {
		includeAll = "<true/>"
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadDisplayName</key><string>%[1]s</string>
	<key>PayloadIdentifier</key><string>vpngw.%[2]s</string>
	<key>PayloadUUID</key><string>%[2]s</string>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadVersion</key><integer>1</integer>
	<key>PayloadDescription</key><string>IKEv2 VPN for %[4]s. You will be asked for your VPN password.</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key><string>com.apple.vpn.managed</string>
			<key>PayloadIdentifier</key><string>vpngw.%[2]s.vpn</string>
			<key>PayloadUUID</key><string>%[3]s</string>
			<key>PayloadVersion</key><integer>1</integer>
			<key>PayloadDisplayName</key><string>%[1]s</string>
			<key>UserDefinedName</key><string>%[1]s</string>
			<key>VPNType</key><string>IKEv2</string>
			<key>IKEv2</key>
			<dict>
				<key>RemoteAddress</key><string>%[5]s</string>
				<key>RemoteIdentifier</key><string>%[9]s</string>
				<key>LocalIdentifier</key><string>%[4]s</string>
				<key>AuthenticationMethod</key><string>None</string>
				<key>ExtendedAuthEnabled</key><integer>1</integer>
				<key>AuthName</key><string>%[4]s</string>
				<key>EnablePFS</key><integer>1</integer>
				<key>DeadPeerDetectionRate</key><string>Medium</string>
				<key>DisableMOBIKE</key><integer>0</integer>
				<key>DisableRedirect</key><integer>1</integer>
				<key>UseConfigurationAttributeInternalIPSubnet</key><integer>0</integer>
				<key>IncludeAllNetworks</key>%[7]s
				<key>IKESecurityAssociationParameters</key>
				%[6]s
				<key>ChildSecurityAssociationParameters</key>
				%[6]s
			</dict>
			<key>IPv4</key>
			<dict><key>OverridePrimary</key><integer>%[8]d</integer></dict>%[10]s
		</dict>
	</array>
</dict>
</plist>
`, xmlEscape(name), id, vpnID, xmlEscape(login), xmlEscape(host), sa, includeAll, boolInt(p != nil && p.FullTunnel), xmlEscape(remoteID), appleDNS(p)))
}

// appleDNS sends the profile's domains to the gateway's DNS server: with
// a split tunnel Apple devices use VPN resolvers only for match domains.
func appleDNS(p *policy.Profile) string {
	if p == nil || len(p.Domains) == 0 || len(p.DNS) == 0 || p.FullTunnel {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\t\t\t<key>DNS</key>\n\t\t\t<dict>\n\t\t\t\t<key>ServerAddresses</key><array>")
	for _, a := range p.DNS {
		fmt.Fprintf(&b, "<string>%s</string>", a)
	}
	b.WriteString("</array>\n\t\t\t\t<key>SupplementalMatchDomains</key><array>")
	for _, d := range p.Domains {
		if !strings.HasPrefix(d, "!") { // excluded names are answered normally
			fmt.Fprintf(&b, "<string>%s</string>", xmlEscape(d))
		}
	}
	b.WriteString("</array>\n\t\t\t\t<key>SupplementalMatchDomainsNoSearch</key><integer>1</integer>\n\t\t\t</dict>")
	return b.String()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SSwan renders a profile for the strongSwan Android app.
func SSwan(host, remoteID, login string, p *policy.Profile) []byte {
	prof := map[string]any{
		"uuid":         strings.ToLower(uuidFrom("sswan", host, login)),
		"name":         ProfileName(host, login),
		"type":         "ikev2-eap",
		"remote":       map[string]any{"addr": host, "id": remoteID},
		"local":        map[string]any{"eap_id": login},
		"ike-proposal": "aes256gcm16-prfsha384-ecp384",
		"esp-proposal": "aes256gcm16-ecp384",
	}
	if p != nil && !p.FullTunnel {
		var nets []string
		for _, r := range p.Routes() {
			nets = append(nets, r.String())
		}
		prof["split-tunneling"] = map[string]any{"subnets": strings.Join(nets, " "), "block-ipv6": true}
	}
	b, _ := json.MarshalIndent(prof, "", "  ")
	return b
}

// WindowsSetup wraps WindowsScript into a .cmd file that runs on a double
// click: PowerShell's execution policy blocks downloaded .ps1 scripts, but
// not a script passed to it with -ExecutionPolicy Bypass. The first line
// feeds the rest of the file to PowerShell; cmd never reads further.
func WindowsSetup(host, login string, p *policy.Profile) []byte {
	head := "@powershell -NoProfile -ExecutionPolicy Bypass -Command \"iex ((Get-Content -LiteralPath '%~f0' | Select-Object -Skip 1) -join [Environment]::NewLine)\" & pause & exit /b\r\n"
	return append([]byte(head), WindowsScript(host, login, p)...)
}

// IPsecCommand is the PowerShell command that switches a Windows IKEv2
// connection to the algorithms the server accepts (Windows' defaults use
// DH group 2, which it refuses).
func IPsecCommand(name string) string {
	return fmt.Sprintf("Set-VpnConnectionIPsecConfiguration -ConnectionName '%s' -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA384 -DHGroup ECP384 -PfsGroup ECP384 -Force", psQuote(name))
}

// WindowsScript renders a PowerShell script that creates the IKEv2
// connection with strong parameters and the routes of the profile.
func WindowsScript(host, login string, p *policy.Profile) []byte {
	name := ProfileName(host, login)
	var b strings.Builder
	b.WriteString("# vpngw: IKEv2 connection setup for Windows 10/11\r\n")
	b.WriteString("$ErrorActionPreference = 'Stop'\r\n")
	fmt.Fprintf(&b, "$Name = '%s'\r\n", psQuote(name))
	fmt.Fprintf(&b, "$Server = '%s'\r\n", psQuote(host))
	fmt.Fprintf(&b, "$Login = '%s'\r\n", psQuote(login))
	full := p != nil && p.FullTunnel
	b.WriteString("Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue | ForEach-Object { rasdial $Name /disconnect | Out-Null; Remove-VpnConnection -Name $Name -Force }\r\n")
	b.WriteString("$eap = New-EapConfiguration\r\n")
	fmt.Fprintf(&b, "Add-VpnConnection -Name $Name -ServerAddress $Server -TunnelType Ikev2 -AuthenticationMethod Eap -EapConfigXmlStream $eap.EapConfigXmlStream -EncryptionLevel Required -SplitTunneling:$%t -RememberCredential:$true -Force\r\n", !full)
	b.WriteString(IPsecCommand(name) + "\r\n")
	if !full && p != nil {
		for _, r := range p.Routes() {
			fmt.Fprintf(&b, "Add-VpnConnectionRoute -ConnectionName $Name -DestinationPrefix '%s'\r\n", r)
		}
	}
	b.WriteString("Write-Host \"Connection '$Name' created. Connect with user name '$Login' and your VPN password.\"\r\n")
	b.WriteString("Write-Host \"Re-run this script when the portal says your routes changed.\"\r\n")
	return []byte(b.String())
}

func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

// LinuxSwanctl renders a swanctl.conf snippet for Linux clients.
func LinuxSwanctl(host, remoteID, login string) []byte {
	conn := ConnName(host, login)
	return []byte(fmt.Sprintf(`# /etc/swanctl/conf.d/%[4]s.conf — connection to %[1]s
# The server certificate is checked against the system CAs; copy the root CA
# into /etc/swanctl/x509ca/ (e.g. /etc/ssl/certs/ISRG_Root_X1.pem), then run:
#   swanctl --load-all && swanctl --initiate --ike %[4]s --child vpn
connections {
  %[4]s {
    version = 2
    remote_addrs = %[1]s
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha384-ecp384
    local {
      auth = eap-mschapv2
      eap_id = %[2]s
    }
    remote {
      auth = pubkey
      id = %[3]s
    }
    children {
      vpn {
        remote_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16-ecp384
      }
    }
  }
}
secrets {
  eap-%[4]s {
    id = %[2]s
    secret = "<your VPN password>"
  }
}
`, host, login, remoteID, conn))
}
