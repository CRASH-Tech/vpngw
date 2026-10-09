# Manual test checklist

Run before a release with real clients. Use a test user with two groups
(one split tunnel with `vpnGateway`, one full tunnel).

## Portal

- [ ] Sign in via SSO; password shown, Show/Copy work; Credentials show the plain login; My networks lists it (all groups, no internet) and every `user@group`.
- [ ] Reissue password: confirmation, all sessions drop, new password works, old does not.
- [ ] Page works on a phone (layout, tabs, downloads); platform tab chosen automatically.

## Cisco Secure Client

- [ ] Windows: connect to the VPN host, split routes present (`route print`), allowed host reachable, other hosts not.
- [ ] macOS: same; disconnect from the admin panel ends the session.
- [ ] Full-tunnel group: all traffic and DNS through the tunnel.

## IKEv2

- [ ] Windows 10/11: PowerShell script creates the connection; connects; routes from the script; `Get-VpnConnection` shows GCMAES256/ECP384.
- [ ] macOS: `.mobileconfig` installs; password prompt; split routes applied.
- [ ] iOS: `.mobileconfig` installs from Safari; connects; split routes applied.
- [ ] Android: strongSwan app imports `.sswan`; connects.
- [ ] Server certificate name check: connecting with a wrong server name fails.

## OpenVPN

- [ ] OpenVPN Connect on iOS and Android import `.ovpn` and connect.
- [ ] After password reissue the old `.ovpn` no longer connects (tls-crypt-v2 key revoked).

## Identity provider

- [ ] Deactivate the user in the IdP: sessions end within `OIDC_REVALIDATE_INTERVAL` + 1 minute.
- [ ] Remove the user from the split-tunnel group: that session ends, the full-tunnel one stays.
- [ ] Add a network to the group: firewall allows it at once, portal asks to reconnect.
- [ ] Stop the IdP (or block its address): sessions survive `OIDC_GRACE_PERIOD`, then end; emergency admin still connects.
- [ ] Back-channel logout (if the IdP can reach the portal): logout in the IdP ends sessions immediately.

## Admin panel

- [ ] Sessions table updates every 5 s; filters and sorting; totals.
- [ ] Settings change (e.g. `SESSION_LIMIT`) applies without restart.
- [ ] Config override for openvpn.conf: diff shown, OpenVPN restarts, reset restores the generated file.
- [ ] Certificate upload / file replacement: new certificate served without dropping sessions.
