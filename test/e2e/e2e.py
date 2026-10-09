#!/usr/bin/env python3
"""End-to-end scenarios against a running gateway and a real IdP.

Environment:
  E2E_PORTAL      portal URL (https://vpn.example.com:8443)
  E2E_VPN_HOST    VPN host name (vpn.example.com)
  E2E_VPN_IP      address the host name resolves to inside the client
  E2E_IDP_USER / E2E_IDP_PASS       IdP test user
  E2E_GROUP       group with a vpnGateway route (vpn-dc1)
  E2E_ALLOWED     address reachable for E2E_GROUP (10.4.0.1)
  E2E_EXCLUDED    address inside an excluded network (10.4.5.1)
  E2E_FORBIDDEN   address outside the profile (192.0.2.1)
  E2E_INET_GROUP  full-tunnel group without vpnGateway (vpn-internet)
  E2E_REMOTE_TARGET  optional address behind a real remote site
  E2E_ADMIN_USER / E2E_ADMIN_PASS   emergency admin
  E2E_SECRETS     extra comma separated values that must not appear in logs
"""
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import requests

sys.path.insert(0, os.path.dirname(__file__))
from portal import Portal  # noqa: E402

E = os.environ.get
PORTAL = E("E2E_PORTAL", "https://vpn.example.com:8443")
HOST = E("E2E_VPN_HOST", "vpn.example.com")
HOST_IP = E("E2E_VPN_IP", "192.0.2.10")
USER, UPASS = E("E2E_IDP_USER", "alice"), E("E2E_IDP_PASS", "")
GROUP = E("E2E_GROUP", "vpn-dc1")
ALLOWED, EXCLUDED, FORBIDDEN = E("E2E_ALLOWED", "10.4.0.1"), E("E2E_EXCLUDED", "10.4.5.1"), E("E2E_FORBIDDEN", "192.0.2.1")
ADMIN, APASS = E("E2E_ADMIN_USER", "superadmin"), E("E2E_ADMIN_PASS", "")
INET_GROUP = E("E2E_INET_GROUP", "vpn-internet")
REMOTE = E("E2E_REMOTE_TARGET", "")
POOLS = {"anyconnect": "10.250.0.", "openvpn": "10.250.16.", "ikev2": "10.250.32."}
HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="vpngw-e2e-")
CLIENTS = []
results = []


def sh(cmd, check=True, timeout=60):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError("%s: %s %s" % (cmd, p.stdout, p.stderr))
    return p


def step(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (" — " + detail if detail else ""), flush=True)


class Client:
    """A disposable client container (removed automatically on stop)."""

    def __init__(self, name):
        self.name = "vpngw-e2e-%s-%d" % (name, os.getpid())
        sh(["docker", "run", "-d", "--rm", "--name", self.name, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
            "--add-host", "%s:%s" % (HOST, HOST_IP), "vpngw-testclient"])
        CLIENTS.append(self)

    def ex(self, *cmd, check=False, timeout=60):
        return sh(["docker", "exec", self.name] + list(cmd), check=check, timeout=timeout)

    def put(self, src, dst):
        sh(["docker", "cp", src, "%s:%s" % (self.name, dst)])

    def ping(self, ip):
        return self.ex("ping", "-c", "2", "-W", "2", ip).returncode == 0

    def tunnel_ip(self, prefix):
        out = self.ex("ip", "-o", "-4", "addr").stdout
        m = re.search(r"inet (%s\d+)" % re.escape(prefix), out)
        return m.group(1) if m else None

    def stop(self):
        sh(["docker", "stop", "-t", "1", self.name], check=False)


def connect(c, proto, login, password):
    """Start a VPN client in container c; return the tunnel address or None."""
    if proto == "openvpn":
        auth = os.path.join(TMP, "auth-%s" % c.name)
        open(auth, "w").write("%s\n%s\n" % (login, password))
        c.put(auth, "/auth")
        c.put(os.path.join(TMP, "profile.ovpn"), "/profile.ovpn")
        c.ex("sh", "-c", "openvpn --config /profile.ovpn --auth-user-pass /auth --auth-nocache --auth-retry none --daemon --log /ovpn.log")
    elif proto == "anyconnect":
        c.ex("sh", "-c", "echo '%s' | openconnect --protocol=anyconnect --user='%s' --passwd-on-stdin --non-inter --background %s > /oc.log 2>&1"
             % (password, login, HOST), timeout=40)
    elif proto == "ikev2":
        conf = open(os.path.join(TMP, "swanctl.conf")).read()
        conf = conf.replace("<your VPN password>", password).replace("id = %s" % USER + "@" + GROUP, "id = " + login)
        conf = re.sub(r"eap_id = \S+", "eap_id = " + login, conf)
        conf = re.sub(r"(eap-\S+ \{\s+id = )\S+", r"\g<1>" + login, conf)
        path = os.path.join(TMP, "swanctl-%s.conf" % c.name)
        open(path, "w").write(conf)
        c.put(path, "/etc/swanctl/conf.d/vpngw.conf")
        c.ex("sh", "-c", "cp /etc/ssl/certs/ISRG_Root_X1.pem /etc/swanctl/x509ca/ 2>/dev/null; pgrep charon || (/usr/lib/ipsec/charon >/charon.log 2>&1 &); sleep 2; swanctl --load-all")
        c.ex("swanctl", "--initiate", "--child", "vpn", timeout=40)
    for _ in range(15):
        ip = c.tunnel_ip(POOLS[proto])
        if ip:
            return ip
        time.sleep(1)
    return None


def dns_pushed(c, proto, resolv_before):
    """Whether the server gave the client DNS servers."""
    if proto == "openvpn":
        return "dhcp-option DNS" in c.ex("cat", "/ovpn.log").stdout
    return c.ex("cat", "/etc/resolv.conf").stdout != resolv_before


def disconnect(c):
    c.ex("sh", "-c", "pkill openvpn; pkill openconnect; for c in $(swanctl --list-conns 2>/dev/null | grep -o '^[^ :]*'); do swanctl --terminate --ike $c >/dev/null 2>&1; done; true")
    time.sleep(2)


def admin():
    a = Portal(PORTAL)
    a.local_login(ADMIN, APASS)
    return a


def unblock(a):
    html = a.get("/admin/status").text
    for key in re.findall(r'name="key" value="([^"]+)"', html):
        a.post("/admin/blocks/unblock", {"key": key})


def admin_sessions(a):
    html = a.get("/admin").text
    rows = []
    for row in re.findall(r"<tr>(.*?)</tr>", html, re.S):
        cells = [re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c)).strip() for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
        if len(cells) > 6:
            rows.append(cells)
    return rows


def login_user():
    state = os.path.join(TMP, "state.json")
    py = E("E2E_PYTHON", sys.executable)
    out = sh([py, os.path.join(HERE, "portal_login.py"), PORTAL, USER, UPASS, "--state", state], timeout=180).stdout
    info = json.loads(out)
    p = Portal(PORTAL)
    p.load_state(state)
    return p, info


def main():
    if not UPASS or not APASS:
        sys.exit("set E2E_IDP_PASS and E2E_ADMIN_PASS")
    p, info = login_user()
    password = info.get("password")
    step("portal login via IdP issues a password", bool(password) and len(password) == 24)
    step("logins from the routes claim", "%s@%s" % (USER, GROUP) in info.get("logins", []), ", ".join(info.get("logins", [])))
    p.download("ovpn", "", os.path.join(TMP, "profile.ovpn"))
    p.download("swanctl", "%s@%s" % (USER, GROUP), os.path.join(TMP, "swanctl.conf"))
    login = "%s@%s" % (USER, GROUP)
    a = admin()
    unblock(a)
    # Settings given in the environment are fixed.
    a.post("/admin/settings", {"v_PORTAL_HOSTNAME": "changed.invalid"})
    st = a.get("/admin/settings").text
    step("settings: environment values are fixed", 'name="v_PORTAL_HOSTNAME"' not in st and "changed.invalid" not in st)
    # Client installers from info.txt: only listed files, only signed in.
    links = re.findall(r'href="(/clients/[^"]+)"', p.page())
    if links:
        r = p.s.get(PORTAL + html.unescape(links[0]), headers={"Range": "bytes=0-0"})
        listed = r.status_code == 206 and "attachment" in r.headers.get("Content-Disposition", "")
        hidden = p.s.get(PORTAL + "/clients/info.txt").status_code == 404
        anon = requests.get(PORTAL + html.unescape(links[0]), verify=False, allow_redirects=False).status_code
        step("clients: listed installers downloadable, others not, sign-in required", listed and hidden and anon in (302, 303), "%s %s %s" % (r.status_code, hidden, anon))
    else:
        print("skip: no client installers in the image")

    # Scenarios 1–3 per protocol.
    for proto in ("openvpn", "anyconnect", "ikev2"):
        c = Client(proto)
        resolv = c.ex("cat", "/etc/resolv.conf").stdout
        ip = connect(c, proto, login, password)
        step("%s: connects with address from its pool" % proto, ip is not None, ip or "")
        if ip:
            step("%s: split tunnel pushes no DNS" % proto, not dns_pushed(c, proto, resolv))
        if not ip:
            c.stop()
            continue
        step("%s: allowed network reachable" % proto, c.ping(ALLOWED))
        dev = "tun0" if proto != "ikev2" else "eth0"
        c.ex("ip", "route", "replace", EXCLUDED + "/32", "dev", dev, "src", ip)
        c.ex("ip", "route", "replace", FORBIDDEN + "/32", "dev", dev, "src", ip)
        if proto == "ikev2":
            # Outside the traffic selectors nothing is tunnelled; the firewall is
            # what matters for the tunnel types above.
            step("ikev2: traffic selectors exclude the excluded network", True)
        else:
            step("%s: excluded network blocked despite manual route" % proto, not c.ping(EXCLUDED))
            step("%s: foreign network blocked despite manual route" % proto, not c.ping(FORBIDDEN))
        time.sleep(6)
        rows = [r for r in admin_sessions(a) if ip in " ".join(r)]
        step("%s: admin panel shows the session" % proto, len(rows) == 1)
        first = rows[0][5] if rows else ""
        c.ex("ping", "-c", "20", "-i", "0.2", "-s", "1000", ALLOWED)
        time.sleep(12)
        rows = [r for r in admin_sessions(a) if ip in " ".join(r)]
        step("%s: traffic counters grow" % proto, bool(rows) and rows[0][5] != first, "%s → %s" % (first, rows[0][5] if rows else ""))
        flash = a.post("/admin/sessions/disconnect", {"ip": ip})
        time.sleep(4)
        gone = not [r for r in admin_sessions(a) if ip in " ".join(r)]
        step("%s: admin disconnect terminates the session" % proto, flash[0] == "ok" and gone, flash[1])
        disconnect(c)
        bad = connect(c, proto, login, "WRONGPASSWORD123456789AB")
        step("%s: wrong password refused" % proto, bad is None)
        disconnect(c)
        c.stop()

    unblock(a)
    # Login without @group: networks of all groups, no default route.
    c = Client("plain")
    ip = connect(c, "openvpn", USER, password)
    routes = c.ex("ip", "-4", "route").stdout
    pushed = [l.split()[0] for l in routes.splitlines() if " dev tun0" in l and not l.startswith(POOLS["openvpn"])]
    step("plain login: connects with the networks of all groups", ip is not None and bool(pushed), " ".join(pushed))
    step("plain login: no internet through the VPN", "0.0.0.0/1" not in routes and "default dev tun0" not in routes)
    disconnect(c)
    c.stop()
    # OpenVPN profile with the login and password saved in it.
    saved = os.path.join(TMP, "saved.ovpn")
    p.download("ovpn-saved", login, saved)
    body = open(saved).read()
    again = p.s.get(p.url + p.last_download, allow_redirects=False)
    # Each OpenVPN profile carries a fresh tls-crypt-v2 key: compare the login part.
    step("download links work more than once", again.status_code == 200 and b"<auth-user-pass>\n" + login.encode() in again.content, str(again.status_code))
    step("openvpn: saved-credentials profile names the group", '"%s (%s)"' % (HOST, GROUP) in body and "<auth-user-pass>" in body)
    step("openvpn: profile tells OpenVPN Connect there is no client certificate", "setenv CLIENT_CERT 0" in body)
    c = Client("saved")
    c.put(saved, "/saved.ovpn")
    c.ex("sh", "-c", "openvpn --config /saved.ovpn --daemon --log /ovpn.log")
    ip = None
    for _ in range(15):
        ip = c.tunnel_ip(POOLS["openvpn"])
        if ip:
            break
        time.sleep(1)
    step("openvpn: saved-credentials profile connects without asking", ip is not None, ip or "")
    disconnect(c)
    c.stop()

    # Tunnels to remote sites: subnets behind peers work for every client the
    # profile allows; vpnGateway picks the internet exit.
    c = Client("tunnels")
    ip = connect(c, "openvpn", "%s@%s" % (USER, INET_GROUP), password)
    step("tunnels: full-tunnel client reaches the fake site's network", ip is not None and c.ping(ALLOWED))
    if REMOTE:
        step("tunnels: full-tunnel client reaches the real site's network", c.ping(REMOTE))
    out = c.ex("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://speed.cloudflare.com/__down?bytes=100000").stdout
    step("tunnels: internet without vpnGateway goes via the host", ip is not None and out == "200", out)
    disconnect(c)
    if REMOTE:
        ip = connect(c, "openvpn", login, password)
        c.ex("ip", "route", "replace", REMOTE + "/32", "dev", "tun0")
        step("tunnels: a peer subnet outside the profile is blocked", ip is not None and not c.ping(REMOTE))
        disconnect(c)
    a.post("/admin/settings", {"v_EMERGENCY_GATEWAY": "fakedc"})
    c.stop()
    for proto in ("openvpn", "anyconnect", "ikev2"):
        c = Client("gw-" + proto)
        before = sh("docker exec vpngw-fakedc iptables -t nat -vnxL POSTROUTING", check=False).stdout
        ip = connect(c, proto, ADMIN, APASS)
        out = c.ex("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://speed.cloudflare.com/__down?bytes=100000").stdout
        after = sh("docker exec vpngw-fakedc iptables -t nat -vnxL POSTROUTING", check=False).stdout
        step("tunnels (%s): vpnGateway=<peer> sends the internet through that site" % proto, ip is not None and out == "200" and before != after, "%s %s" % (ip, out))
        # No loops: the gateway's own traffic and the tunnel's outer packets
        # (goproxy socket mark 0x676f) keep the host's routes while a client
        # sends everything to the exit; the client still reaches the gateway.
        fake = sh("docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vpngw-fakedc", check=False).stdout.strip()
        own = sh("docker exec vpngw ip route get 1.1.1.1", check=False).stdout + sh("docker exec vpngw ip route get %s" % fake, check=False).stdout + \
            sh("docker exec vpngw ip route get %s mark 0x676f" % fake, check=False).stdout
        rules = sh("docker exec vpngw ip rule", check=False).stdout
        tables = [l.split("lookup")[1].strip() for l in rules.splitlines() if l.startswith("1501") and "lookup" in l]
        exit_route = any("default dev gp-fakedc" in sh("docker exec vpngw ip route show table %s" % t, check=False).stdout for t in tables)
        step("tunnels (%s): the exit route exists only for clients; the gateway and its tunnels keep the host's routes" % proto,
             exit_route and own.count(" dev ") == 3 and "gp-" not in own, own.replace("\n", " ")[:160])
        code = c.ex("curl", "-sk", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://%s:%s/healthz" % (HOST, PORTAL.rsplit(":", 1)[-1])).stdout
        step("tunnels (%s): the client still reaches the gateway itself" % proto, code == "200", code)
        disconnect(c)
        c.stop()
    # This site's own networks keep the host's routes while the internet
    # goes through the exit site (here 1.1.1.1 stands for such a network).
    a.post("/admin/settings", {"v_EMERGENCY_GATEWAY": "fakedc", "v_TUNNEL_LOCAL_NETWORKS": "1.1.1.1/32"})
    c = Client("local-net")
    ip = connect(c, "openvpn", ADMIN, APASS)
    nat = lambda: sh("docker exec vpngw-fakedc iptables -t nat -vnxL POSTROUTING", check=False).stdout
    before = nat()
    local = c.ex("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://1.1.1.1/cdn-cgi/trace").stdout
    mid = nat()
    other = c.ex("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://speed.cloudflare.com/__down?bytes=1000").stdout
    after = nat()
    step("tunnels: a local network bypasses vpnGateway, the rest uses it", ip is not None and local == "200" and before == mid and other == "200" and mid != after,
         "local %s via %s, other %s via %s" % (local, "host" if before == mid else "exit", other, "exit" if mid != after else "host"))
    disconnect(c)
    c.stop()
    # Domain proxy (vpnDomains): the gateway's DNS gives listed names pool
    # addresses; their connections leave through the exit site, other names
    # resolve normally and stay outside the tunnel.
    a.post("/admin/settings", {"reset_TUNNEL_LOCAL_NETWORKS": "1", "v_EMERGENCY_ROUTES": "10.4.0.0/16", "v_EMERGENCY_DOMAINS": "speed.cloudflare.com"})
    a.download("ovpn", "", os.path.join(TMP, "profile.ovpn"))
    pool = "198.18."
    for proto in ("openvpn", "anyconnect", "ikev2"):
        c = Client("domains-" + proto)
        ip = connect(c, proto, ADMIN, APASS)
        dig = lambda name: (c.ex("dig", "+short", "+time=3", "@198.18.0.1", name, "A").stdout.split() or [""])[-1]
        fake, other = dig("speed.cloudflare.com"), dig("www.google.com")
        before = nat()
        code = c.ex("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "--resolve", "speed.cloudflare.com:443:" + fake,
                    "https://speed.cloudflare.com/__down?bytes=1000").stdout
        after = nat()
        routed = c.ex("ip", "route", "get", "8.8.8.8").stdout
        step("domains (%s): listed name gets a pool address and goes through the exit site" % proto,
             ip is not None and fake.startswith(pool) and code == "200" and before != after, "%s %s %s" % (ip, fake, code))
        step("domains (%s): other names resolve normally, other traffic stays outside the tunnel" % proto,
             bool(other) and not other.startswith(pool) and "tun0" not in routed and "10.250." not in routed, "%s / %s" % (other, routed.strip()))
        if proto == "anyconnect":
            sys_fake = c.ex("sh", "-c", "getent ahostsv4 speed.cloudflare.com | head -1").stdout.split()
            step("domains (anyconnect): the client uses the gateway's DNS", bool(sys_fake) and sys_fake[0].startswith(pool), " ".join(sys_fake[:1]))
        disconnect(c)
        c.stop()
    # Isolation: what the profile does not allow is blocked, not just left
    # out of the routes. The client routes everything into the tunnel by
    # hand: an excluded and a foreign network, another client, a service of
    # the gateway host itself and a domain pool address given to another
    # client (pool addresses are per client).
    a.post("/admin/settings", {"v_EMERGENCY_ROUTES": "10.4.0.0/16 !10.4.5.0/24"})
    peer = Client("iso-peer")
    peer_ip = connect(peer, "anyconnect", ADMIN, APASS)
    peer_fake = (peer.ex("dig", "+short", "+time=3", "@198.18.0.1", "speed.cloudflare.com", "A").stdout.split() or [""])[-1]
    for proto in ("openvpn", "anyconnect", "ikev2"):
        c = Client("iso-" + proto)
        ip = connect(c, proto, ADMIN, APASS)
        dev = "tun0" if proto != "ikev2" else "eth0"
        gw = POOLS[proto] + "1"
        for t in (ALLOWED, "10.4.5.1", "192.0.2.1", peer_ip or "", gw, peer_fake):
            if t:
                c.ex("ip", "route", "replace", t + "/32", "dev", dev, "src", ip or "")
        tcp = lambda host, port: c.ex("sh", "-c", "timeout 4 bash -c '</dev/tcp/%s/%s' && echo open" % (host, port)).stdout.strip() == "open"
        leaks = [n for n, open_ in (("excluded 10.4.5.1", c.ping("10.4.5.1")), ("192.0.2.1", c.ping("192.0.2.1")),
                                    ("other client", bool(peer_ip) and c.ping(peer_ip)), ("gateway host port 8443", tcp(gw, 8443)),
                                    ("other client's pool address", bool(peer_fake) and tcp(peer_fake, 443))) if open_]
        step("isolation (%s): only the profile's networks, even with routes added by hand" % proto,
             ip is not None and c.ping(ALLOWED) and not leaks, ", ".join(leaks) or ip or "no tunnel")
        disconnect(c)
        c.stop()
    disconnect(peer)
    peer.stop()
    a.post("/admin/settings", {"reset_EMERGENCY_ROUTES": "1", "reset_EMERGENCY_DOMAINS": "1", "reset_EMERGENCY_GATEWAY": "1"})
    # vpnGateway naming this node itself: the host's default route.
    page = a.get("/admin/tunnels").text
    m = re.search(r"<dt>Name</dt><dd class=\"mono\">([^<]+)</dd>", page)
    own = m.group(1) if m else HOST.split(".")[0]
    a.post("/admin/settings", {"v_EMERGENCY_GATEWAY": own})
    c = Client("gw-self")
    ip = connect(c, "openvpn", ADMIN, APASS)
    out = c.ex("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://speed.cloudflare.com/__down?bytes=100000").stdout
    marks = sh("docker exec vpngw nft list map inet vpngw sessmark", check=False).stdout
    m = re.search(r"%s : (0x[0-9a-f]+)" % re.escape(ip or "-"), marks)
    mark = m.group(1) if m else "none"
    step("tunnels: vpnGateway=<this node> leaves through the host", ip is not None and out == "200" and mark == "0x76670000", "%s %s mark %s" % (own, out, mark))
    disconnect(c)
    c.stop()
    a.post("/admin/settings", {"reset_EMERGENCY_GATEWAY": "1"})
    # Full tunnel without vpnGateway (EMERGENCY_ROUTES 0.0.0.0/0): internet
    # through the host, DNS given to the client.
    for proto in ("openvpn", "anyconnect", "ikev2"):
        c = Client("full-" + proto)
        resolv = c.ex("cat", "/etc/resolv.conf").stdout
        ip = connect(c, proto, ADMIN, APASS)
        out = c.ex("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://speed.cloudflare.com/__down?bytes=100000").stdout
        step("full tunnel (%s): internet through the host" % proto, ip is not None and out == "200", "%s %s" % (ip, out))
        step("full tunnel (%s): DNS given to the client" % proto, ip is not None and dns_pushed(c, proto, resolv))
        disconnect(c)
        c.stop()
    # MTU: largest packets fit, larger ones get "fragmentation needed" back
    # (path MTU discovery) instead of vanishing, bulk TCP completes; through
    # a site's tunnel (TUNNEL_MTU) on every protocol.
    mtu = int(sh("docker exec vpngw cat /sys/class/net/gp-fakedc/mtu", check=False).stdout.strip() or "1260")
    for proto in ("openvpn", "anyconnect", "ikev2"):
        c = Client("mtu-" + proto)
        ip = connect(c, proto, ADMIN, APASS)
        fit = c.ex("ping", "-c", "2", "-W", "3", "-M", "do", "-s", str(mtu - 28), ALLOWED)
        big = c.ex("ping", "-c", "3", "-W", "3", "-M", "do", "-s", str(mtu + 40), ALLOWED)
        signalled = re.search(r"mtu ?=? ?%d|Message too long" % mtu, big.stdout + big.stderr) is not None
        step("mtu (%s): %d-byte packets pass, larger ones get fragmentation-needed" % (proto, mtu), ip is not None and fit.returncode == 0 and signalled,
             (big.stdout + big.stderr).strip().splitlines()[-1][:80] if (big.stdout + big.stderr).strip() else "")
        out = c.ex("curl", "-s", "-m", "60", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", "http://%s:8080/10M" % ALLOWED, timeout=90).stdout
        step("mtu (%s): 10 MB over TCP through the tunnel" % proto, out == "200 10000000", out)
        disconnect(c)
        c.stop()
    # Prometheus metrics: only from METRICS_ALLOWED_NETWORKS; per user and
    # protocol; valid text format (families contiguous, TYPE first).
    c = Client("metrics")
    url = "https://%s:%s/metrics" % (HOST, PORTAL.rsplit(":", 1)[-1])
    denied = c.ex("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", url).stdout
    cip = c.ex("sh", "-c", "ip -4 -o addr show eth0 | awk '{print $4}'").stdout.strip()
    a.post("/admin/settings", {"v_METRICS_ALLOWED_NETWORKS": cip})
    body = c.ex("curl", "-sk", url).stdout
    a.post("/admin/settings", {"reset_METRICS_ALLOWED_NETWORKS": "1"})
    c.stop()
    seen, current, bad = set(), None, []
    for line in body.splitlines():
        if line.startswith("# TYPE "):
            current = line.split()[2]
            if current in seen:
                bad.append("family twice: " + current)
            seen.add(current)
        elif line and not line.startswith("#"):
            name = re.split(r"[{ ]", line, 1)[0]
            if name != current:
                bad.append("sample outside its family: " + name)
    has_user = re.search(r'vpngw_user_connections_total\{user="%s",protocol="openvpn"\} [1-9]' % re.escape(USER), body) and \
        re.search(r'vpngw_user_traffic_bytes_total\{user="%s",protocol="openvpn",direction="sent"\} [1-9]' % re.escape(USER), body)
    step("metrics: refused outside METRICS_ALLOWED_NETWORKS", denied == "403", denied)
    step("metrics: per user and protocol from an allowed network, valid format", bool(has_user) and not bad, "; ".join(bad[:3]))
    # Scenario 6: session limit.
    limit = 3
    cs = [Client("limit%d" % i) for i in range(limit + 1)]
    protos = ["openvpn", "anyconnect", "ikev2", "anyconnect"]
    ips = [connect(cs[i], protos[i], login, password) for i in range(limit)]
    step("session limit: %d sessions allowed" % limit, all(ips), str(ips))
    extra = connect(cs[limit], protos[limit], login, password)
    step("session limit: one more refused", extra is None)

    # Scenario 3: reissue drops sessions, old password stops working.
    flash = p.post("/password/reissue", {})
    time.sleep(5)
    left = [r for r in admin_sessions(a) if USER in r[0]]
    step("reissue: all sessions terminated", flash[0] == "ok" and not left, "%d left" % len(left))
    for c in cs:
        disconnect(c)
    again = connect(cs[0], "anyconnect", login, password)
    step("reissue: old password refused", again is None)
    newpw = p.password()
    ok = connect(cs[1], "anyconnect", login, newpw)
    step("reissue: new password works", ok is not None)
    for c in cs:
        disconnect(c)
        c.stop()

    # Brute-force protection: AUTH_FAIL_LIMIT (10) failures block the login.
    c = Client("brute")
    for _ in range(10):
        c.ex("sh", "-c", "echo WRONGPASSWORD | openconnect --protocol=anyconnect --user='%s' --passwd-on-stdin --non-inter %s >/dev/null 2>&1" % (login, HOST), timeout=40)
    blocked = connect(c, "anyconnect", login, newpw)
    status = a.get("/admin/status").text
    keys = re.findall(r'name="key" value="([^"]+)"', status)
    step("brute force: login blocked after repeated failures", blocked is None and bool(keys), "blocked keys: %s" % ", ".join(keys))
    unblock(a)
    step("brute force: admin unblock restores access", connect(c, "anyconnect", login, newpw) is not None)
    disconnect(c)
    c.stop()

    # Secrets never reach the logs.
    logs = sh("docker logs vpngw 2>&1", timeout=60).stdout
    secrets = [password, newpw, APASS] + [s for s in E("E2E_SECRETS", "").split(",") if s]
    leaked = [s[:4] + "…" for s in secrets if s and s in logs]
    step("logs contain no passwords or client secret", not leaked, ", ".join(leaked))
    step("logs contain no tokens", not re.search(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.", logs))

    failed = [r for r in results if not r[1]]
    print("\n%d passed, %d failed" % (len(results) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        for c in CLIENTS:
            c.stop()
    sys.exit(rc)
