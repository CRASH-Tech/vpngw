#!/usr/bin/env python3
"""Small client for the vpngw portal used by the e2e scripts.

  portal.py URL local USER PASS           sign in as the emergency admin
  portal.py URL cookies FILE              reuse a Playwright storage state
then commands (chainable):
  password                                print the VPN password
  download KIND [LOGIN] OUT               save a profile (ovpn|ps1|mobileconfig|sswan|swanctl)
  kill IP                                 admin: disconnect a session
  revoke USERID                           admin: disconnect user + revoke password
  reissue                                 reissue own password (prints the new one)
  sessions                                admin: print sessions page rows (text)
"""
import html
import json
import re
import sys

import requests
import urllib3

urllib3.disable_warnings()


class Portal:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.verify = False

    def get(self, path):
        r = self.s.get(self.url + path, allow_redirects=True)
        r.raise_for_status()
        return r

    def csrf(self):
        m = re.search(r'name="csrf-token" content="([^"]+)"', self.get("/").text)
        return m.group(1)

    def post(self, path, data):
        data = dict(data, csrf=self.csrf())
        r = self.s.post(self.url + path, data=data, allow_redirects=True)
        r.raise_for_status()
        flash = re.search(r'<div class="alert (\w*)">([^<]*)</div>', r.text)
        return flash.groups() if flash else ("", "")

    def local_login(self, user, pw):
        r = self.s.post(self.url + "/login/local", data={"username": user, "password": pw}, allow_redirects=True)
        if "Invalid credentials" in r.text or r.status_code >= 400:
            raise SystemExit("local login failed")

    def load_state(self, path):
        st = json.load(open(path))
        for c in st["cookies"]:
            self.s.cookies.set(c["name"], c["value"], domain=c["domain"], path=c["path"])

    def page(self):
        return self.get("/").text

    def password(self):
        m = re.search(r'id="vpn-password" data-value="([^"]+)"', self.page())
        return m.group(1) if m else None

    def download(self, kind, login, out):
        page = self.page()
        if kind == "ovpn":
            m = re.search(r'href="(/download/[^"]+)">Download', page)
        elif kind == "ovpn-saved":
            group = login.split("@", 1)[1]
            m = re.search(r'href="(/download/[^"]+)">[^<]* \(' + re.escape(group) + r'\)</a>', page)
        else:
            labels = {"ps1": "Windows setup", "mobileconfig": "macOS profile", "sswan": "strongSwan profile", "swanctl": "swanctl.conf"}
            m = re.search(r'href="(/download/[^"]+)">' + re.escape(labels[kind]) + r' · ' + re.escape(login) + '<', page)
        if not m:
            raise SystemExit("download link not found for %s %s" % (kind, login))
        self.last_download = html.unescape(m.group(1))
        r = self.get(self.last_download)
        open(out, "wb").write(r.content)
        print("saved", out, len(r.content), "bytes")


def main():
    args = sys.argv[1:]
    p = Portal(args.pop(0))
    mode = args.pop(0)
    if mode == "local":
        p.local_login(args.pop(0), args.pop(0))
    elif mode == "cookies":
        p.load_state(args.pop(0))
    while args:
        cmd = args.pop(0)
        if cmd == "password":
            print(p.password())
        elif cmd == "download":
            kind = args.pop(0)
            login = args.pop(0) if kind != "ovpn" else ""
            p.download(kind, login, args.pop(0))
        elif cmd == "kill":
            print(p.post("/admin/sessions/disconnect", {"ip": args.pop(0)}))
        elif cmd == "revoke":
            print(p.post("/admin/users/%s/revoke" % args.pop(0), {}))
        elif cmd == "reissue":
            print(p.post("/password/reissue", {}))
            print(p.password())
        elif cmd == "sessions":
            html = p.get("/admin").text
            for row in re.findall(r"<tr>(.*?)</tr>", html, re.S):
                cells = [re.sub(r"<[^>]+>", " ", c).split() for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
                if cells:
                    print(" | ".join(" ".join(c) for c in cells[:10]))
        else:
            raise SystemExit("unknown command " + cmd)


if __name__ == "__main__":
    main()
