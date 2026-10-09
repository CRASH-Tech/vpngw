#!/usr/bin/env python3
"""Sign in to the vpngw portal through the IdP (Authentik) with a headless
browser and print the VPN password and download links as JSON.

Usage: portal_login.py <portal-url> <idp-user> <idp-password> [--state FILE]
The browser storage state (cookies) is saved to FILE for later downloads.
"""
import json
import re
import sys

from playwright.sync_api import sync_playwright


def main():
    portal, user, password = sys.argv[1:4]
    state = None
    if "--state" in sys.argv:
        state = sys.argv[sys.argv.index("--state") + 1]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.goto(portal.rstrip("/") + "/login")
        page.wait_for_selector("input[name=uidField]", timeout=20000)
        page.fill("input[name=uidField]", user)
        page.keyboard.press("Enter")
        page.wait_for_selector("input[name=password]", timeout=20000)
        page.fill("input[name=password]", password)
        page.keyboard.press("Enter")
        for _ in range(30):
            page.wait_for_timeout(1000)
            if page.url.startswith(portal.rstrip("/")) and "/oidc/" not in page.url:
                break
            for name in ("Continue", "Yes", "Allow"):
                btn = page.get_by_role("button", name=name)
                try:
                    if btn.count():
                        btn.first.click(timeout=3000)
                except Exception:
                    pass
        if not page.url.startswith(portal.rstrip("/")):
            print(json.dumps({"error": "login did not return to portal", "url": page.url}))
            sys.exit(1)
        html = page.content()
        out = {"url": page.url}
        m = re.search(r'id="vpn-password" data-value="([^"]+)"', html)
        out["password"] = m.group(1) if m else None
        out["logins"] = re.findall(r'<td><span class="mono nowrap">([^<]+)</span>', html)
        out["downloads"] = sorted(set(re.findall(r'href="(/download/[^"]+)"', html)))
        err = re.search(r'<p class="muted">([^<]+)</p>', html)
        if out["password"] is None and err:
            out["message"] = err.group(1)
        if state:
            ctx.storage_state(path=state)
        print(json.dumps(out, indent=1))
        browser.close()


if __name__ == "__main__":
    main()
