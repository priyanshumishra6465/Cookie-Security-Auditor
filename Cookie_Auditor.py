#!/usr/bin/env python3
"""
Cookie Security Auditor
------------------------
A defensive tool that audits cookie security configuration.

Two modes:
  1. Live URL scan   -- inspects Set-Cookie headers returned by a site you
                         own or have permission to test.
  2. Cookie file scan -- analyzes an exported cookie file (Netscape format,
                          the kind browsers/extensions export, or a JSON
                          export) from YOUR OWN browser.

This tool does not exfiltrate, transmit, or collect anyone else's cookies.
It only reads cookie *attributes* (flags/metadata) to score how securely
they are configured, and prints/report that locally.

Usage:
    python3 cookie_auditor.py url https://example.com
    python3 cookie_auditor.py file path/to/cookies.txt
    python3 cookie_auditor.py file path/to/cookies.json --format json
"""

import argparse
import http.client
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CookieFinding:
    name: str
    domain: str = ""
    secure: Optional[bool] = None
    httponly: Optional[bool] = None
    samesite: Optional[str] = None
    expires: Optional[float] = None  # unix timestamp, None = session cookie
    path: str = "/"
    issues: list = field(default_factory=list)   # problems found (deduct points)
    notes: list = field(default_factory=list)    # informational, incl. "this is fine, here's why"
    score: int = 100  # out of 100, deducted per issue

    def evaluate(self, served_over_https: bool = True):
        self.issues = []
        self.notes = []
        self.score = 100

        looks_like_session_cookie = any(
            kw in self.name.lower()
            for kw in ("sess", "sid", "token", "auth", "login", "jwt", "id")
        )

        # --- Secure flag -> defends against network sniffing / MITM ---
        if self.secure is False:
            self.issues.append(
                "[Attack: Network sniffing / MITM] Missing 'Secure' flag -- "
                "this cookie can be sent over plain HTTP. Anyone capturing "
                "traffic on the same network (public WiFi, a compromised "
                "router, ARP spoofing) can read it straight out of the "
                "packet, e.g. in Wireshark, with no decryption needed."
            )
            self.score -= 30
        elif self.secure is None:
            self.issues.append("Could not determine 'Secure' flag status.")
            self.score -= 5
        else:
            self.notes.append(
                "[Defends against: Network sniffing / MITM] 'Secure' flag is "
                "set -- this cookie is never sent over plain HTTP, so a "
                "packet capture only sees encrypted TLS traffic, not the "
                "cookie value."
            )

        # --- HttpOnly flag -> defends against XSS cookie theft ---
        if self.httponly is False:
            self.issues.append(
                "[Attack: XSS (Cross-Site Scripting)] Missing 'HttpOnly' "
                "flag -- if an attacker manages to inject JavaScript into "
                "this site (e.g. via an unsanitized comment field or search "
                "box), that script can read this cookie with "
                "document.cookie and send it to the attacker's own server."
            )
            self.score -= 30
        elif self.httponly is None:
            self.issues.append("Could not determine 'HttpOnly' flag status.")
            self.score -= 5
        else:
            self.notes.append(
                "[Defends against: XSS cookie theft] 'HttpOnly' flag is set "
                "-- JavaScript cannot read this cookie at all, even if an "
                "XSS payload runs on the page."
            )

        # --- SameSite -> defends against CSRF ---
        if self.samesite is None or self.samesite.lower() == "none":
            self.issues.append(
                "[Attack: CSRF (Cross-Site Request Forgery)] SameSite is "
                "missing or set to 'None' -- if you're logged in here and "
                "visit a malicious page in another tab, that page can "
                "trigger requests to this site and your browser will still "
                "attach this cookie, letting the attacker perform actions "
                "as you (e.g. change your email, transfer funds)."
            )
            self.score -= 20
        elif self.samesite.lower() == "lax":
            self.notes.append(
                "[Defends against: most CSRF] SameSite=Lax blocks the "
                "cookie on cross-site POST/forms but still allows it on "
                "simple top-level navigation (a plain link) -- 'Strict' "
                "closes that remaining gap for highly sensitive cookies."
            )
            self.score -= 5
        else:
            self.notes.append(
                "[Defends against: CSRF] SameSite=Strict -- this cookie is "
                "never sent on cross-site requests at all, the strongest "
                "CSRF protection available at the cookie level."
            )

        # --- Expiry -> limits the damage window of session hijacking ---
        if self.expires is not None:
            days_remaining = (self.expires - time.time()) / 86400
            if looks_like_session_cookie and days_remaining > 7:
                self.issues.append(
                    f"[Attack: Session hijacking -- extended damage window] "
                    f"Looks like a session/auth cookie but expires in "
                    f"~{int(days_remaining)} days. If this cookie is ever "
                    f"stolen by any of the methods above, the attacker has "
                    f"that same multi-week window to use it before it "
                    f"expires on its own."
                )
                self.score -= 15
            elif looks_like_session_cookie:
                self.notes.append(
                    "[Limits: session hijacking damage window] Short "
                    "expiry on this session-like cookie -- even if stolen, "
                    "an attacker has only a brief window to use it."
                )

        # --- Domain scope -> subdomain-related attack surface ---
        if self.domain.startswith("."):
            self.issues.append(
                f"[Attack surface: subdomain takeover / cross-subdomain "
                f"leakage] Domain scope '{self.domain}' is a broad "
                f"wildcard-style domain -- this cookie is sent to every "
                f"subdomain. If any subdomain is ever compromised, "
                f"misconfigured, or taken over (e.g. an abandoned "
                f"dev.{self.domain.lstrip('.')} pointing at a dead cloud "
                f"service), that subdomain can read or receive this "
                f"cookie too."
            )
            self.score -= 5

        if not served_over_https and self.secure:
            self.issues.append(
                "Site was not reachable over HTTPS, so the 'Secure' flag "
                "cannot actually take effect as intended."
            )

        self.score = max(self.score, 0)
        return self


# ---------------------------------------------------------------------------
# Mode 1: Live URL scan
# ---------------------------------------------------------------------------

def scan_url(url: str) -> list:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    findings = []
    served_over_https = parsed.scheme == "https"
    hsts_present = False
    redirects_to_https = False

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"[!] Could not reach {url}: {e}")
        return findings

    if resp.history:
        final_scheme = urlparse(resp.url).scheme
        if final_scheme == "https" and parsed.scheme == "http":
            redirects_to_https = True
        served_over_https = final_scheme == "https"

    hsts_present = "strict-transport-security" in resp.headers

    for cookie in resp.cookies:
        c = CookieFinding(
            name=cookie.name,
            domain=cookie.domain or parsed.netloc,
            secure=bool(cookie.secure),
            httponly=("HttpOnly" in cookie._rest) if hasattr(cookie, "_rest") else None,
            samesite=cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None,
            expires=cookie.expires,
            path=cookie.path or "/",
        )
        c.evaluate(served_over_https=served_over_https)
        findings.append(c)

    # Site-level notes, printed separately by the caller
    scan_url.site_notes = {
        "served_over_https": served_over_https,
        "redirects_to_https": redirects_to_https,
        "hsts_present": hsts_present,
    }

    return findings


# ---------------------------------------------------------------------------
# Mode 2: Cookie file scan (Netscape format or JSON export)
# ---------------------------------------------------------------------------

def scan_netscape_file(path: str) -> list:
    findings = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            domain, _flag, cookie_path, secure_flag, expiry, name, _value = parts[:7]
            is_httponly = domain.startswith("#HttpOnly_")
            display_domain = domain[len("#HttpOnly_"):] if is_httponly else domain
            c = CookieFinding(
                name=name,
                domain=display_domain,
                secure=(secure_flag.upper() == "TRUE"),
                httponly=is_httponly,
                samesite=None,  # Netscape format predates SameSite
                expires=float(expiry) if expiry and expiry != "0" else None,
                path=cookie_path,
            )
            c.evaluate(served_over_https=True)
            findings.append(c)
    return findings


def parse_relaxed_object_list(text: str) -> list:
    """Parse the loose, unquoted-key JS-object-literal format some browser
    extensions produce when you 'copy as object' from DevTools, e.g.:
        [{ domain: example.com, httpOnly: true, name: foo, ... }]
    This is not valid JSON (bare keys and bare string values), so we parse
    each { ... } block line by line instead of using json.loads."""
    objects = re.findall(r"\{(.*?)\}", text, re.DOTALL)
    cookies = []
    for obj_text in objects:
        entry = {}
        for line in obj_text.split("\n"):
            line = line.strip().rstrip(",")
            if not line:
                continue
            m = re.match(r"^(\w+)\s*:\s*(.*)$", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            elif val.startswith("'") and val.endswith("'"):
                val = val[1:-1]
            elif val.lower() == "true":
                val = True
            elif val.lower() == "false":
                val = False
            elif val.lower() == "null":
                val = None
            else:
                try:
                    val = float(val) if "." in val else int(val)
                except ValueError:
                    pass  # leave as a bare string (domain names, cookie names/values, etc.)
            entry[key] = val
        if entry:
            cookies.append(entry)
    return cookies


def scan_json_file(path: str) -> list:
    findings = []
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    try:
        data = json.loads(raw)
        cookies = data if isinstance(data, list) else data.get("cookies", [])
    except json.JSONDecodeError:
        # Not strict JSON -- likely a browser "copy as object" style export
        # with unquoted keys/values. Fall back to the relaxed parser.
        cookies = parse_relaxed_object_list(raw)
    for entry in cookies:
        c = CookieFinding(
            name=entry.get("name", "unknown"),
            domain=entry.get("domain", ""),
            secure=entry.get("secure"),
            httponly=entry.get("httpOnly") or entry.get("httponly"),
            samesite=entry.get("sameSite") or entry.get("samesite"),
            expires=entry.get("expirationDate") or entry.get("expires"),
            path=entry.get("path", "/"),
        )
        c.evaluate(served_over_https=True)
        findings.append(c)
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def transport_score(site_notes: dict) -> tuple:
    """Score the site's transport-layer security separately from cookie
    flags. Returns (score, list_of_issues)."""
    score = 100
    issues = []
    if not site_notes["served_over_https"]:
        issues.append("Final response was not served over HTTPS at all.")
        score -= 50
    if not site_notes["hsts_present"]:
        issues.append(
            "No Strict-Transport-Security (HSTS) header -- the site does not "
            "instruct browsers to refuse future HTTP connections, leaving a "
            "window for SSL-stripping / downgrade attacks on the first "
            "request or on old http:// links."
        )
        score -= 30
    return max(score, 0), issues


def print_report(findings: list, site_notes: Optional[dict] = None):
    print("=" * 70)
    print("COOKIE SECURITY AUDIT REPORT")
    print("=" * 70)

    t_score = None
    if site_notes:
        print(f"Served over HTTPS      : {site_notes['served_over_https']}")
        print(f"HTTP -> HTTPS redirect  : {site_notes['redirects_to_https']}")
        print(f"HSTS header present     : {site_notes['hsts_present']}")
        t_score, t_issues = transport_score(site_notes)
        print(f"Transport security score: {t_score}/100  [{grade(t_score)}]")
        for issue in t_issues:
            print(f"   - {issue}")
        print("-" * 70)

    if not findings:
        print("No cookies found to analyze.")
        if t_score is not None:
            print(f"\nNote: no cookies to score, but transport security is "
                  f"{grade(t_score)} ({t_score}/100) -- see above.")
        return

    total_score = 0
    for c in findings:
        print(f"\nCookie: {c.name}  (domain: {c.domain})")
        print(f"  Secure={c.secure}  HttpOnly={c.httponly}  SameSite={c.samesite}")
        print(f"  Score: {c.score}/100  [{grade(c.score)}]")
        if c.issues:
            print("  Issues found:")
            for issue in c.issues:
                print(f"   - {issue}")
        if c.notes:
            print("  Working as intended:")
            for note in c.notes:
                print(f"   - {note}")
        if not c.issues and not c.notes:
            print("   - No issues found.")
        total_score += c.score

    cookie_avg = total_score / len(findings)
    print("\n" + "-" * 70)
    print(f"Cookie-flags average score : {cookie_avg:.1f}/100  [{grade(int(cookie_avg))}]")
    if t_score is not None:
        print(f"Transport security score  : {t_score}/100  [{grade(t_score)}]")
        combined = (cookie_avg + t_score) / 2
        print(f"Combined overall score    : {combined:.1f}/100  [{grade(int(combined))}]")
    print("=" * 70)


def export_json(findings: list, out_path: str, site_notes: Optional[dict] = None):
    payload = {
        "site_notes": site_notes,
        "cookies": [
            {
                "name": c.name,
                "domain": c.domain,
                "secure": c.secure,
                "httponly": c.httponly,
                "samesite": c.samesite,
                "score": c.score,
                "grade": grade(c.score),
                "issues": c.issues,
                "notes": c.notes,
            }
            for c in findings
        ],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"\n[+] JSON report written to {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cookie Security Auditor -- audits cookie flag hygiene "
                    "(Secure/HttpOnly/SameSite/expiry/domain scope). "
                    "Defensive tool: only use on sites/data you own or are "
                    "authorized to test."
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    url_parser = sub.add_parser("url", help="Scan a live URL's Set-Cookie headers")
    url_parser.add_argument("target", help="URL to scan, e.g. https://example.com")

    file_parser = sub.add_parser("file", help="Scan an exported cookie file")
    file_parser.add_argument("path", help="Path to the cookie file")
    file_parser.add_argument(
        "--format", choices=["netscape", "json"], default="netscape",
        help="Cookie file format (default: netscape)"
    )

    parser.add_argument("--json-out", help="Also write results to this JSON file")

    args = parser.parse_args()

    site_notes = None
    if args.mode == "url":
        findings = scan_url(args.target)
        site_notes = getattr(scan_url, "site_notes", None)
    else:
        if args.format == "json":
            findings = scan_json_file(args.path)
        else:
            findings = scan_netscape_file(args.path)

    print_report(findings, site_notes)

    if args.json_out:
        export_json(findings, args.json_out, site_notes)


if __name__ == "__main__":
    main()
