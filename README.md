# Cookie Security Auditor

A defensive security tool that audits cookie configuration for common
weaknesses — the same weaknesses that enable session hijacking, XSS-based
cookie theft, and CSRF attacks.

## What it does

Given a live URL or an exported cookie file, it checks each cookie against:

| Check | Attack it defends against | What happens if it's missing |
|---|---|---|
| `Secure` flag | Network sniffing / MITM | Cookie can be sent over plain HTTP and read straight out of the packet (e.g. in Wireshark) by anyone on the same network |
| `HttpOnly` flag | XSS (Cross-Site Scripting) | Any injected JavaScript on the page can read the cookie via `document.cookie` and send it to an attacker's server |
| `SameSite` attribute | CSRF (Cross-Site Request Forgery) | A malicious page in another tab can trigger requests to the site, and the browser still attaches the cookie, letting the attacker act as the victim |
| Expiry length | Session hijacking (damage window) | A long-lived session/auth cookie gives a stolen cookie a longer window to be exploited |
| Domain scope | Subdomain takeover / cross-subdomain leakage | A broad `.example.com`-style domain sends the cookie to every subdomain, including any that are later abandoned or compromised |
| HSTS header | SSL stripping / downgrade | Without it, a browser's first request (or an old `http://` link) can be intercepted and kept on plain HTTP by an attacker in the middle |

Each cookie gets its own 0–100 score and letter grade, plus a site-wide
**transport security score** (HTTPS + HSTS) reported separately and then
combined into an overall grade — so a perfectly configured cookie on a site
missing HSTS won't show as a false 100/100.

For every check, the report explicitly names the attack class it defends
against — both when a flag is **missing** (what attack becomes possible) and
when it's **set correctly** (what it's actually blocking). This is meant to
double as a learning reference, not just a pass/fail score.

## Usage

```bash
# Scan a live site's Set-Cookie headers (only scan sites you own or are
# authorized to test)
python3 cookie_auditor.py url https://example.com

# Scan a cookie export (Netscape format, e.g. from a browser extension)
python3 cookie_auditor.py file cookies.txt

# Scan a JSON cookie export
python3 cookie_auditor.py file cookies.json --format json

# Also save a machine-readable report
python3 cookie_auditor.py --json-out report.json url https://example.com
```

## Example output

```
Transport security score: 70/100  [C]
   - No Strict-Transport-Security (HSTS) header -- the site does not
     instruct browsers to refuse future HTTP connections, leaving a
     window for SSL-stripping / downgrade attacks...

Cookie: PHPSESSID  (domain: example.com)
  Secure=True  HttpOnly=True  SameSite=Strict
  Score: 100/100  [A]
  Working as intended:
   - [Defends against: Network sniffing / MITM] 'Secure' flag is set...
   - [Defends against: XSS cookie theft] 'HttpOnly' flag is set...
   - [Defends against: CSRF] SameSite=Strict...

Cookie: auth_token  (domain: example.com)
  Secure=False  HttpOnly=False  SameSite=None
  Score: 5/100  [F]
  Issues found:
   - [Attack: Network sniffing / MITM] Missing 'Secure' flag...
   - [Attack: XSS (Cross-Site Scripting)] Missing 'HttpOnly' flag...
   - [Attack: CSRF (Cross-Site Request Forgery)] SameSite is missing...

Cookie-flags average score : 52.5/100  [D]
Transport security score  : 20/100  [F]
Combined overall score    : 36.2/100  [F]
```

## Why this exists

Session cookie theft (via XSS, unencrypted traffic, or local malware) is one
of the most common real-world attack vectors — stolen cookies can grant full
account access without needing a password at all. This tool flips that
attack surface into a checklist: point it at your own site or app during
development/code review and catch missing cookie protections before they
ship.

## Scope and ethics

This is a **read-only auditing tool**. It does not collect, exfiltrate, or
transmit cookie values anywhere — it only inspects cookie *attributes*
(flags/metadata) and reports locally. Only run the `url` mode against sites
you own or have explicit authorization to test.

## Requirements

- Python 3.8+
- `requests`

```bash
pip install requests
```
