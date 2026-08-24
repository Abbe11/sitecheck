#!/usr/bin/env python3
import sys, html, datetime, requests
from urllib.parse import urlparse

def normalize(u):
    return u if u.startswith(("http://", "https://")) else "https://" + u

FIX = {
 "csp": ("Content-Security-Policy", "The strongest defense against cross-site scripting (XSS). It limits which scripts a page is allowed to run.",
   "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
   "Add via your server or host. On Vercel, put it in vercel.json headers. Test after adding -- a strict policy can block legitimate scripts, so tune it."),
 "xfo": ("X-Frame-Options", "Stops clickjacking -- your site being loaded invisibly inside an attacker page to trick your users.",
   "X-Frame-Options: DENY", "Add this response header on every page."),
 "xcto": ("X-Content-Type-Options", "Stops the browser guessing file types, which can be abused to smuggle in scripts.",
   "X-Content-Type-Options: nosniff", "Add this response header globally."),
 "ref": ("Referrer-Policy", "Stops leaking which page a visitor came from to third-party sites.",
   "Referrer-Policy: strict-origin-when-cross-origin", "Add this response header globally."),
 "hsts": ("Strict-Transport-Security", "Forces browsers to always use HTTPS, blocking downgrade attacks.",
   "Strict-Transport-Security: max-age=31536000; includeSubDomains", "Add only once HTTPS works everywhere on the site."),
}

def check(url):
    url = normalize(url); host = urlparse(url).netloc
    findings = []
    try:
        r = requests.get(url, timeout=12, allow_redirects=True)
    except requests.exceptions.SSLError:
        findings.append((2, None, "HTTPS certificate problem", "The padlock is broken -- traffic may not be safely encrypted."))
        return host, findings
    except Exception as e:
        findings.append((2, None, "Could not reach the site", str(e)))
        return host, findings
    if urlparse(r.url).scheme == "https":
        findings.append((0, None, "HTTPS is on", "Traffic is encrypted in transit."))
    else:
        findings.append((2, None, "No HTTPS", "The site is not using HTTPS -- data travels in cleartext."))
    try:
        hr = requests.get("http://" + host, timeout=12, allow_redirects=True)
        if urlparse(hr.url).scheme == "https":
            findings.append((0, None, "http redirects to https", "Visitors are auto-upgraded to a secure connection."))
        else:
            findings.append((2, None, "No http to https redirect", "Visitors can be downgraded to an unencrypted connection."))
    except Exception:
        findings.append((1, None, "Redirect not tested", "Could not test the http-to-https redirect."))
    h = {k.lower(): v for k, v in r.headers.items()}
    hmap = {"hsts":"strict-transport-security","csp":"content-security-policy",
            "xfo":"x-frame-options","xcto":"x-content-type-options","ref":"referrer-policy"}
    for cid, present_sev in [("hsts",1),("csp",2),("xfo",1),("xcto",1),("ref",1)]:
        name, why, _, _ = FIX[cid]
        if hmap[cid] in h:
            findings.append((0, None, name + " present", why))
        else:
            findings.append((present_sev, cid, "Missing " + name, why))
    sc = r.headers.get("set-cookie")
    if sc:
        low = sc.lower()
        findings.append((0, None, "Cookies are HttpOnly", "JavaScript (an XSS bug) cannot steal the session cookie.") if "httponly" in low
                        else (2, "cookie", "Cookie is not HttpOnly", "An XSS bug could steal the login session cookie."))
        if "secure" not in low:
            findings.append((1, None, "Cookie not marked Secure", "It could leak over an unencrypted connection."))
    for leak in ("server", "x-powered-by"):
        if leak in h and any(c.isdigit() for c in h[leak]):
            findings.append((1, None, "Version disclosure", "'%s: %s' leaks exact software versions, helping attackers look up known exploits." % (leak, h[leak])))
    return host, findings

def grade_for(findings):
    imp = sum(1 for s,r_ in [(f[0],0) for f in findings] if s == 2)
    rev = sum(1 for f in findings if f[0] == 1)
    imp = sum(1 for f in findings if f[0] == 2)
    penalty = 3*imp + rev
    if penalty == 0:   g = "A"
    elif penalty <= 2: g = "B"
    elif penalty <= 4: g = "C"
    elif penalty <= 7: g = "D"
    else:              g = "F"
    verdict = {"A":"Strong posture","B":"Solid, minor gaps","C":"Needs attention",
               "D":"Several gaps to close","F":"Serious gaps"}[g]
    color = {"A":"var(--pass)","B":"var(--pass)","C":"var(--review)","D":"var(--warn)","F":"var(--crit)"}[g]
    return g, verdict, color

CSS = r"""
:root{
  --paper:#eaece7; --card:#ffffff; --ink:#1b1e1b; --muted:#5b625a;
  --line:#d6dbd3; --rule:#c2c9bd; --accent:#1c34c4;
  --pass:#2e7d57; --review:#b07a16; --warn:#c4622a; --crit:#b23a28;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:"IBM Plex Sans",system-ui,-apple-system,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:720px;margin:0 auto;padding:48px 22px 72px}
.eyebrow{font-family:"IBM Plex Mono",monospace;font-size:12px;letter-spacing:.24em;
  text-transform:uppercase;color:var(--accent);display:flex;align-items:center;gap:12px}
.eyebrow::after{content:"";height:1px;flex:1;background:var(--rule)}
.target{font-family:"IBM Plex Mono",monospace;font-size:clamp(21px,5vw,30px);font-weight:600;
  margin:16px 0 4px;word-break:break-all;line-height:1.15}
.scanmeta{color:var(--muted);font-size:12.5px;font-family:"IBM Plex Mono",monospace}
.gradecard{display:flex;gap:22px;align-items:center;margin:32px 0 4px;
  background:var(--card);border:1px solid var(--line);border-radius:5px;padding:22px 24px}
.grade{font-family:"IBM Plex Mono",monospace;font-weight:700;font-size:58px;line-height:1;color:#fff;
  width:104px;height:104px;flex:none;display:grid;place-items:center;border-radius:5px}
.gv b{font-size:18px;font-weight:600}
.gv p{margin:3px 0 0;color:var(--muted);font-size:13.5px}
.tallies{display:flex;gap:8px;margin-top:13px;flex-wrap:wrap}
.tally{font-family:"IBM Plex Mono",monospace;font-size:12.5px;font-weight:600;
  border:1px solid var(--line);border-radius:3px;padding:4px 9px;display:flex;gap:7px;align-items:center;
  font-variant-numeric:tabular-nums}
.dot{width:8px;height:8px;border-radius:50%;flex:none}
.slabel{font-family:"IBM Plex Mono",monospace;font-size:11.5px;letter-spacing:.2em;
  text-transform:uppercase;color:var(--muted);margin:38px 0 13px}
.finding{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--line);
  border-radius:4px;padding:15px 17px;margin:0 0 9px}
.fhead{display:flex;align-items:center;gap:11px}
.sev{font-family:"IBM Plex Mono",monospace;font-size:10px;font-weight:700;letter-spacing:.08em;
  color:#fff;padding:3px 7px;border-radius:3px;flex:none}
.finding h3{font-size:15.5px;margin:0;font-weight:600}
.finding p{margin:8px 0 0;color:var(--muted);font-size:14px;line-height:1.55}
.fix{margin-top:12px;border-top:1px dashed var(--line);padding-top:11px}
.flabel{font-family:"IBM Plex Mono",monospace;font-size:10.5px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--accent)}
.fix pre{font-family:"IBM Plex Mono",monospace;font-size:12.5px;background:var(--ink);color:#e9efe6;
  border-radius:4px;padding:11px 13px;overflow-x:auto;margin:7px 0 6px;line-height:1.5}
.fix small{color:var(--muted);font-size:13px;line-height:1.5;display:block}
footer{margin-top:34px;border-top:1px solid var(--rule);padding-top:15px;color:var(--muted);
  font-size:12px;font-family:"IBM Plex Mono",monospace;line-height:1.65}
"""

SEV = {0:("var(--pass)","PASS"), 1:("var(--review)","REVIEW"), 2:("var(--crit)","ACTION")}

def finding_html(sev, cid, title, detail):
    color, tag = SEV[sev]
    fix = ""
    if cid and cid in FIX:
        _,_,snip,howto = FIX[cid]
        fix = ('<div class="fix"><span class="flabel">How to fix</span>'
               '<pre>%s</pre><small>%s</small></div>' % (html.escape(snip), html.escape(howto)))
    return ('<div class="finding" style="border-left-color:%s">'
            '<div class="fhead"><span class="sev" style="background:%s">%s</span>'
            '<h3>%s</h3></div><p>%s</p>%s</div>'
            % (color, color, tag, html.escape(title), html.escape(detail), fix))

def build_report(host, findings):
    imp = sum(1 for f in findings if f[0] == 2)
    rev = sum(1 for f in findings if f[0] == 1)
    good = sum(1 for f in findings if f[0] == 0)
    g, verdict, gcolor = grade_for(findings)
    when = datetime.datetime.now().strftime("%d %b %Y - %H:%M")
    action = sorted([f for f in findings if f[0] > 0], key=lambda x: -x[0])
    passing = [f for f in findings if f[0] == 0]
    action_html = "".join(finding_html(*f) for f in action) or (
        '<div class="finding" style="border-left-color:var(--pass)"><div class="fhead">'
        '<span class="sev" style="background:var(--pass)">CLEAR</span><h3>Nothing to action</h3></div>'
        '<p>All checked defenses are in place.</p></div>')
    passing_html = "".join(finding_html(*f) for f in passing)
    return (
      '<!doctype html><html lang="en"><head><meta charset="utf-8">'
      '<meta name="viewport" content="width=device-width,initial-scale=1">'
      '<title>Security Report Card</title>'
      '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
      'family=IBM+Plex+Mono:wght@500;600;700&family=IBM+Plex+Sans:wght@400;600;700&display=swap">'
      '<style>' + CSS + '</style></head><body><div class="wrap">'
      '<div class="eyebrow">Security Audit &nbsp;/&nbsp; response headers</div>'
      '<div class="target">' + html.escape(host) + '</div>'
      '<div class="scanmeta">Scanned ' + when + ' &middot; non-invasive &middot; no attacks performed</div>'
      '<div class="gradecard"><div class="grade" style="background:' + gcolor + '">' + g + '</div>'
      '<div class="gv"><b>' + verdict + '</b><p>Grade based on the weight of what is missing.</p>'
      '<div class="tallies">'
      '<span class="tally"><span class="dot" style="background:var(--crit)"></span>' + str(imp) + ' action</span>'
      '<span class="tally"><span class="dot" style="background:var(--review)"></span>' + str(rev) + ' review</span>'
      '<span class="tally"><span class="dot" style="background:var(--pass)"></span>' + str(good) + ' passing</span>'
      '</div></div></div>'
      '<div class="slabel">Needs attention</div>' + action_html +
      '<div class="slabel">Passing checks</div>' + passing_html +
      '<footer>SiteCheck v2 &middot; reads public response headers only, like your browser does.<br>'
      'This grades technical header hygiene, not whether a site is trustworthy. '
      'Only run active security tools on sites you own or have permission to test.</footer>'
      '</div></body></html>')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sitecheck_v2.py <domain-or-url>"); sys.exit(1)
    host, findings = check(sys.argv[1])
    with open(host.replace(":", "_") + "-report.html", "w", encoding="utf-8") as f:
        f.write(build_report(host, findings))
    g,_,_ = grade_for(findings)
    print("Grade " + g + " -- report written to " + host.replace(":", "_") + "-report.html")
