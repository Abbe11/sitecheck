import sys, requests
from urllib.parse import urlparse
G, Y, R, B, DIM, END = "\033[92m","\033[93m","\033[91m","\033[96m","\033[2m","\033[0m"
def ok(s):   return f"{G}PASS{END}  {s}"
def warn(s): return f"{Y}WARN{END}  {s}"
def bad(s):  return f"{R}FAIL{END}  {s}"
def normalize(u):
    return u if u.startswith(("http://","https://")) else "https://"+u
def check(url):
    url = normalize(url); host = urlparse(url).netloc
    print(f"\n{B}=== Security checkup for {host} ==={END}")
    print(f"{DIM}(reading public response headers only -- no attacks performed){END}\n")
    f = []
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.SSLError:
        f.append((2, bad("HTTPS certificate problem -- the padlock is broken."))); report(f); return
    except Exception as e:
        print(bad(f"Could not reach {host}: {e}")); return
    f.append((0, ok("Served over HTTPS (encrypted).")) if urlparse(r.url).scheme=="https"
             else (2, bad("NOT using HTTPS -- data travels in cleartext.")))
    try:
        hr = requests.get("http://"+host, timeout=10, allow_redirects=True)
        f.append((0, ok("Plain http:// redirects to https://.")) if urlparse(hr.url).scheme=="https"
                 else (2, bad("Plain http:// does NOT redirect to https://.")))
    except Exception:
        f.append((1, warn("Couldn't test the http-to-https redirect.")))
    h = {k.lower(): v for k, v in r.headers.items()}
    checks = [("strict-transport-security","HSTS","forces browsers to always use HTTPS"),
              ("content-security-policy","Content-Security-Policy","the strongest defense against XSS"),
              ("x-frame-options","X-Frame-Options","stops clickjacking"),
              ("x-content-type-options","X-Content-Type-Options","stops file-type mis-guessing (XSS vector)"),
              ("referrer-policy","Referrer-Policy","stops leaking where users came from")]
    for key, name, why in checks:
        if key in h: f.append((0, ok(f"{name} present -- {why}.")))
        else:
            sev = 2 if key=="content-security-policy" else 1
            f.append((sev, (bad if sev==2 else warn)(f"Missing {name} -- {why}.")))
    sc = r.headers.get("set-cookie")
    if sc:
        low = sc.lower()
        f.append((0, ok("Cookies HttpOnly -- XSS cannot steal the session.")) if "httponly" in low
                 else (2, bad("Cookie NOT HttpOnly -- an XSS bug could steal the session.")))
        f.append((0, ok("Cookies Secure.")) if "secure" in low else (1, warn("Cookie not Secure.")))
        f.append((0, ok("Cookies use SameSite (anti-CSRF).")) if "samesite" in low else (1, warn("No SameSite on cookie.")))
    else:
        f.append((1, warn("No cookies set on homepage (nothing to check).")))
    for leak in ("server","x-powered-by"):
        if leak in h and any(c.isdigit() for c in h[leak]):
            f.append((1, warn(f"'{leak}: {h[leak]}' leaks software versions -- helps attackers find exploits.")))
    report(f)
def report(f):
    print()
    for sev, msg in f: print("  "+msg)
    p=sum(1 for s,_ in f if s==0); w=sum(1 for s,_ in f if s==1); b=sum(1 for s,_ in f if s==2)
    print(f"\n{B}Summary:{END} {G}{p} good{END}, {Y}{w} to review{END}, {R}{b} important{END}")
    print(f"\n{DIM}Only run active security tools on sites you own or may test.{END}\n")
if __name__=="__main__":
    if len(sys.argv)!=2: print("Usage: python sitecheck.py <domain-or-url>"); sys.exit(1)
    check(sys.argv[1])
