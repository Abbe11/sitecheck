# sitecheck

A friendly, non-invasive website security checker, plus a few browser-based security learning tools I built alongside it.

## sitecheck.py

Point it at a website and it checks the basics that are visible to any visitor, without attacking anything:

- whether the site uses HTTPS and whether the certificate is valid
- whether plain `http://` redirects to `https://`
- which security headers are present or missing (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security)

It gives the site a grade and writes an HTML report explaining each missing header in plain language, with the exact header to add.

```
pip install requests
python sitecheck.py example.com
```

The report is saved as `<host>-report.html` in the current folder.

Only run it against sites you own or have permission to test. It sends normal page requests, but it is still your responsibility.

## Browser tools

These are single HTML files. Open them directly in a browser, no install needed.

| File | What it does |
|---|---|
| `log-detective.html` | Paste log lines and it highlights signs of an attack |
| `passlab.html` | Estimates how long a password would survive a guessing attack |
| `scam-shield-kenya.html` | Helps people spot common Kenyan phone and M-Pesa scams |
| `webvuln-lab.html` | Shows the same web attack against a vulnerable and a protected version side by side |

## License

MIT
