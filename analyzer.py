#!/usr/bin/env python3
"""
Phishing Email Analyzer
-----------------------
Analyzes a raw email (.eml) and produces a risk score with explainable findings.

Layers:
  1. Deterministic heuristics (always on, no data leaves your machine)
  2. VirusTotal URL reputation (optional, --vt, needs VT_API_KEY)
  3. LLM second opinion (optional, --ai, needs ANTHROPIC_API_KEY)

Usage:
  python analyzer.py samples/phish_benefits.eml
  python analyzer.py samples/phish_benefits.eml --ai --vt
  python analyzer.py samples/phish_benefits.eml --json
"""

import argparse
import base64
import email
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from email import policy
from html.parser import HTMLParser
from urllib.parse import urlparse

# ---------------------------------------------------------------- config ---

KNOWN_BRANDS = [
    "floridablue.com", "microsoft.com", "office365.com", "google.com",
    "paypal.com", "amazon.com", "apple.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "docusign.com", "linkedin.com", "outlook.com",
]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}

RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk",
              "ml", "cf", "work", "rest", "support"}

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso",
                    ".img", ".html", ".htm", ".hta", ".lnk", ".docm",
                    ".xlsm", ".zip", ".rar", ".7z"}

URGENCY_PATTERNS = [
    r"urgent", r"immediately", r"within 24 hours", r"account (will be )?(suspended|locked|closed)",
    r"verify your (account|identity|information)", r"unusual (sign-in|activity)",
    r"final notice", r"action required", r"confirm your password",
    r"your (benefits|coverage) (will|may) (be )?(terminated|cancel)",
    # Spanish
    r"urgente", r"inmediatamente", r"cuenta (será )?(suspendida|bloqueada)",
    r"verifique su (cuenta|identidad)", r"acción requerida",
]

SEVERITY_POINTS = {"low": 5, "medium": 15, "high": 30}


# ---------------------------------------------------------------- models ---

@dataclass
class Finding:
    check: str
    severity: str  # low | medium | high
    detail: str


@dataclass
class Report:
    subject: str
    sender: str
    score: int = 0
    verdict: str = ""
    findings: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    virustotal: dict = field(default_factory=dict)
    ai_opinion: dict = field(default_factory=dict)


# --------------------------------------------------------------- helpers ---

class LinkExtractor(HTMLParser):
    """Collects (href, visible_text) pairs from HTML bodies."""

    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(address: str) -> str:
    m = re.search(r"@([\w.-]+)", address or "")
    return m.group(1).lower() if m else ""


def root_domain(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str):
    """Returns the brand a domain imitates, or None."""
    d = root_domain(domain)
    for brand in KNOWN_BRANDS:
        if d == brand:
            return None
        brand_name = brand.split(".")[0]
        if 0 < levenshtein(d, brand) <= 2:
            return brand
        if brand_name in d and d != brand:  # e.g. floridablue-benefits.com
            return brand
    return None


def get_bodies(msg):
    text, html = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/plain":
            text += content
        elif ctype == "text/html":
            html += content
    return text, html


# ---------------------------------------------------------------- checks ---

def analyze(msg) -> Report:
    sender = str(msg.get("From", ""))
    report = Report(subject=str(msg.get("Subject", "")), sender=sender)
    add = lambda c, s, d: report.findings.append(Finding(c, s, d))

    from_domain = domain_of(sender)
    display_name = sender.split("<")[0].strip().strip('"').lower()

    # 1. Authentication results (SPF / DKIM / DMARC)
    auth = str(msg.get("Authentication-Results", "")).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m and m.group(1) in ("fail", "softfail", "none", "permerror"):
            add("Email authentication", "high",
                f"{mech.upper()} result is '{m.group(1)}' — sender may be spoofed.")
    if not auth:
        add("Email authentication", "low", "No Authentication-Results header present.")

    # 2. Reply-To / Return-Path mismatch
    for hdr in ("Reply-To", "Return-Path"):
        other = domain_of(str(msg.get(hdr, "")))
        if other and root_domain(other) != root_domain(from_domain):
            add(f"{hdr} mismatch", "medium",
                f"{hdr} domain '{other}' differs from From domain '{from_domain}'.")

    # 3. Display-name impersonation
    for brand in KNOWN_BRANDS:
        name = brand.split(".")[0]
        if name in display_name.replace(" ", "") and root_domain(from_domain) != brand:
            add("Display-name impersonation", "high",
                f"Display name mentions '{name}' but mail comes from '{from_domain}'.")
            break

    # 4. Lookalike sender domain
    brand = lookalike_of(from_domain)
    if brand:
        add("Lookalike domain", "high", f"Sender domain '{from_domain}' imitates '{brand}'.")

    # 5. Body content
    text, html = get_bodies(msg)
    combined = f"{report.subject}\n{text}\n{re.sub('<[^>]+>', ' ', html)}".lower()
    hits = sorted({p for p in URGENCY_PATTERNS if re.search(p, combined)})
    if hits:
        add("Urgency / pressure language", "medium" if len(hits) < 3 else "high",
            f"{len(hits)} pressure phrase(s) matched: {', '.join(hits[:4])}")
    if re.search(r"(password|ssn|social security|member id|credit card|routing number)", combined):
        add("Requests sensitive data", "high",
            "Email asks about credentials or sensitive personal data.")

    # 6. URLs
    parser = LinkExtractor()
    parser.feed(html)
    raw_urls = set(re.findall(r"https?://[^\s\"'<>)]+", text + " " + html))
    raw_urls |= {h for h, _ in parser.links if h and h.startswith("http")}
    report.urls = sorted(raw_urls)

    for href, visible in parser.links:
        shown = re.search(r"([\w-]+\.)+[a-z]{2,}", visible or "")
        real = urlparse(href or "").hostname or ""
        if shown and real and root_domain(shown.group(0)) != root_domain(real):
            add("Deceptive link text", "high",
                f"Link shows '{shown.group(0)}' but goes to '{real}'.")

    for url in report.urls:
        host = (urlparse(url).hostname or "").lower()
        if re.fullmatch(r"[\d.]+", host):
            add("Raw IP link", "high", f"Link points to an IP address: {host}")
        if host in URL_SHORTENERS:
            add("URL shortener", "medium", f"Shortened link hides destination: {url}")
        if host.split(".")[-1] in RISKY_TLDS:
            add("Risky TLD", "medium", f"Uncommon/abused top-level domain: {host}")
        if lookalike_of(host):
            add("Lookalike link domain", "high", f"Link domain '{host}' imitates '{lookalike_of(host)}'.")
        if "@" in urlparse(url).netloc:
            add("Obfuscated URL", "high", f"URL contains '@' to disguise destination: {url}")

    # 7. Attachments
    for part in msg.walk():
        fname = part.get_filename()
        if fname:
            report.attachments.append(fname)
            ext = os.path.splitext(fname.lower())[1]
            if ext in RISKY_EXTENSIONS:
                add("Risky attachment", "high", f"Attachment '{fname}' has a risky extension ({ext}).")

    # Score & verdict (deduplicate same check+detail)
    unique = {(f.check, f.detail): f for f in report.findings}
    report.findings = list(unique.values())
    report.score = min(100, sum(SEVERITY_POINTS[f.severity] for f in report.findings))
    report.verdict = ("PHISHING — do not interact" if report.score >= 60 else
                      "SUSPICIOUS — verify through another channel" if report.score >= 25 else
                      "LIKELY SAFE — no strong indicators")
    return report


# ------------------------------------------------------ optional: VT -------

def virustotal_lookup(urls, api_key):
    import requests
    results = {}
    for url in urls[:4]:  # free tier: 4 req/min
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers={"x-apikey": api_key}, timeout=15)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                results[url] = {"malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0)}
            else:
                results[url] = {"error": f"HTTP {r.status_code} (not yet scanned?)"}
        except Exception as e:
            results[url] = {"error": str(e)}
    return results


# ------------------------------------------------------ optional: AI -------

AI_PROMPT = """You are a SOC analyst assistant. Review this email and the automated findings.
Respond ONLY with JSON, no markdown:
{{"verdict": "phishing|suspicious|legitimate", "confidence": 0-100,
  "reasoning": "2-3 sentences", "recommended_action": "one sentence"}}

Automated findings: {findings}
Subject: {subject}
From: {sender}
Body (truncated):
{body}"""


def ai_second_opinion(report, body, api_key):
    import requests
    prompt = AI_PROMPT.format(
        findings=json.dumps([asdict(f) for f in report.findings]),
        subject=report.subject, sender=report.sender, body=body[:3000])
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": os.getenv("ANALYZER_MODEL", "claude-haiku-5-5"),
              "max_tokens": 400,
              "messages": [{"role": "user", "content": prompt}]},
        timeout=60)
    r.raise_for_status()
    text = "".join(b.get("text", "") for b in r.json()["content"])
    return json.loads(re.sub(r"```(json)?", "", text).strip())


# ----------------------------------------------------------------- output --

def print_report(rep: Report):
    bar = "█" * (rep.score // 5) + "░" * (20 - rep.score // 5)
    print(f"\n{'=' * 64}\n  PHISHING ANALYSIS REPORT\n{'=' * 64}")
    print(f"  Subject : {rep.subject}\n  From    : {rep.sender}")
    print(f"  Score   : {bar} {rep.score}/100\n  Verdict : {rep.verdict}\n{'-' * 64}")
    order = {"high": 0, "medium": 1, "low": 2}
    for f in sorted(rep.findings, key=lambda f: order[f.severity]):
        print(f"  [{f.severity.upper():6}] {f.check}\n           {f.detail}")
    if not rep.findings:
        print("  No indicators found.")
    if rep.urls:
        print(f"{'-' * 64}\n  URLs found ({len(rep.urls)}):")
        for u in rep.urls:
            print(f"    - {u}")
    if rep.attachments:
        print(f"  Attachments: {', '.join(rep.attachments)}")
    if rep.virustotal:
        print(f"{'-' * 64}\n  VirusTotal:")
        for u, res in rep.virustotal.items():
            print(f"    {u}\n      {res}")
    if rep.ai_opinion:
        a = rep.ai_opinion
        conf = f" ({a['confidence']}% confident)" if a.get("confidence") is not None else ""
        print(f"{'-' * 64}\n  AI second opinion{conf}: {a.get('verdict')}")
        print(f"    {a.get('reasoning')}")
        if a.get("recommended_action"):
            print(f"    Action: {a['recommended_action']}")
    print("=" * 64 + "\n")


def main():
    ap = argparse.ArgumentParser(description="Explainable phishing email analyzer")
    ap.add_argument("eml", help="Path to a raw .eml file")
    ap.add_argument("--vt", action="store_true", help="Check URLs on VirusTotal (VT_API_KEY)")
    ap.add_argument("--ai", action="store_true", help="LLM second opinion (ANTHROPIC_API_KEY)")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = ap.parse_args()

    with open(args.eml, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)
    rep = analyze(msg)

    if args.vt:
        key = os.getenv("VT_API_KEY")
        rep.virustotal = virustotal_lookup(rep.urls, key) if key else {"error": "VT_API_KEY not set"}
    if args.ai:
        key = os.getenv("ANTHROPIC_API_KEY")
        if key:
            try:
                text, html = get_bodies(msg)
                rep.ai_opinion = ai_second_opinion(rep, text or re.sub("<[^>]+>", " ", html), key)
            except Exception as e:
                rep.ai_opinion = {"verdict": "error", "reasoning": str(e)}
        else:
            rep.ai_opinion = {"verdict": "skipped", "reasoning": "ANTHROPIC_API_KEY not set"}

    if args.json:
        out = asdict(rep)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_report(rep)
    sys.exit(2 if rep.score >= 60 else 1 if rep.score >= 25 else 0)


if __name__ == "__main__":
    main()
