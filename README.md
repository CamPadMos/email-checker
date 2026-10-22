# Email Checker — Phishing Detection Tool

**Live demo:** https://campadmos.github.io/email-checker

An explainable phishing triage tool that scores a raw email (`.eml`) from 0–100 and tells you **why** it's suspicious — combining deterministic security checks, URL reputation (VirusTotal), and an optional LLM second opinion.

Built to mirror how a SOC analyst triages a reported email: check the headers, inspect the links, look at the attachments, and then decide.

## Three ways to use it

| Version | For | Where |
|---|---|---|
| **Web app** | Anyone — paste an email or drop a `.eml` file, get a verdict in plain English or Spanish | [`docs/index.html`](docs/index.html) · [live demo](https://campadmos.github.io/email-checker) |
| **Automatic Gmail protection** | Anyone with Gmail — scans and labels new emails every 10 minutes | [`gmail-auto/Code.gs`](gmail-auto/Code.gs) (Google Apps Script web app, OAuth per user) |
| **Python CLI** | Analysts — JSON output, VirusTotal and LLM second opinion | [`analyzer.py`](analyzer.py) |

## Why I built it

Phishing is the most common entry point for breaches, especially in healthcare, where attackers impersonate insurers to steal member IDs and credentials. I wanted a tool that doesn't just say "phishing: yes/no", but shows the evidence an analyst would use to make the call.

## What it checks

| Layer | Check | Example |
|---|---|---|
| Headers | SPF / DKIM / DMARC failures | `dmarc=fail` |
| Headers | Reply-To / Return-Path mismatch | From `brand.com`, replies go to `x.xyz` |
| Identity | Display-name impersonation | "Florida Blue" sent from another domain |
| Identity | Lookalike domains (edit distance + brand-in-domain) | `floridablue-benefits.com` |
| Content | Urgency / pressure language (EN + ES) | "terminated within 24 hours" |
| Content | Requests for credentials or sensitive data | "confirm your Member ID and password" |
| Links | Deceptive link text (shown ≠ real destination) | shows `floridablue.com`, goes to an IP |
| Links | Raw IPs, URL shorteners, abused TLDs, `@` obfuscation | `bit.ly/...`, `.top` |
| Attachments | Risky file types | `.html`, `.exe`, `.iso`, `.docm` |
| Optional | VirusTotal URL reputation | malicious engine count |
| Optional | LLM second opinion (Claude API) | verdict + reasoning + recommended action |

## Responsible AI design

- **Heuristics first.** The score comes only from deterministic, auditable rules. The LLM gives a *second opinion*; it never changes the score on its own.
- **Opt-in data sharing.** Nothing leaves your machine unless you pass `--vt` or `--ai`.
- **Data minimization.** The AI layer receives a truncated body (3,000 characters), not attachments.
- **Explainability.** Every point in the score maps to a finding a human can verify.

## Automatic Gmail protection — how it works

- Deployed as a Google Apps Script web app that executes as **the user accessing it**, so each person authorizes only their own account and the developer never sees anyone's email.
- A time-based trigger scans new inbox threads every 10 minutes and adds the labels `Email Checker/Phishing` or `Email Checker/Suspicious`. It never deletes anything; moving phishing to Spam is opt-in.
- Users can turn it on or off from a simple page and revoke access anytime at myaccount.google.com → Security.

## Quick start (Python CLI)

```bash
pip install -r requirements.txt
python analyzer.py samples/phish_benefits.eml       # heuristics only
python analyzer.py samples/legit_newsletter.eml     # should score 0

# Optional layers
export VT_API_KEY=...          # free key at virustotal.com
export ANTHROPIC_API_KEY=...
python analyzer.py samples/phish_benefits.eml --vt --ai

python analyzer.py samples/phish_benefits.eml --json   # for SIEM / automation
```

Exit codes: `0` likely safe, `1` suspicious, `2` phishing, so it can be scripted into a pipeline.

## Sample output

```
  Score   : ████████████████████ 100/100
  Verdict : PHISHING — do not interact
  [HIGH  ] Lookalike domain
           Sender domain 'floridablue-benefits.com' imitates 'floridablue.com'.
  [HIGH  ] Deceptive link text
           Link shows 'www.floridablue.com' but goes to '185.22.14.7'.
  [HIGH  ] Risky attachment
           Attachment 'Claim_Statement.html' has a risky extension (.html).
  ...
```

## Scoring

High = 30 pts · Medium = 15 · Low = 5 (capped at 100)
`≥ 60` Phishing · `25–59` Suspicious · `< 25` Likely safe

## Roadmap

- [ ] Test against a public phishing corpus and report precision / recall
- [ ] Attachment hashing + VirusTotal file lookup
- [ ] Simple web UI for non-technical users
- [ ] Map findings to MITRE ATT&CK (T1566 – Phishing)

## Note

The sample emails are synthetic and built for testing. The brand names are used only to demonstrate impersonation detection.
