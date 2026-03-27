# arpa-phish-detect

> A focused, explainable phishing detection prototype targeting abuse of the `.arpa` top-level domain as phishing delivery infrastructure.

**Based on:** Infoblox Threat Intel research, February 2026  
**Author:** Rami Jamal Aldine  
**Stack:** Python 3.11+ · Streamlit · stdlib-only core  

---

## 🎯 Problem Statement

The `.arpa` top-level domain is reserved exclusively for internet DNS infrastructure — specifically for reverse DNS lookups (PTR records). It was never designed to host web content. Yet threat actors have discovered that because `.arpa` carries an **implicitly trusted reputation**, security tools consistently fail to scrutinize it.

**The attack chain (documented Feb 2026):**

```
1. Attacker acquires free IPv6 /64 block via tunnel service (e.g., Hurricane Electric)
2. Gains administrative delegation over corresponding ip6.arpa subdomain
3. Delegates that .arpa zone to a third-party DNS provider (e.g., Cloudflare)
4. Creates A records (NOT PTR records) pointing to CDN/phishing infrastructure
5. Prepends randomly-generated DGA prefix → unique FQDN per victim
6. Embeds FQDN in phishing email as hidden hyperlink behind an image
7. Victim clicks image → TDS fingerprints traffic → delivers phishing page
```

**Why traditional defenses fail:**

| Defense Mechanism | Why It Fails |
|---|---|
| URL reputation / blocklists | `.arpa` has implicitly clean reputation; new FQDNs aren't in blocklists |
| WHOIS / registration checks | `.arpa` has no WHOIS data (infrastructure domain) |
| Policy denylists | `.arpa` often explicitly excluded as "trusted infrastructure" |
| Visual URL inspection | Domain hidden behind image in email; victims never see it |
| Domain age heuristics | `.arpa` zones have no "age" in the traditional sense |

**The core detection idea:** An `.arpa` domain behaving like a web endpoint (HTTP/HTTPS context, CDN resolution, email-delivered) is fundamentally anomalous. This is the signal we detect.

---

## 🏗️ Architecture

```
arpa-phish-detect/
├── detector/
│   ├── __init__.py         # Public API: analyze_url(), analyze_hostname()
│   ├── extractor.py        # Feature extraction (domain/DNS/structural features)
│   ├── scorer.py           # Rule-based scoring engine with signal explanations
│   ├── dns_utils.py        # DNS resolution + CDN IP range detection
│   └── email_parser.py     # URL/link extraction from HTML and plain-text email
├── data/
│   └── test_dataset.csv    # Labeled evaluation dataset (malicious/benign/comparison)
├── detections/
│   ├── splunk_queries.spl  # 7 SPL queries (proxy, DNS, email, composite)
│   ├── sentinel_kql.kql    # 5 KQL queries (Microsoft Sentinel)
│   └── sigma_rule.yml      # 3 Sigma rules (proxy, email, DNS anomaly)
├── app.py                  # Streamlit UI (3 tabs: URL, Email, Batch)
├── cli.py                  # CLI interface
├── evaluate.py             # Dataset evaluation + FP/FN reporting
└── requirements.txt
```

**Module responsibilities:**

- `extractor.py` — Pure feature extraction. No scoring. No I/O. Takes a URL/hostname, returns a `Features` dataclass.
- `scorer.py` — Pure scoring. No I/O. Takes `Features`, returns `ScoringResult` with every triggered signal and its rationale.
- `dns_utils.py` — Optional live DNS calls. Can be disabled for offline/batch use.
- `email_parser.py` — Extracts links from raw email HTML/plaintext. Tracks image-wrapped href links (the exact phishing delivery pattern).
- `app.py` — Streamlit UI only. All detection logic delegated to the core modules.

---

## ⚡ Quickstart

```bash
git clone https://github.com/ramialdine/arpa-phish-detect
cd arpa-phish-detect
pip install -r requirements.txt

# CLI — analyze a URL
python cli.py --url "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"

# CLI — analyze a bare hostname
python cli.py --hostname "xkzpqmwrtu.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa" --email-delivered

# CLI — parse an email file and analyze all links
python cli.py --email samples/phish.html

# CLI — with live DNS resolution (CDN check)
python cli.py --hostname "..." --dns

# CLI — JSON output (for SIEM integration)
python cli.py --url "https://..." --json

# Streamlit UI
streamlit run app.py

# Evaluate against test dataset
python evaluate.py
```

---

## 🧪 Live Infrastructure Test

This project was validated against **real attacker-replicating infrastructure** built from scratch using the exact same technique documented by Infoblox. The following documents how to reproduce this test environment.

### What We Built

A live `.arpa` domain resolving to a Cloudflare IP via A record — structurally identical to the malicious infrastructure in the Infoblox report, pointed at a safe test IP (`1.1.1.1`) instead of a phishing server.

### Step 1 — Get a Free IPv6 /64 Block (Hurricane Electric)

1. Create a free account at [tunnelbroker.net](https://tunnelbroker.net)
2. Click **"Create Regular Tunnel"**, enter your public IPv4 address, choose any server location
3. Submit — you do not need to actually configure the tunnel on your machine
4. Go to the tunnel detail page and find the **Routed /64** field — this is your IPv6 block (e.g. `2001:470:1f07:3e::/64`)

> **Note:** The Routed /64 field may show as empty immediately after tunnel creation. Wait a few minutes and refresh — HE provisions it asynchronously.

> **Important:** The Routed /64 is a *different* block from your tunnel endpoint addresses (`Client IPv6`). Always use the Routed /64 for the `.arpa` zone derivation, not the tunnel endpoint address. They differ by one nibble group and will give you the wrong zone if confused.

### Step 2 — Derive Your .arpa Zone

Take your Routed /64 prefix and reverse it nibble-by-nibble. For example, `2001:470:1f07:003e::/64`:

```
Pad to full hex:     2001 : 0470 : 1f07 : 003e
Split into nibbles:  2 0 0 1 0 4 7 0 1 f 0 7 0 0 3 e
Reverse:             e 3 0 0 7 0 f 1 0 7 4 0 1 0 0 2
Dot-separate + zone: e.3.0.0.7.0.f.1.0.7.4.0.1.0.0.2.ip6.arpa
```

That string is your `.arpa` zone. HE has already delegated authority over it to you because you own the `/64` block.

### Step 3 — Create the Zone in Cloudflare

1. Create a free account at [dash.cloudflare.com](https://dash.cloudflare.com)
2. Click **"Add a site"** and enter your full `.arpa` zone string exactly
3. Select the **Free plan**
4. Add a DNS A record:

| Field | Value |
|-------|-------|
| Type | A |
| Name | `@` |
| IPv4 address | `1.1.1.1` |
| Proxy status | **DNS only** (gray cloud — must not be proxied) |
| TTL | Auto |

5. Note the two Cloudflare nameservers assigned to your zone (e.g. `mcgrory.ns.cloudflare.com`, `vera.ns.cloudflare.com`)
6. **Ignore Cloudflare's instruction to update nameservers at a registrar** — `.arpa` zones have no registrar. The delegation happens through HE directly in the next step.

### Step 4 — Wire HE to Cloudflare

Go back to your HE tunnel detail page and find the **rDNS Delegations** section. Enter your Cloudflare nameservers:

```
rDNS Delegated NS1: mcgrory.ns.cloudflare.com
rDNS Delegated NS2: vera.ns.cloudflare.com
```

Save. This tells HE's authoritative DNS servers to forward all queries for your `.arpa` zone to Cloudflare.

### Step 5 — Verify the Chain

Run these in order to confirm each layer:

```bash
# 1. Confirm HE is delegating to Cloudflare
nslookup -type=NS e.3.0.0.7.0.f.1.0.7.4.0.1.0.0.2.ip6.arpa ns1.he.net
# Expected: nameserver = mcgrory.ns.cloudflare.com

# 2. Confirm Cloudflare has the A record
nslookup e.3.0.0.7.0.f.1.0.7.4.0.1.0.0.2.ip6.arpa mcgrory.ns.cloudflare.com
# Expected: Address: 1.1.1.1

# 3. Confirm public resolution works end-to-end
nslookup e.3.0.0.7.0.f.1.0.7.4.0.1.0.0.2.ip6.arpa 8.8.8.8
# Expected: Address: 1.1.1.1
```

### Step 6 — Run the Detector

```bash
python cli.py --hostname "e.3.0.0.7.0.f.1.0.7.4.0.1.0.0.2.ip6.arpa" --dns
```

**Expected output — all 7 signals, 100/100:**

```
TARGET : e.3.0.0.7.0.f.1.0.7.4.0.1.0.0.2.ip6.arpa
SCORE  : [████████████████████████████████████████] 100/100
VERDICT: 🔴  HIGH

TRIGGERED SIGNALS:
  [+15]  ARPA_TLD
  [+10]  IP6_ARPA_ZONE
  [+20]  IPV6_NIBBLE_PATTERN          (16 nibble labels found)
  [+10]  LONG_HOSTNAME                (40 chars)
  [+10]  PARTIAL_NIBBLE_DELEGATION    (16 nibbles — /64 block)
  [+25]  RESOLVES_AS_A_RECORD         (resolved to: 1.1.1.1)
  [+10]  CDN_RESOLUTION               (CDN IP: 1.1.1.1)
```

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `NXDOMAIN` from `8.8.8.8` but correct from Cloudflare NS | HE delegation not propagated yet | Wait 15–30 min, verify rDNS fields saved on HE tunnel page |
| `SERVFAIL` from `8.8.8.8` | HE delegation found Cloudflare but Cloudflare rejected query | Check zone is **Active** (not Pending) in Cloudflare, confirm A record uses `@` as name and is DNS only |
| `REFUSED` from Cloudflare NS directly | Cloudflare doesn't recognize the zone | Wrong `.arpa` string — re-derive from Routed /64, not tunnel endpoint. Create new Cloudflare zone with correct string |
| `CDN_RESOLUTION` fires but `RESOLVES_AS_A_RECORD` does not, CDN IP shows empty | Root-level `detector.py` shadowing the `detector/` package | Check for a `detector.py` file in your project root — remove or rename it. Ensure `__init__.py` uses `get_resolution_summary()` not `resolves_to_cdn()` |
| `1.1.1.1` not detected as CDN | `1.1.1.0/24` not in CIDR list | Confirm `dns_utils.py` includes `1.1.1.0/24` and `1.0.0.0/24`. These are Cloudflare's DNS resolver ranges, distinct from their CDN edge ranges |
| Routed /64 shows empty on HE | Tunnel provisioned but block not assigned yet | Refresh the page after a few minutes — HE assigns the block asynchronously after tunnel creation |

### What This Proves

| Step | Attacker | This Test |
|------|----------|-----------|
| IPv6 block | Free tunnel from HE | ✅ Same |
| `.arpa` delegation | HE rDNS → attacker's NS | ✅ Same |
| DNS provider | Cloudflare (per Infoblox) | ✅ Same |
| A record on `.arpa` zone | Points to phishing server | Points to `1.1.1.1` (safe) |
| Resolves via CDN network | Yes — Cloudflare IPs | ✅ Same |

The only difference is the destination. The infrastructure chain is identical to the documented attack.

---

## 🔬 Scoring Logic

The detector uses a **transparent, rule-based scoring system**. No machine learning. Every point is attributable to a named signal with a written explanation.

### Signal Weights

| Signal | Weight | Rationale |
|--------|--------|-----------|
| `ARPA_TLD` | +15 | `.arpa` reserved for infrastructure; a strong anchor but not sufficient alone |
| `IP6_ARPA_ZONE` | +10 | IPv6 reverse-DNS zone — abused via free tunnel services |
| `INADDR_ARPA_ZONE` | +5 | IPv4 reverse-DNS zone — less commonly abused |
| `IPV6_NIBBLE_PATTERN` | +20 | Hex chars separated by dots before `ip6.arpa` — core attack structure |
| `DGA_PREFIX` | +15 | Random alphabetic prefix before nibble run — per-victim uniqueness |
| `LONG_HOSTNAME` | +10 | Length ≥ 40 chars — inherent to weaponized IPv6 FQDNs |
| `VERY_LONG_HOSTNAME` | +5 | Length ≥ 70 chars — additive; full IPv6 strings with DGA prefix |
| `PARTIAL_NIBBLE_DELEGATION` | +10 | 8–31 nibbles = attacker-controlled block, not single-host PTR |
| `HTTP_CONTEXT` | +12 | `.arpa` used as web URL — behavioral misuse signal |
| `EMAIL_DELIVERED` | +10 | Matches known delivery pattern: image-wrapped href in email |
| `RESOLVES_AS_A_RECORD` | +25 | `.arpa` domain returned an A/AAAA record — strongest technical violation |
| `CDN_RESOLUTION` | +10 | Resolved IP in CDN range — attacker masks phishing host behind CDN |
| `DNS_NO_RESPONSE` | +5 | DNS attempted but domain is dead — consistent with expired phishing asset |
| `LIKELY_LEGIT_PTR` | **-25** | Full 32-nibble PTR with no DGA prefix and no HTTP context — likely legitimate |

### Verdict Thresholds

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0 – 30 | 🟢 LOW | Likely legitimate DNS infrastructure |
| 31 – 60 | 🟡 MEDIUM | Partial signals — investigate further |
| 61 – 100 | 🔴 HIGH | Strong indicators of `.arpa` phishing abuse |

---

## 📊 Evaluation Results

Evaluated against 23 labeled samples across 4 categories.

```
TOTAL SAMPLES : 23
CORRECT       : 20/23 (87%)
TRUE POSITIVE : 9    (malicious correctly flagged HIGH)  ✅
TRUE NEGATIVE : 12   (benign correctly not flagged HIGH) ✅
FALSE POSITIVE: 2    (benign incorrectly flagged HIGH)   ⚠️
FALSE NEGATIVE: 0    (malicious missed)                  ✅

PRECISION     : 81.82%
RECALL        : 100.00%   ← zero missed malicious
F1 SCORE      : 90.00%
```

**Score distribution by group:**

| Label Group | n | Avg Score | Min | Max |
|------------|---|-----------|-----|-----|
| `malicious` | 9 | 100.0 | 100 | 100 |
| `medium_risk` | 3 | 63.3 | 30 | 85 |
| `benign` | 8 | 21.2 | 0 | 45 |
| `comparison_phish` | 3 | 10.0 | 10 | 10 |

---

## 🛡️ Detection Engineering Outputs

### Splunk (`detections/splunk_queries.spl`)

| Query | Description |
|-------|-------------|
| `SPL-1` | `.arpa` domains in proxy/web traffic |
| `SPL-2` | Composite risk-scored detection (mirrors Python engine) |
| `SPL-3` | `.arpa` domains in O365 email URL logs |
| `SPL-4` | DNS A/AAAA query against `.arpa` (behavioral anomaly) |
| `SPL-5` | IOC-based threat hunt for known IPv6 blocks |
| `SPL-6` | TDS domain detection (companion kill chain) |
| `SPL-7` | Dashboard summary query |

### Microsoft Sentinel (`detections/sentinel_kql.kql`)

| Query | Description |
|-------|-------------|
| `KQL-1` | `.arpa` in proxy logs (`CommonSecurityLog`) |
| `KQL-2` | `.arpa` in email links (`EmailUrlInfo` + `EmailEvents`) |
| `KQL-3` | High-confidence composite risk-scored rule |
| `KQL-4` | DNS anomaly — A record queries for `.arpa` |
| `KQL-5` | Dangling CNAME hijack companion detection |

### Sigma (`detections/sigma_rule.yml`)

Three rules covering proxy traffic, email URLs, and DNS anomalies. Compatible with `sigmac` for conversion to any SIEM format.

---

## ⚠️ Limitations

1. **DNS resolution is optional** — CDN detection requires live DNS lookups which add latency and may alert defenders on monitored infrastructure.
2. **DGA prefix heuristic** — Works well for the documented 6–15 alpha char pattern but could miss numeric-only or word-like prefixes. Tune `_DGA_ALPHA_RE` in `extractor.py` as variants emerge.
3. **No MIME email parsing** — HTML and plaintext only. For `.eml` files add `mail-parser` and extend `email_parser.py`.
4. **CDN CIDR lists need maintenance** — Periodically refresh from provider-published IP lists. Note: `1.1.1.0/24` (Cloudflare DNS resolver) is distinct from Cloudflare's CDN edge ranges and must be listed separately.
5. **Short-lived phishing domains** — Per Infoblox, links are only active for a few days. The `DNS_NO_RESPONSE` signal (+5) provides partial coverage for dead-but-suspicious domains.
6. **HE dns.he.net interface patched** — HE's hosted DNS frontend now restricts `.arpa` zone creation to IPv4 only, likely in response to Infoblox's February 2026 disclosure. The attack path via rDNS delegation to Cloudflare still works since Cloudflare applies no such restriction.
7. **Evaluation dataset is small** — 23 samples is sufficient for a prototype. Contribute labeled samples via GitHub issue.

---

## 🔭 Findings Summary

The strongest detection signals in order of reliability:

1. **DGA prefix + nibble pattern + ip6.arpa** — structural, zero false positives observed
2. **Partial nibble delegation (8–31 nibbles)** — fingerprint of attacker-controlled /64 block
3. **`RESOLVES_AS_A_RECORD`** — core technical violation, confirmed on live infrastructure
4. **`CDN_RESOLUTION`** — Cloudflare IPs, confirmed on live infrastructure
5. **HTTP/HTTPS context** — behavioral, 2 ambiguous edge cases remain
6. **Email-delivered link** — contextual, requires email log correlation

The detector was validated against live attacker-replicating infrastructure built using the exact technique documented by Infoblox, achieving **100/100** across all signals on a self-built test domain.

---

## 📚 References

- [Infoblox: Abusing .arpa — The TLD That Isn't Supposed to Host Anything](https://www.infoblox.com/blog/threat-intelligence/abusing-arpa-the-tld-that-isnt-supposed-to-host-anything/) (Feb 2026)
- [CyberSecurity News: Phishing Schemes Abuse .arpa TLD and IPv6 Tunnels](https://cybersecuritynews.com/phishing-schemes-abuse-arpa-tld-and-ipv6-tunnels/) (Feb 2026)
- [IANA: .arpa Domain](https://www.iana.org/domains/arpa)
- [RFC 3172: Management Guidelines for the .arpa Domain](https://www.rfc-editor.org/rfc/rfc3172)
- [Infoblox: From Click to Chaos — Traffic Distribution Systems](https://www.infoblox.com/blog/threat-intelligence/from-click-to-chaos-bouncing-around-in-malicious-traffic-distribution-systems/)
- [Infoblox GitHub: Threat Intelligence IOCs](https://github.com/infobloxopen/threat-intelligence)
- [Hurricane Electric Tunnel Broker](https://tunnelbroker.net)

---

*Built as a detection engineering portfolio project. Not a production security product.*