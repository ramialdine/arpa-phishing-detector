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
3. Creates A records (NOT PTR records) pointing to CDN/phishing infrastructure
4. Prepends randomly-generated DGA prefix → unique FQDN per victim
5. Embeds FQDN in phishing email as hidden hyperlink behind an image
6. Victim clicks image → TDS fingerprints traffic → delivers phishing page
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

# CLI — analyze a hostname from an email
python cli.py --hostname "xkzpqmwrtu.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa" --email-delivered

# CLI — parse an email file and analyze all links
python cli.py --email samples/phish.html

# CLI — with live DNS resolution (CDN check)
python cli.py --url "https://..." --dns

# CLI — JSON output (for SIEM integration)
python cli.py --url "https://..." --json

# Streamlit UI
streamlit run app.py

# Evaluate against test dataset
python evaluate.py
```

---

## 🔬 Scoring Logic

The detector uses a **transparent, rule-based scoring system**. No machine learning. Every point is attributable to a named signal with a written explanation.

### Signal Weights

| Signal | Weight | Rationale |
|--------|--------|-----------|
| `ARPA_TLD` | +25 | `.arpa` reserved for infrastructure; any web delivery is anomalous |
| `IP6_ARPA_ZONE` | +10 | IPv6 reverse-DNS zone — abused via free tunnel services |
| `INADDR_ARPA_ZONE` | +5 | IPv4 reverse-DNS zone — less commonly abused |
| `IPV6_NIBBLE_PATTERN` | +20 | Hex chars separated by dots before `ip6.arpa` — core attack structure |
| `DGA_PREFIX` | +15 | Random alphabetic prefix before nibble run — per-victim uniqueness |
| `LONG_HOSTNAME` | +10 | Length > 40 chars — inherent to weaponized IPv6 FQDNs |
| `VERY_LONG_HOSTNAME` | +5 | Length > 70 chars — additive; full IPv6 strings with DGA prefix |
| `HTTP_CONTEXT` | +10 | `.arpa` used as web URL — the defining behavioral anomaly |
| `EMAIL_DELIVERED` | +10 | Matches known delivery pattern: image-wrapped href in email |
| `CDN_RESOLUTION` | +10 | Resolves to CDN IP — attacker uses CDN to mask phishing host |
| `LIKELY_LEGIT_PTR` | **-25** | Negative: nibble pattern present but NO DGA prefix AND NOT in HTTP context → likely legitimate PTR |

### Verdict Thresholds

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0 – 30 | 🟢 LOW | Likely legitimate DNS infrastructure |
| 31 – 60 | 🟡 MEDIUM | Partial signals — investigate further |
| 61 – 100 | 🔴 HIGH | Strong indicators of `.arpa` phishing abuse |

### Design Decisions

**Why rule-based, not ML?**
- Full explainability required for security operations (what triggered, why)
- Attack pattern is well-defined and structurally detectable without training data
- Easier to tune weights as new variants emerge
- No training data maintenance burden

**Why the negative signal?**  
Legitimate IPv6 reverse-DNS PTR records look structurally identical to attacker FQDNs — except they don't appear in HTTP context and don't have DGA prefixes. Without the negative signal, full 32-nibble PTR hosts score ~70 (high), producing false positives. The negative signal reduces them to medium (~45) while leaving malicious detections unaffected.

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
| `malicious` | 9 | 97.8 | 90 | 100 |
| `medium_risk` | 3 | 53.3 | 30 | 65 |
| `benign` | 8 | 21.2 | 0 | 45 |
| `comparison_phish` | 3 | 10.0 | 10 | 10 |

The score separation between malicious (avg 97.8) and benign (avg 21.2) is excellent. The 2 remaining FPs are `ip6.arpa` domains used in HTTP context **without** a DGA prefix — a genuinely ambiguous case (suspicious but not definitively malicious).

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

2. **DGA prefix heuristic** — The entropy-based DGA detection works well for the documented pattern (6–15 alpha chars) but could miss variants with shorter or differently structured prefixes. Tune `_DGA_ALPHA_RE` in `extractor.py` as new variants emerge.

3. **No MIME email parsing** — The email parser handles HTML and plaintext. For proper MIME parsing of `.eml` files, add `mail-parser` and extend `email_parser.py`.

4. **No full 32-nibble validation** — We don't validate that nibble strings correspond to real IPv6 addresses from known attacker-controlled blocks. This is intentional (avoids requiring a threat intel feed dependency) but means we can't definitively attribute IPv6 space to specific threat actors.

5. **CDN CIDR lists need maintenance** — Hardcoded CDN ranges in `dns_utils.py` should be periodically refreshed from provider-published IP lists.

6. **Short-lived phishing domains** — Per Infoblox, links are only active for a few days. DNS-based CDN detection may fail after domains go inactive.

7. **Evaluation dataset is small** — 23 samples is sufficient for a prototype but production tuning requires a larger corpus. Contribute samples by opening a GitHub issue.

---

## 🔭 Findings Summary

The `.arpa` phishing technique is novel because it inverts the trust model of DNS infrastructure. Traditional phishing detection relies on:
- Domain registration data (`.arpa` has none)  
- URL reputation scoring (`.arpa` scores "trusted")  
- Blocklists (`.arpa` often explicitly excluded)  

The detection approach in this prototype shifts focus from **reputation** to **behavior**: an infrastructure-tier domain behaving like a web endpoint is a structural anomaly that can be detected without relying on any pre-existing threat intelligence.

The strongest detection signals — in order of reliability — are:
1. **DGA prefix + nibble pattern + ip6.arpa** (structural, no false positives observed)  
2. **HTTP/HTTPS context for any .arpa domain** (behavioral, 2 ambiguous cases)  
3. **Email-delivered link** (contextual, requires email log correlation)  
4. **CDN resolution** (behavioral, requires live DNS)  

The zero false-negative rate is the most operationally important metric: no malicious sample in the test set was missed. The 2 residual false positives represent genuinely ambiguous edge cases that warrant analyst review rather than automatic block.

---

## 📚 References

- [Infoblox: Abusing .arpa — The TLD That Isn't Supposed to Host Anything](https://www.infoblox.com/blog/threat-intelligence/abusing-arpa-the-tld-that-isnt-supposed-to-host-anything/) (Feb 2026)
- [CyberSecurity News: Phishing Schemes Abuse .arpa TLD and IPv6 Tunnels](https://cybersecuritynews.com/phishing-schemes-abuse-arpa-tld-and-ipv6-tunnels/) (Feb 2026)
- [IANA: .arpa Domain](https://www.iana.org/domains/arpa)
- [RFC 3172: Management Guidelines for the .arpa Domain](https://www.rfc-editor.org/rfc/rfc3172)
- [Infoblox: From Click to Chaos — Traffic Distribution Systems](https://www.infoblox.com/blog/threat-intelligence/from-click-to-chaos-bouncing-around-in-malicious-traffic-distribution-systems/)
- [Infoblox GitHub: Threat Intelligence IOCs](https://github.com/infobloxopen/threat-intelligence)

---

*Built as a detection engineering portfolio project. Not a production security product.*
