"""
scorer.py — Rule-based, explainable scoring engine for .arpa phishing detection.

Each feature triggers a Signal with an assigned weight.
The final score (0–100) maps to a risk verdict (low / medium / high).
Every triggered signal includes a human-readable explanation — no black box.
"""

from dataclasses import dataclass, field
from typing import List

try:
    # Package-style import
    from .extractor import Features
except ImportError:
    # Flat-layout fallback (running scripts from project root)
    from extractor import Features


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Signal:
    name: str
    description: str
    weight: int
    triggered: bool = False
    detail: str = ""          # runtime detail (e.g. actual entropy value)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "triggered": self.triggered,
            "weight": self.weight if self.triggered else 0,
            "description": self.description,
            "detail": self.detail,
        }


@dataclass
class ScoringResult:
    score: int
    verdict: str                     # "low" | "medium" | "high"
    triggered_signals: List[Signal]
    all_signals: List[Signal]
    explanation: str
    features: Features

    @property
    def verdict_emoji(self) -> str:
        return {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(self.verdict, "⚪")

    def to_dict(self) -> dict:
        return {
            "hostname": self.features.hostname,
            "score": self.score,
            "verdict": self.verdict,
            "triggered_signals": [s.to_dict() for s in self.triggered_signals],
            "explanation": self.explanation,
        }

    def pretty_print(self):
        """Human-readable console output."""
        width = 72
        bar_filled = int((self.score / 100) * 40)
        bar = "█" * bar_filled + "░" * (40 - bar_filled)

        print("\n" + "═" * width)
        print(f"  TARGET : {self.features.hostname}")
        print(f"  SCORE  : [{bar}] {self.score}/100")
        print(f"  VERDICT: {self.verdict_emoji}  {self.verdict.upper()}")
        print("─" * width)

        if self.triggered_signals:
            print("  TRIGGERED SIGNALS:")
            for s in self.triggered_signals:
                detail = f"  ({s.detail})" if s.detail else ""
                print(f"    [{s.weight:>3}pts]  {s.name}{detail}")
                print(f"            {s.description}")
        else:
            print("  No signals triggered.")

        print("─" * width)
        print(f"  {self.explanation}")
        print("═" * width + "\n")


# ---------------------------------------------------------------------------
# Scoring weights reference
# ---------------------------------------------------------------------------
#
#  Tier 1 — Structural (domain construction)
#    ARPA_TLD              25   Core signal: domain is in reserved .arpa namespace
#    IP6_ARPA_ZONE         10   Specifically in IPv6 reverse-DNS zone
#    INADDR_ARPA_ZONE       5   Specifically in IPv4 reverse-DNS zone (less suspicious)
#    IPV6_NIBBLE_PATTERN   20   Contains reversed IPv6 nibble notation
#    DGA_PREFIX            15   High-entropy random subdomain prefix prepended
#
#  Tier 2 — Contextual (usage behavior)
#    LONG_HOSTNAME         10   Length > 40 chars (additive)
#    VERY_LONG_HOSTNAME     5   Length > 70 chars (additive bonus)
#    HTTP_CONTEXT          10   Used as a web URL — infrastructure domains shouldn't be
#    EMAIL_DELIVERED       10   Embedded in email — matches known phishing delivery pattern
#    CDN_RESOLUTION        10   Resolves to CDN/proxy IP (Cloudflare, Fastly, etc.)
#
#  Maximum raw score: 120 → capped at 100
#
#  Verdict thresholds:
#    0 – 30   → LOW
#   31 – 60   → MEDIUM
#   61 – 100  → HIGH


class Scorer:
    """
    Rule-based scoring engine.

    Usage:
        result = Scorer().score(features, cdn_resolved=True)
    """

    LOW_THRESHOLD = 31
    HIGH_THRESHOLD = 61

    def score(self, features: Features, cdn_resolved: bool = False) -> ScoringResult:
        signals = self._build_signals(features, cdn_resolved)
        raw = sum(s.weight for s in signals if s.triggered)
        final_score = min(raw, 100)
        triggered = [s for s in signals if s.triggered]
        verdict = self._verdict(final_score)
        explanation = self._explain(final_score, verdict, triggered, features)

        return ScoringResult(
            score=final_score,
            verdict=verdict,
            triggered_signals=triggered,
            all_signals=signals,
            explanation=explanation,
            features=features,
        )

    # ------------------------------------------------------------------
    # Signal definitions
    # ------------------------------------------------------------------

    def _build_signals(self, f: Features, cdn_resolved: bool) -> List[Signal]:
        signals: List[Signal] = []

        # ── Tier 1: Structural ───────────────────────────────────────────

        s = Signal(
            name="ARPA_TLD",
            weight=25,
            description=(
                ".arpa TLD detected. This namespace is exclusively reserved for "
                "internet DNS infrastructure (RFC 3172). It was never designed to "
                "host public web content. Any domain in this TLD appearing in web "
                "traffic or email links is inherently anomalous."
            ),
        )
        s.triggered = f.is_arpa_tld
        signals.append(s)

        s = Signal(
            name="IP6_ARPA_ZONE",
            weight=10,
            description=(
                "Domain is in the ip6.arpa zone, which exists solely for IPv6 "
                "reverse-DNS PTR lookups. Attackers abuse free IPv6 tunnel services "
                "(e.g., Hurricane Electric) to acquire /64 IPv6 blocks, gain "
                "delegation over the corresponding ip6.arpa subdomain, then create "
                "A records instead of PTR records."
            ),
        )
        s.triggered = f.is_ip6_arpa
        signals.append(s)

        s = Signal(
            name="INADDR_ARPA_ZONE",
            weight=5,
            description=(
                "Domain is in the in-addr.arpa zone (IPv4 reverse-DNS). "
                "Less commonly abused than ip6.arpa but still anomalous "
                "when appearing in web or email context."
            ),
        )
        s.triggered = f.is_inaddr_arpa and not f.is_ip6_arpa
        signals.append(s)

        s = Signal(
            name="IPV6_NIBBLE_PATTERN",
            weight=20,
            description=(
                "Domain contains a reversed IPv6 nibble sequence — the characteristic "
                "structure of an IPv6 reverse-DNS FQDN. In the attack pattern, the "
                "actor takes their /64 IPv6 prefix, reverses it nibble-by-nibble "
                "(each hex digit separated by dots), and appends .ip6.arpa to form "
                "the domain. This pattern is functionally useless for legitimate PTR "
                "lookups but creates a convincing infrastructure-looking hostname."
            ),
        )
        s.triggered = f.has_ipv6_nibble_pattern
        if s.triggered:
            s.detail = f"{f.nibble_run_length} nibble labels found"
        signals.append(s)

        s = Signal(
            name="DGA_PREFIX",
            weight=15,
            description=(
                "High-entropy DGA-like subdomain prefix detected. Attackers prepend "
                "a randomly generated alphabetic string (e.g., 'abcdefghij') to the "
                "nibble-based reverse-DNS string. This makes each FQDN unique, "
                "preventing blocklist reuse across victims and complicating detection "
                "by pattern matchers expecting static domain strings."
            ),
        )
        s.triggered = f.has_dga_prefix
        if s.triggered:
            s.detail = f"prefix='{f.subdomain_prefix}' entropy={f.subdomain_entropy:.2f}bits"
        signals.append(s)

        # ── Tier 2: Contextual ──────────────────────────────────────────

        s = Signal(
            name="LONG_HOSTNAME",
            weight=10,
            description=(
                f"Hostname length ({f.hostname_length} chars) exceeds 40 characters. "
                "While legitimate PTR domains are inherently long by design, a long "
                ".arpa domain appearing as a web link or email hyperlink is a strong "
                "contextual anomaly."
            ),
        )
        s.triggered = f.hostname_length > 40
        if s.triggered:
            s.detail = f"{f.hostname_length} chars"
        signals.append(s)

        s = Signal(
            name="VERY_LONG_HOSTNAME",
            weight=5,
            description=(
                f"Hostname length ({f.hostname_length} chars) exceeds 70 characters. "
                "Full IPv6 reverse DNS strings with a prepended DGA prefix typically "
                "reach 70–90 chars — this length strongly suggests a weaponized "
                "IPv6 reverse-DNS FQDN."
            ),
        )
        s.triggered = f.hostname_length > 70
        if s.triggered:
            s.detail = f"{f.hostname_length} chars (very long)"
        signals.append(s)

        s = Signal(
            name="HTTP_CONTEXT",
            weight=10,
            description=(
                "Domain is used in an HTTP or HTTPS URL. DNS infrastructure domains "
                "in the .arpa namespace should never resolve to web servers. An "
                ".arpa domain appearing with an http:// or https:// scheme is a "
                "critical behavioral anomaly — the defining characteristic of "
                "this attack technique."
            ),
        )
        s.triggered = f.used_in_http_context
        if s.triggered:
            s.detail = f"scheme={f.scheme}"
        signals.append(s)

        s = Signal(
            name="EMAIL_DELIVERED",
            weight=10,
            description=(
                "Domain was extracted from email content. This matches the exact "
                "delivery mechanism documented by Infoblox: phishing emails contain "
                "a single hyperlinked image, with the malicious .arpa domain hidden "
                "inside the image's href attribute. Victims see a legitimate-looking "
                "image and never notice the domain in the link."
            ),
        )
        s.triggered = f.is_email_delivered
        signals.append(s)

        s = Signal(
            name="CDN_RESOLUTION",
            weight=10,
            description=(
                "Domain resolves to a known CDN or proxy provider IP range. "
                "Attackers configure their .arpa domain to point to CDN infrastructure "
                "(e.g., Cloudflare), which masks the true phishing server origin, "
                "inherits the CDN's trusted reputation, and makes takedown harder."
            ),
        )
        s.triggered = cdn_resolved
        signals.append(s)

        # ── Tier 3: Negative signals (reduce score for likely-legitimate patterns) ──

        s = Signal(
            name="LIKELY_LEGIT_PTR",
            weight=-25,          # negative: reduces score
            description=(
                "Domain matches the pattern of a legitimate PTR-only record: "
                "contains a full IPv6 nibble sequence but has NO random DGA prefix "
                "and is NOT used in HTTP/HTTPS context. Legitimate reverse-DNS "
                "infrastructure commonly looks like this. Score reduced to reflect "
                "lower phishing probability — but re-evaluate if HTTP context or "
                "email delivery is later confirmed."
            ),
        )
        # Fire only when: has nibble pattern, NO DGA prefix, NOT in HTTP context
        s.triggered = (
            f.has_ipv6_nibble_pattern
            and not f.has_dga_prefix
            and not f.used_in_http_context
            and not f.is_email_delivered
        )
        if s.triggered:
            s.detail = "no DGA prefix, no HTTP context → likely legitimate PTR"
        signals.append(s)

        return signals

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _verdict(self, score: int) -> str:
        if score >= self.HIGH_THRESHOLD:
            return "high"
        elif score >= self.LOW_THRESHOLD:
            return "medium"
        return "low"

    def _explain(self, score: int, verdict: str, triggered: List[Signal], f: Features) -> str:
        if not triggered:
            return (
                "No suspicious signals detected. Domain appears to conform to "
                "legitimate DNS infrastructure patterns. Continue monitoring if "
                "additional context becomes available."
            )

        signal_names = ", ".join(s.name for s in triggered)

        if verdict == "high":
            return (
                f"HIGH RISK — Score {score}/100. Signals: [{signal_names}]. "
                "This domain exhibits multiple hallmarks of the .arpa phishing "
                "technique documented by Infoblox (Feb 2026): attackers use free "
                "IPv6 tunnel services to acquire /64 blocks, gain .arpa subdomain "
                "delegation, create A records (not PTR records), and prepend random "
                "DGA prefixes to create unique-per-victim FQDNs. These domains bypass "
                "traditional blocklists because .arpa has an implicitly clean reputation, "
                "no WHOIS registration data, and is excluded from policy denylists. "
                "Recommend: block, alert, and investigate associated email campaign."
            )
        elif verdict == "medium":
            return (
                f"MEDIUM RISK — Score {score}/100. Signals: [{signal_names}]. "
                "Partial indicators of .arpa infrastructure abuse detected. "
                "This could represent a legitimate but unusual DNS configuration, "
                "or an early-stage indicator. Investigate DNS resolution behavior, "
                "check if domain appears in email links, and monitor for CDN resolution."
            )
        else:
            return (
                f"LOW RISK — Score {score}/100. Signals: [{signal_names}]. "
                "Minor .arpa-related signals detected but insufficient to confirm "
                "phishing activity. This may be legitimate DNS infrastructure. "
                "Monitor for additional signals such as email delivery or HTTP context."
            )
