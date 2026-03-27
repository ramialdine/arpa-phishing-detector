"""
extractor.py — Feature extraction for .arpa phishing detection.

Extracts domain/DNS features, entropy metrics, and behavioral signals
from URLs, hostnames, and email-delivered links.
"""

import re
import math
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Optional


# ---------------------------------------------------------------------------
# Feature dataclass
# ---------------------------------------------------------------------------

@dataclass
class Features:
    # Raw inputs
    raw_input: str = ""
    hostname: str = ""
    scheme: str = ""
    path: str = ""
    is_url: bool = False
    is_email_delivered: bool = False

    # --- Domain / DNS features ---
    is_arpa_tld: bool = False
    is_ip6_arpa: bool = False
    is_inaddr_arpa: bool = False
    hostname_length: int = 0
    label_count: int = 0

    # IPv6 nibble pattern detection
    has_ipv6_nibble_pattern: bool = False
    nibble_run_length: int = 0           # how many nibble labels found

    # Subdomain prefix analysis (DGA detection)
    subdomain_prefix: str = ""           # leftmost labels before the nibble run
    subdomain_entropy: float = 0.0
    has_dga_prefix: bool = False

    # Behavioral / contextual features
    used_in_http_context: bool = False   # scheme is http or https

    # DNS resolution results (set externally after live DNS check)
    dns_resolved: bool = False           # domain returned any A/AAAA record (anomaly for .arpa)
    dns_cdn_resolved: bool = False       # resolved IP falls in a known CDN range
    dns_ips: str = ""                    # comma-separated resolved IPs (stored as str for dataclass simplicity)
    dns_was_checked: bool = False        # True if live DNS resolution was actually attempted

    def to_dict(self) -> dict:
        return self.__dict__


# ---------------------------------------------------------------------------
# Regexes (compiled once)
# ---------------------------------------------------------------------------

# Loose match: 4+ single hex chars separated by dots, preceding ip6.arpa
_IPV6_NIBBLE_RE = re.compile(
    r'((?:[0-9a-f]\.){4,32})ip6\.arpa$',  # $ anchors to end — prevents ip6.arpa.com matching
    re.IGNORECASE
)

# Strict: full 32-nibble reverse dns (no extra prefix)
_IPV6_FULL_RE = re.compile(
    r'^(?:[0-9a-f]\.){32}ip6\.arpa$',
    re.IGNORECASE
)

# in-addr.arpa: reversed IPv4 octets
_INADDR_RE = re.compile(
    r'(?:\d{1,3}\.){1,4}in-addr\.arpa',
    re.IGNORECASE
)

# DGA-like prefix: all-alphabetic, 6–15 chars, single label
_DGA_ALPHA_RE = re.compile(r'^[a-z]{6,15}$', re.IGNORECASE)

# DGA-like prefix: alphanumeric random string
_DGA_ALNUM_RE = re.compile(r'^[a-z0-9]{8,15}$', re.IGNORECASE)

_HEX_CHARS = set('0123456789abcdef')


# ---------------------------------------------------------------------------
# Extractor class
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """
    Extracts structured features from a URL or bare hostname.

    Usage:
        fx = FeatureExtractor()
        features = fx.extract_from_url("https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa/")
        features = fx.extract_from_hostname("abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa")
    """

    def extract_from_url(self, url: str, is_email_delivered: bool = False) -> Features:
        """Extract features from a full URL string."""
        features = Features(raw_input=url, is_url=True, is_email_delivered=is_email_delivered)

        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = parsed.hostname or url
        scheme = parsed.scheme.lower()
        path = parsed.path or ""

        features.scheme = scheme
        features.path = path
        features.used_in_http_context = scheme in ("http", "https")

        self._extract_domain_features(hostname, features)
        return features

    def extract_from_hostname(self, hostname: str, is_email_delivered: bool = False) -> Features:
        """Extract features from a bare hostname (no scheme)."""
        features = Features(raw_input=hostname, is_url=False, is_email_delivered=is_email_delivered)
        self._extract_domain_features(hostname, features)
        return features

    # ------------------------------------------------------------------
    # Core domain analysis
    # ------------------------------------------------------------------

    def _extract_domain_features(self, hostname: str, features: Features):
        hostname = hostname.lower().strip().rstrip(".")
        features.hostname = hostname
        features.hostname_length = len(hostname)
        features.label_count = len(hostname.split("."))

        # --- TLD / zone checks ---
        features.is_arpa_tld = hostname.endswith(".arpa") or hostname == "arpa"
        # Use endswith() not substring match — prevents .ip6.arpa.com from triggering
        features.is_ip6_arpa = hostname.endswith(".ip6.arpa") or hostname == "ip6.arpa"
        features.is_inaddr_arpa = (
            bool(_INADDR_RE.search(hostname))
            and not features.is_ip6_arpa
            and hostname.endswith(".arpa")  # must actually be .arpa TLD
        )

        # --- IPv6 nibble pattern ---
        m = _IPV6_NIBBLE_RE.search(hostname)
        if m:
            features.has_ipv6_nibble_pattern = True
            nibble_part = m.group(1)  # e.g. "5.2.1.6.3.0.0.0."
            features.nibble_run_length = nibble_part.count(".")
        
        # --- Subdomain prefix analysis (only meaningful for ip6.arpa) ---
        if features.is_ip6_arpa:
            self._analyze_subdomain_prefix(hostname, features)

    def _analyze_subdomain_prefix(self, hostname: str, features: Features):
        """
        Identify and analyse the subdomain prefix that attackers prepend
        to the reverse-DNS nibble string to create unique FQDNs.

        Pattern:  <DGA_PREFIX>.<nibbles>.ip6.arpa
        Example:  abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa
                  ^^^^^^^^^^ prefix
        """
        labels = hostname.split(".")
        prefix_labels = []

        for label in labels:
            # A nibble-run label is exactly one hex char
            if len(label) == 1 and label in _HEX_CHARS:
                break
            # Stop at known zone markers
            if label in ("ip6", "arpa", "in-addr"):
                break
            prefix_labels.append(label)

        if not prefix_labels:
            return

        features.subdomain_prefix = ".".join(prefix_labels)
        features.subdomain_entropy = _shannon_entropy(features.subdomain_prefix)

        # DGA heuristic:
        #   - single label (not compound subdomain like "mail.example")
        #   - all alpha or alphanumeric
        #   - reasonable length (6–15 chars)
        #   - high Shannon entropy (> 3.0 bits) — random strings are high entropy
        if (
            len(prefix_labels) == 1
            and (_DGA_ALPHA_RE.match(prefix_labels[0]) or _DGA_ALNUM_RE.match(prefix_labels[0]))
            and features.subdomain_entropy > 3.0
        ):
            features.has_dga_prefix = True


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits) of string s."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return round(
        -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values()),
        4
    )