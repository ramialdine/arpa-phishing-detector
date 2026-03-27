"""
arpa-phish-detect detector package.

# test comment

Public API:
    from detector import FeatureExtractor, Scorer, analyze_url, analyze_hostname
"""

from .extractor import FeatureExtractor, Features
from .scorer import Scorer, ScoringResult, Signal
from .dns_utils import resolves_to_cdn, get_resolution_summary
from .email_parser import extract_links, extract_arpa_links, summarize_links

__all__ = [
    "FeatureExtractor",
    "Features",
    "Scorer",
    "ScoringResult",
    "Signal",
    "resolves_to_cdn",
    "get_resolution_summary",
    "extract_links",
    "extract_arpa_links",
    "summarize_links",
    "analyze_url",
    "analyze_hostname",
]


def analyze_url(url: str, is_email_delivered: bool = False, run_dns: bool = False) -> ScoringResult:
    """
    One-shot analysis of a URL.

    Args:
        url:               The URL to analyze.
        is_email_delivered: Set True if the URL was extracted from email content.
        run_dns:           If True, perform live DNS resolution for CDN check.
                           May add latency; set False for offline/batch use.

    Returns:
        ScoringResult with score, verdict, triggered signals, and explanation.
    """
    fx = FeatureExtractor()
    features = fx.extract_from_url(url, is_email_delivered=is_email_delivered)

    cdn_resolved = False
    if run_dns and features.hostname:
        dns_info = get_resolution_summary(features.hostname)
        cdn_resolved = dns_info["cdn_resolved"]
        features.dns_resolved = dns_info["resolved"]
        features.dns_cdn_resolved = dns_info["cdn_resolved"]
        features.dns_ips = ", ".join(dns_info["ip_addresses"])
        features.dns_was_checked = True

    return Scorer().score(features, cdn_resolved=cdn_resolved)


def analyze_hostname(hostname: str, is_email_delivered: bool = False, run_dns: bool = False) -> ScoringResult:
    """
    One-shot analysis of a bare hostname.

    Args:
        hostname:          The hostname to analyze.
        is_email_delivered: Set True if extracted from email content.
        run_dns:           If True, perform live DNS resolution for CDN check.

    Returns:
        ScoringResult with score, verdict, triggered signals, and explanation.
    """
    fx = FeatureExtractor()
    features = fx.extract_from_hostname(hostname, is_email_delivered=is_email_delivered)

    cdn_resolved = False
    if run_dns and features.hostname:
        dns_info = get_resolution_summary(features.hostname)
        cdn_resolved = dns_info["cdn_resolved"]
        features.dns_resolved = dns_info["resolved"]
        features.dns_cdn_resolved = dns_info["cdn_resolved"]
        features.dns_ips = ", ".join(dns_info["ip_addresses"])
        features.dns_was_checked = True

    return Scorer().score(features, cdn_resolved=cdn_resolved)