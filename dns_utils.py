"""
dns_utils.py — DNS resolution helpers for .arpa phishing detection.

Performs real DNS lookups (A/AAAA record anomaly detection) and checks
whether resolved IPs belong to known CDN or proxy provider ranges.

Design note: DNS lookups are best-effort. Failures are caught and logged
rather than crashing the detector — phishing domains are often short-lived
and may not resolve at all during investigation.
"""

import socket
import ipaddress
import logging
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known CDN / proxy CIDR ranges
# Attackers route .arpa domains through CDN infrastructure to:
#   1. Mask the true phishing server origin
#   2. Inherit CDN's clean reputation
#   3. Make takedown significantly harder
#
# Sources: Cloudflare, Fastly, Akamai, Amazon CloudFront public IP ranges.
# Update periodically from provider published CIDR lists.
# ---------------------------------------------------------------------------

_CDN_CIDRS_RAW = [
    # Cloudflare (documented in Infoblox report as abused provider)
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
    # Fastly
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.64.0/18",
    "140.248.128.0/17",
    "146.75.0.0/17",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
    # Akamai (broad)
    "23.32.0.0/11",
    "23.64.0.0/14",
    "23.192.0.0/11",
    "104.64.0.0/10",
    # Amazon CloudFront (subset)
    "13.32.0.0/15",
    "13.35.0.0/16",
    "52.46.0.0/18",
    "52.84.0.0/15",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "64.252.64.0/18",
    "99.84.0.0/16",
    "205.251.192.0/19",
    "216.137.32.0/19",
]

# Parse once at module load
_CDN_NETWORKS = []
for cidr in _CDN_CIDRS_RAW:
    try:
        _CDN_NETWORKS.append(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_a_records(hostname: str, timeout: float = 3.0) -> list[str]:
    """
    Resolve hostname to IPv4/IPv6 addresses.

    Returns a list of IP address strings, or an empty list if resolution fails.

    NOTE: For .arpa domains used in phishing, we expect to find A/AAAA records
    where only PTR records should exist — the detection signal is the resolution
    itself, not what it resolves to specifically.
    """
    ips: list[str] = []
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        results = socket.getaddrinfo(hostname, None)
        for result in results:
            ip = result[4][0]
            if ip not in ips:
                ips.append(ip)
    except (socket.gaierror, socket.herror, OSError) as e:
        log.debug("DNS resolution failed for %s: %s", hostname, e)
    finally:
        socket.setdefaulttimeout(original_timeout)
    return ips


def resolves_to_cdn(hostname: str, timeout: float = 3.0) -> bool:
    """
    Returns True if the hostname resolves to a known CDN/proxy IP range.

    This is a key behavioral signal: .arpa domains used in phishing typically
    resolve to Cloudflare or similar CDN IPs to mask the phishing server.
    """
    ips = resolve_a_records(hostname, timeout=timeout)
    for ip_str in ips:
        if _is_cdn_ip(ip_str):
            log.info("%s → %s (CDN match)", hostname, ip_str)
            return True
    return False


def resolves_at_all(hostname: str, timeout: float = 3.0) -> bool:
    """
    Returns True if the hostname resolves to any IP address.

    Context: Legitimate .arpa PTR-only names typically don't have A records.
    An .arpa hostname that resolves via A query is anomalous.
    """
    return len(resolve_a_records(hostname, timeout=timeout)) > 0


def get_resolution_summary(hostname: str, timeout: float = 3.0) -> dict:
    """
    Returns a structured dict with resolution results and CDN analysis.
    Useful for both CLI output and Streamlit display.
    """
    ips = resolve_a_records(hostname, timeout=timeout)
    cdn_hits = [ip for ip in ips if _is_cdn_ip(ip)]

    return {
        "hostname": hostname,
        "resolved": len(ips) > 0,
        "ip_addresses": ips,
        "cdn_resolved": len(cdn_hits) > 0,
        "cdn_ips": cdn_hits,
        "resolution_anomaly": len(ips) > 0,  # any A record for .arpa is anomalous
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_cdn_ip(ip_str: str) -> bool:
    """Check whether an IP address falls within known CDN ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _CDN_NETWORKS)
    except ValueError:
        return False
