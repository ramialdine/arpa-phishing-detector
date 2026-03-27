#!/usr/bin/env python3
"""
test_suite.py — Comprehensive test suite for the .arpa phishing detector.

Covers: extractor, scorer, dns_utils, email_parser, detector (integration).
Run with: python -m pytest test_suite.py -v
"""

import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))

from extractor import FeatureExtractor, Features, _shannon_entropy
from scorer import Scorer, Signal, ScoringResult
from dns_utils import _is_cdn_ip, _CDN_NETWORKS
from email_parser import extract_links, extract_arpa_links, summarize_links, ExtractedLink
from detector import analyze_url, analyze_hostname


# ═══════════════════════════════════════════════════════════════════════════
# EXTRACTOR TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestFeatureExtractor(unittest.TestCase):
    """Tests for extractor.py — feature extraction from URLs and hostnames."""

    def setUp(self):
        self.fx = FeatureExtractor()

    # --- .arpa TLD detection ---

    def test_arpa_tld_detected_ip6(self):
        f = self.fx.extract_from_hostname("a.b.c.ip6.arpa")
        self.assertTrue(f.is_arpa_tld)

    def test_arpa_tld_detected_inaddr(self):
        f = self.fx.extract_from_hostname("1.0.0.127.in-addr.arpa")
        self.assertTrue(f.is_arpa_tld)

    def test_arpa_tld_not_detected_for_normal_domain(self):
        f = self.fx.extract_from_hostname("google.com")
        self.assertFalse(f.is_arpa_tld)

    def test_bare_arpa_is_arpa_tld(self):
        f = self.fx.extract_from_hostname("arpa")
        self.assertTrue(f.is_arpa_tld)

    # --- ip6.arpa zone detection ---

    def test_ip6_arpa_detected(self):
        f = self.fx.extract_from_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        self.assertTrue(f.is_ip6_arpa)

    def test_ip6_arpa_not_detected_for_inaddr(self):
        f = self.fx.extract_from_hostname("1.0.0.127.in-addr.arpa")
        self.assertFalse(f.is_ip6_arpa)

    # --- in-addr.arpa zone detection ---

    def test_inaddr_arpa_detected(self):
        f = self.fx.extract_from_hostname("4.3.2.1.in-addr.arpa")
        self.assertTrue(f.is_inaddr_arpa)

    def test_inaddr_arpa_not_detected_for_ip6(self):
        f = self.fx.extract_from_hostname(
            "a.b.c.d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        )
        self.assertFalse(f.is_inaddr_arpa)

    # --- IPv6 nibble pattern detection ---

    def test_nibble_pattern_detected_partial(self):
        f = self.fx.extract_from_hostname(
            "5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        self.assertTrue(f.has_ipv6_nibble_pattern)
        self.assertGreater(f.nibble_run_length, 0)

    def test_nibble_pattern_detected_full_32(self):
        f = self.fx.extract_from_hostname(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
        self.assertTrue(f.has_ipv6_nibble_pattern)
        self.assertEqual(f.nibble_run_length, 32)

    def test_nibble_pattern_not_detected_for_normal_domain(self):
        f = self.fx.extract_from_hostname("google.com")
        self.assertFalse(f.has_ipv6_nibble_pattern)

    # --- DGA prefix detection ---

    def test_dga_prefix_detected(self):
        f = self.fx.extract_from_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        self.assertTrue(f.has_dga_prefix)
        self.assertEqual(f.subdomain_prefix, "abcdefghij")

    def test_dga_prefix_detected_variant(self):
        f = self.fx.extract_from_hostname(
            "xkzpqmwrtu.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        self.assertTrue(f.has_dga_prefix)

    def test_no_dga_prefix_when_absent(self):
        f = self.fx.extract_from_hostname(
            "5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        self.assertFalse(f.has_dga_prefix)
        self.assertEqual(f.subdomain_prefix, "")

    def test_no_dga_prefix_for_full_32_nibble_ptr(self):
        f = self.fx.extract_from_hostname(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
        self.assertFalse(f.has_dga_prefix)

    def test_short_prefix_not_flagged_as_dga(self):
        """Prefixes shorter than 6 chars should not trigger DGA."""
        f = self.fx.extract_from_hostname(
            "abc.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        self.assertFalse(f.has_dga_prefix)

    # --- URL extraction ---

    def test_extract_from_url_sets_scheme_and_context(self):
        f = self.fx.extract_from_url(
            "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa/track"
        )
        self.assertTrue(f.is_url)
        self.assertEqual(f.scheme, "https")
        self.assertTrue(f.used_in_http_context)
        self.assertEqual(f.path, "/track")

    def test_extract_from_url_no_scheme_defaults_http(self):
        f = self.fx.extract_from_url("example.com/page")
        self.assertEqual(f.scheme, "http")
        self.assertTrue(f.used_in_http_context)

    def test_email_delivered_flag(self):
        f = self.fx.extract_from_url(
            "https://test.ip6.arpa", is_email_delivered=True
        )
        self.assertTrue(f.is_email_delivered)

    def test_hostname_email_delivered_flag(self):
        f = self.fx.extract_from_hostname(
            "test.ip6.arpa", is_email_delivered=True
        )
        self.assertTrue(f.is_email_delivered)

    # --- Hostname normalization ---

    def test_hostname_lowercased(self):
        f = self.fx.extract_from_hostname("ABC.IP6.ARPA")
        self.assertEqual(f.hostname, "abc.ip6.arpa")

    def test_hostname_trailing_dot_stripped(self):
        f = self.fx.extract_from_hostname("test.ip6.arpa.")
        self.assertEqual(f.hostname, "test.ip6.arpa")

    def test_hostname_whitespace_stripped(self):
        f = self.fx.extract_from_hostname("  test.arpa  ")
        self.assertEqual(f.hostname, "test.arpa")

    # --- Hostname length ---

    def test_hostname_length_calculated(self):
        hostname = "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        f = self.fx.extract_from_hostname(hostname)
        self.assertEqual(f.hostname_length, len(hostname))

    # --- Label count ---

    def test_label_count(self):
        f = self.fx.extract_from_hostname("a.b.c.ip6.arpa")
        self.assertEqual(f.label_count, 5)

    # --- Features to_dict ---

    def test_features_to_dict(self):
        f = Features(hostname="test.arpa", is_arpa_tld=True)
        d = f.to_dict()
        self.assertEqual(d["hostname"], "test.arpa")
        self.assertTrue(d["is_arpa_tld"])


class TestShannonEntropy(unittest.TestCase):
    """Tests for the Shannon entropy utility function."""

    def test_empty_string(self):
        self.assertEqual(_shannon_entropy(""), 0.0)

    def test_single_char(self):
        self.assertEqual(_shannon_entropy("a"), 0.0)

    def test_uniform_distribution(self):
        # "ab" has 2 chars, each with probability 0.5 → entropy = 1.0 bit
        self.assertAlmostEqual(_shannon_entropy("ab"), 1.0, places=3)

    def test_high_entropy_string(self):
        # Random-looking strings should have high entropy
        entropy = _shannon_entropy("abcdefghij")
        self.assertGreater(entropy, 3.0)

    def test_low_entropy_string(self):
        # Repetitive strings should have low entropy
        entropy = _shannon_entropy("aaaa")
        self.assertEqual(entropy, 0.0)


# ═══════════════════════════════════════════════════════════════════════════
# SCORER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestScorer(unittest.TestCase):
    """Tests for scorer.py — signal triggering, scoring, and verdicts."""

    def setUp(self):
        self.scorer = Scorer()
        self.fx = FeatureExtractor()

    # --- Verdict thresholds ---

    def test_low_verdict(self):
        self.assertEqual(self.scorer._verdict(0), "low")
        self.assertEqual(self.scorer._verdict(30), "low")

    def test_medium_verdict(self):
        self.assertEqual(self.scorer._verdict(31), "medium")
        self.assertEqual(self.scorer._verdict(60), "medium")

    def test_high_verdict(self):
        self.assertEqual(self.scorer._verdict(61), "high")
        self.assertEqual(self.scorer._verdict(100), "high")

    # --- Score clamping ---

    def test_score_capped_at_100(self):
        """Malicious IOC with all signals should cap at 100."""
        f = self.fx.extract_from_url(
            "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True
        )
        result = self.scorer.score(f, cdn_resolved=True)
        self.assertLessEqual(result.score, 100)

    def test_score_floored_at_zero(self):
        """Score should never go below 0, even with negative signals."""
        f = Features()
        # Manually construct a scenario where only negative signal fires
        # This shouldn't naturally happen, but tests the floor
        f.is_arpa_tld = False
        result = self.scorer.score(f)
        self.assertGreaterEqual(result.score, 0)

    # --- Known IOC patterns → HIGH ---

    def test_known_ioc_scores_high(self):
        """Exact IOC from Infoblox report should score HIGH."""
        f = self.fx.extract_from_url(
            "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True,
        )
        result = self.scorer.score(f)
        self.assertEqual(result.verdict, "high")
        self.assertGreaterEqual(result.score, 61)

    def test_variant_ioc_scores_high(self):
        f = self.fx.extract_from_url(
            "https://xkzpqmwrtu.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True,
        )
        result = self.scorer.score(f)
        self.assertEqual(result.verdict, "high")

    def test_hostname_ioc_with_email_scores_high(self):
        f = self.fx.extract_from_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True,
        )
        result = self.scorer.score(f)
        self.assertEqual(result.verdict, "high")

    # --- Benign patterns → LOW ---

    def test_normal_domain_scores_low(self):
        f = self.fx.extract_from_url("https://google.com")
        result = self.scorer.score(f)
        self.assertEqual(result.verdict, "low")
        # HTTP_CONTEXT fires (+10) for any https:// URL — still well below threshold
        self.assertLessEqual(result.score, 30)

    def test_inaddr_arpa_ptr_scores_low(self):
        f = self.fx.extract_from_hostname("4.3.2.1.in-addr.arpa")
        result = self.scorer.score(f)
        self.assertEqual(result.verdict, "low")

    def test_full_32_nibble_ptr_no_dga_scores_low(self):
        """Legitimate full 32-nibble PTR should get the negative signal reduction."""
        f = self.fx.extract_from_hostname(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
        result = self.scorer.score(f)
        # Should be low or medium — not high
        self.assertNotEqual(result.verdict, "high")
        # The LIKELY_LEGIT_PTR signal should have fired
        signal_names = [s.name for s in result.triggered_signals]
        self.assertIn("LIKELY_LEGIT_PTR", signal_names)

    # --- Medium risk patterns ---

    def test_ip6_arpa_http_no_dga_scores_medium(self):
        """ip6.arpa in HTTP context without DGA prefix = partial signal."""
        f = self.fx.extract_from_url(
            "https://5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        result = self.scorer.score(f)
        self.assertIn(result.verdict, ("medium", "high"))

    # --- Individual signal triggering ---

    def test_arpa_tld_signal_fires(self):
        f = self.fx.extract_from_hostname("test.arpa")
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("ARPA_TLD", names)

    def test_http_context_signal_fires(self):
        f = self.fx.extract_from_url("https://test.arpa")
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("HTTP_CONTEXT", names)

    def test_email_delivered_signal_fires(self):
        f = self.fx.extract_from_hostname("test.arpa", is_email_delivered=True)
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("EMAIL_DELIVERED", names)

    def test_cdn_resolution_signal_fires(self):
        f = self.fx.extract_from_hostname("test.arpa")
        result = self.scorer.score(f, cdn_resolved=True)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("CDN_RESOLUTION", names)

    def test_long_hostname_signal_fires(self):
        f = self.fx.extract_from_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        self.assertGreaterEqual(f.hostname_length, 40)
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("LONG_HOSTNAME", names)

    def test_dns_no_response_signal_fires(self):
        f = self.fx.extract_from_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        f.dns_was_checked = True
        f.dns_resolved = False
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("DNS_NO_RESPONSE", names)

    def test_dns_no_response_does_not_fire_without_check(self):
        """DNS_NO_RESPONSE should NOT fire when DNS was never attempted."""
        f = self.fx.extract_from_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        # dns_was_checked defaults to False
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertNotIn("DNS_NO_RESPONSE", names)

    def test_resolves_as_a_record_signal_fires(self):
        f = self.fx.extract_from_hostname("test.arpa")
        f.dns_resolved = True
        f.dns_ips = "1.2.3.4"
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("RESOLVES_AS_A_RECORD", names)

    def test_partial_nibble_delegation_signal_fires(self):
        """16-nibble run (a /64 block) should trigger PARTIAL_NIBBLE_DELEGATION."""
        f = self.fx.extract_from_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
        )
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertIn("PARTIAL_NIBBLE_DELEGATION", names)

    def test_likely_legit_ptr_does_not_fire_with_dga(self):
        """LIKELY_LEGIT_PTR should NOT fire if DGA prefix is present."""
        f = self.fx.extract_from_url(
            "https://abcdefghijkl.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True,
        )
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertNotIn("LIKELY_LEGIT_PTR", names)

    def test_likely_legit_ptr_does_not_fire_in_http_context(self):
        """LIKELY_LEGIT_PTR should NOT fire when in HTTP context."""
        f = self.fx.extract_from_url(
            "https://1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
        result = self.scorer.score(f)
        names = [s.name for s in result.triggered_signals]
        self.assertNotIn("LIKELY_LEGIT_PTR", names)

    # --- ScoringResult methods ---

    def test_scoring_result_to_dict(self):
        f = self.fx.extract_from_hostname("test.arpa")
        result = self.scorer.score(f)
        d = result.to_dict()
        self.assertIn("hostname", d)
        self.assertIn("score", d)
        self.assertIn("verdict", d)
        self.assertIn("triggered_signals", d)

    def test_scoring_result_verdict_emoji(self):
        f = self.fx.extract_from_url(
            "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True,
        )
        result = self.scorer.score(f)
        self.assertEqual(result.verdict_emoji, "🔴")

    def test_no_signals_explanation(self):
        f = self.fx.extract_from_hostname("google.com")
        result = self.scorer.score(f)
        self.assertIn("No suspicious signals", result.explanation)

    def test_signal_to_dict(self):
        s = Signal(name="TEST", description="test desc", weight=10, triggered=True, detail="detail")
        d = s.to_dict()
        self.assertEqual(d["name"], "TEST")
        self.assertEqual(d["weight"], 10)
        self.assertTrue(d["triggered"])

    def test_signal_to_dict_untriggered_weight_zero(self):
        s = Signal(name="TEST", description="test desc", weight=10, triggered=False)
        d = s.to_dict()
        self.assertEqual(d["weight"], 0)


# ═══════════════════════════════════════════════════════════════════════════
# DNS_UTILS TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestDnsUtils(unittest.TestCase):
    """Tests for dns_utils.py — CDN IP matching and DNS helpers."""

    def test_cdn_networks_loaded(self):
        self.assertGreater(len(_CDN_NETWORKS), 0)

    # --- CDN IP matching ---

    def test_cloudflare_ip_detected(self):
        self.assertTrue(_is_cdn_ip("104.16.0.1"))

    def test_fastly_ip_detected(self):
        self.assertTrue(_is_cdn_ip("151.101.1.1"))

    def test_akamai_ip_detected(self):
        self.assertTrue(_is_cdn_ip("23.32.0.1"))

    def test_cloudfront_ip_detected(self):
        self.assertTrue(_is_cdn_ip("54.230.0.1"))

    def test_non_cdn_ip_not_detected(self):
        self.assertFalse(_is_cdn_ip("8.8.8.8"))  # Google DNS

    def test_private_ip_not_cdn(self):
        self.assertFalse(_is_cdn_ip("192.168.1.1"))

    def test_invalid_ip_returns_false(self):
        self.assertFalse(_is_cdn_ip("not-an-ip"))

    def test_empty_string_returns_false(self):
        self.assertFalse(_is_cdn_ip(""))

    # --- IPv6 CDN detection ---

    def test_cloudflare_ipv6_detected(self):
        self.assertTrue(_is_cdn_ip("2606:4700::1"))

    def test_non_cdn_ipv6_not_detected(self):
        self.assertFalse(_is_cdn_ip("2001:4860:4860::8888"))  # Google DNS

    # --- DNS resolution (mocked) ---

    @patch("dns_utils.socket.getaddrinfo")
    def test_resolve_a_records_success(self, mock_getaddrinfo):
        from dns_utils import resolve_a_records
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('1.2.3.4', 0)),
            (2, 1, 6, '', ('5.6.7.8', 0)),
        ]
        ips = resolve_a_records("test.example.com")
        self.assertEqual(ips, ["1.2.3.4", "5.6.7.8"])

    @patch("dns_utils.socket.getaddrinfo")
    def test_resolve_a_records_deduplicates(self, mock_getaddrinfo):
        from dns_utils import resolve_a_records
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('1.2.3.4', 0)),
            (2, 1, 6, '', ('1.2.3.4', 0)),
        ]
        ips = resolve_a_records("test.example.com")
        self.assertEqual(ips, ["1.2.3.4"])

    @patch("dns_utils.socket.getaddrinfo")
    def test_resolve_a_records_failure_returns_empty(self, mock_getaddrinfo):
        import socket
        from dns_utils import resolve_a_records
        mock_getaddrinfo.side_effect = socket.gaierror("DNS failed")
        ips = resolve_a_records("nonexistent.example.com")
        self.assertEqual(ips, [])

    @patch("dns_utils.socket.getaddrinfo")
    def test_resolves_to_cdn_true(self, mock_getaddrinfo):
        from dns_utils import resolves_to_cdn
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('104.16.0.1', 0)),  # Cloudflare
        ]
        self.assertTrue(resolves_to_cdn("test.example.com"))

    @patch("dns_utils.socket.getaddrinfo")
    def test_resolves_to_cdn_false(self, mock_getaddrinfo):
        from dns_utils import resolves_to_cdn
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('8.8.8.8', 0)),  # Google DNS — not CDN
        ]
        self.assertFalse(resolves_to_cdn("test.example.com"))

    @patch("dns_utils.socket.getaddrinfo")
    def test_get_resolution_summary(self, mock_getaddrinfo):
        from dns_utils import get_resolution_summary
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('104.16.0.1', 0)),
        ]
        summary = get_resolution_summary("test.example.com")
        self.assertTrue(summary["resolved"])
        self.assertTrue(summary["cdn_resolved"])
        self.assertEqual(summary["ip_addresses"], ["104.16.0.1"])
        self.assertEqual(summary["cdn_ips"], ["104.16.0.1"])

    @patch("dns_utils.socket.getaddrinfo")
    def test_get_resolution_summary_no_resolution(self, mock_getaddrinfo):
        import socket
        from dns_utils import get_resolution_summary
        mock_getaddrinfo.side_effect = socket.gaierror("DNS failed")
        summary = get_resolution_summary("nonexistent.example.com")
        self.assertFalse(summary["resolved"])
        self.assertFalse(summary["cdn_resolved"])
        self.assertEqual(summary["ip_addresses"], [])


# ═══════════════════════════════════════════════════════════════════════════
# EMAIL_PARSER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestEmailParser(unittest.TestCase):
    """Tests for email_parser.py — URL extraction from email content."""

    # --- HTML link extraction ---

    def test_extract_href_from_html(self):
        html = '<html><body><a href="https://evil.ip6.arpa/track">Click</a></body></html>'
        links = extract_links(html)
        urls = [l.url for l in links]
        self.assertIn("https://evil.ip6.arpa/track", urls)

    def test_extract_img_src_from_html(self):
        html = '<html><body><img src="https://cdn.example.com/image.png" /></body></html>'
        links = extract_links(html)
        urls = [l.url for l in links]
        self.assertIn("https://cdn.example.com/image.png", urls)

    def test_image_wrapped_link_detected(self):
        """The core phishing pattern: <a href=malicious><img src=legit></a>"""
        html = '''<html><body>
        <a href="https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa">
            <img src="https://cdn.example.com/promo.png" />
        </a>
        </body></html>'''
        links = extract_links(html)
        arpa_links = [l for l in links if l.is_arpa]
        self.assertGreater(len(arpa_links), 0)
        # At least one arpa link should be image-wrapped
        image_wrapped_arpa = [l for l in arpa_links if l.is_image_link]
        self.assertGreater(len(image_wrapped_arpa), 0)

    def test_arpa_flagged_in_links(self):
        html = '<a href="https://test.ip6.arpa">Click</a>'
        links = extract_links(html)
        arpa = [l for l in links if l.is_arpa]
        self.assertGreater(len(arpa), 0)

    def test_non_arpa_not_flagged(self):
        html = '<a href="https://google.com">Click</a>'
        links = extract_links(html)
        arpa = [l for l in links if l.is_arpa]
        self.assertEqual(len(arpa), 0)

    # --- Plaintext extraction ---

    def test_extract_urls_from_plaintext(self):
        text = "Check this out: https://example.com/page and https://test.arpa/path"
        links = extract_links(text)
        urls = [l.url for l in links]
        self.assertIn("https://example.com/page", urls)
        self.assertIn("https://test.arpa/path", urls)

    def test_plaintext_trailing_punctuation_stripped(self):
        text = "Visit https://example.com/page."
        links = extract_links(text)
        urls = [l.url for l in links]
        self.assertIn("https://example.com/page", urls)
        self.assertNotIn("https://example.com/page.", urls)

    # --- Deduplication ---

    def test_duplicate_urls_deduplicated(self):
        html = '''<html><body>
        <a href="https://example.com">Link 1</a>
        <a href="https://example.com">Link 2</a>
        </body></html>'''
        links = extract_links(html)
        urls = [l.url for l in links]
        self.assertEqual(urls.count("https://example.com"), 1)

    def test_deduplication_across_html_and_plaintext(self):
        """URLs found by both HTML parser and regex should not duplicate."""
        html = '<html><body><a href="https://example.com">Link</a> https://example.com</body></html>'
        links = extract_links(html)
        urls = [l.url for l in links]
        self.assertEqual(urls.count("https://example.com"), 1)

    # --- extract_arpa_links convenience ---

    def test_extract_arpa_links(self):
        html = '''<html><body>
        <a href="https://evil.ip6.arpa">Bad</a>
        <a href="https://google.com">Good</a>
        </body></html>'''
        arpa = extract_arpa_links(html)
        self.assertEqual(len(arpa), 1)
        self.assertIn("arpa", arpa[0].url)

    # --- summarize_links ---

    def test_summarize_links(self):
        links = [
            ExtractedLink(url="https://evil.arpa", hostname="evil.arpa", source="href", is_arpa=True, is_image_link=True),
            ExtractedLink(url="https://good.com", hostname="good.com", source="href", is_arpa=False, is_image_link=False),
        ]
        summary = summarize_links(links)
        self.assertEqual(summary["total_links"], 2)
        self.assertEqual(summary["arpa_links"], 1)
        self.assertEqual(summary["image_wrapped_links"], 1)
        self.assertEqual(summary["arpa_image_links"], 1)

    # --- Edge cases ---

    def test_empty_content(self):
        links = extract_links("")
        self.assertEqual(len(links), 0)

    def test_no_links_in_content(self):
        links = extract_links("This is plain text with no links at all.")
        self.assertEqual(len(links), 0)

    def test_malformed_html_doesnt_crash(self):
        html = '<a href="https://test.com"><img src="broken><div>mess</a>'
        links = extract_links(html)
        # Should not raise — results may vary but shouldn't crash
        self.assertIsInstance(links, list)


# ═══════════════════════════════════════════════════════════════════════════
# DETECTOR INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectorIntegration(unittest.TestCase):
    """Integration tests for detector.py — analyze_url and analyze_hostname."""

    # --- Known malicious patterns ---

    def test_analyze_url_known_ioc(self):
        result = analyze_url(
            "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True,
        )
        self.assertEqual(result.verdict, "high")
        self.assertGreaterEqual(result.score, 61)

    def test_analyze_hostname_known_ioc(self):
        result = analyze_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            is_email_delivered=True,
        )
        self.assertEqual(result.verdict, "high")

    # --- Known benign patterns ---

    def test_analyze_url_benign(self):
        result = analyze_url("https://google.com/search?q=test")
        self.assertEqual(result.verdict, "low")
        # HTTP_CONTEXT fires (+10) for any https:// URL — still well below threshold
        self.assertLessEqual(result.score, 30)

    def test_analyze_hostname_benign_ptr(self):
        result = analyze_hostname("4.3.2.1.in-addr.arpa")
        self.assertEqual(result.verdict, "low")

    def test_analyze_hostname_benign_full_ptr(self):
        result = analyze_hostname(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
        self.assertNotEqual(result.verdict, "high")

    # --- Non-.arpa phishing (comparison) ---

    def test_non_arpa_phishing_scores_low(self):
        result = analyze_url("https://secure-paypal-verify.phishingsite.com/login")
        self.assertEqual(result.verdict, "low")
        # HTTP_CONTEXT fires (+10) for any https:// URL — still well below threshold
        self.assertLessEqual(result.score, 30)

    # --- DNS integration (mocked) ---

    @patch("detector.get_resolution_summary")
    def test_analyze_url_with_dns(self, mock_dns):
        mock_dns.return_value = {
            "resolved": True,
            "cdn_resolved": True,
            "ip_addresses": ["104.16.0.1"],
            "cdn_ips": ["104.16.0.1"],
        }
        result = analyze_url(
            "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            run_dns=True,
        )
        self.assertEqual(result.verdict, "high")
        signal_names = [s.name for s in result.triggered_signals]
        self.assertIn("CDN_RESOLUTION", signal_names)
        self.assertIn("RESOLVES_AS_A_RECORD", signal_names)

    @patch("detector.get_resolution_summary")
    def test_analyze_hostname_with_dns(self, mock_dns):
        mock_dns.return_value = {
            "resolved": True,
            "cdn_resolved": False,
            "ip_addresses": ["8.8.8.8"],
            "cdn_ips": [],
        }
        result = analyze_hostname(
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            run_dns=True,
        )
        signal_names = [s.name for s in result.triggered_signals]
        self.assertIn("RESOLVES_AS_A_RECORD", signal_names)
        self.assertNotIn("CDN_RESOLUTION", signal_names)

    # --- Return type checks ---

    def test_analyze_url_returns_scoring_result(self):
        result = analyze_url("https://example.com")
        self.assertIsInstance(result, ScoringResult)

    def test_analyze_hostname_returns_scoring_result(self):
        result = analyze_hostname("example.com")
        self.assertIsInstance(result, ScoringResult)

    def test_result_has_features(self):
        result = analyze_url("https://test.arpa")
        self.assertIsInstance(result.features, Features)

    # --- Full test dataset validation ---

    def test_all_malicious_samples_score_high(self):
        """Every known malicious IOC from the dataset must score HIGH."""
        malicious_urls = [
            ("https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa", True),
            ("https://xkzpqmwrtu.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa", True),
            ("http://pqrstuabcd.1.9.5.0.9.1.0.0.0.7.4.0.1.0.0.2.ip6.arpa", True),
            ("http://randomxyz00.9.a.d.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa", True),
            ("https://lmnoabcdef.8.1.9.5.0.9.1.0.0.0.7.4.0.1.0.0.2.ip6.arpa", True),
        ]
        for url, email_delivered in malicious_urls:
            result = analyze_url(url, is_email_delivered=email_delivered)
            self.assertEqual(
                result.verdict, "high",
                f"Expected HIGH for {url}, got {result.verdict} (score={result.score})"
            )

    def test_no_false_negatives_hostnames(self):
        """Hostname-only malicious samples must also score HIGH."""
        hostnames = [
            "abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            "xkzpqmwrtu.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
        ]
        for hostname in hostnames:
            result = analyze_hostname(hostname, is_email_delivered=True)
            self.assertEqual(
                result.verdict, "high",
                f"Expected HIGH for {hostname}, got {result.verdict} (score={result.score})"
            )

    def test_benign_domains_not_high(self):
        """Known benign domains must NOT score HIGH."""
        benign = [
            "google.com",
            "microsoft.com",
            "dns.google",
            "ns1.cloudflare.com",
            "4.3.2.1.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
        ]
        for hostname in benign:
            result = analyze_hostname(hostname)
            self.assertNotEqual(
                result.verdict, "high",
                f"Expected NOT HIGH for {hostname}, got {result.verdict} (score={result.score})"
            )

    def test_comparison_phishing_scores_low(self):
        """Non-.arpa phishing domains should score LOW (detector is .arpa-specific)."""
        comparison = [
            "https://secure-paypal-verify.phishingsite.com/login",
            "https://amazon-prize-claim.shop/redeem?id=abc123",
            "https://microsoft365-account-suspended.net/verify",
        ]
        for url in comparison:
            result = analyze_url(url)
            self.assertEqual(
                result.verdict, "low",
                f"Expected LOW for {url}, got {result.verdict} (score={result.score})"
            )


# ═══════════════════════════════════════════════════════════════════════════
# EDGE CASE & SECURITY TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    """Edge cases and security-related tests."""

    def setUp(self):
        self.fx = FeatureExtractor()

    def test_empty_url(self):
        result = analyze_url("")
        self.assertIsInstance(result, ScoringResult)

    def test_empty_hostname(self):
        result = analyze_hostname("")
        self.assertIsInstance(result, ScoringResult)

    def test_very_long_input(self):
        """Extremely long input should not crash."""
        long_hostname = "a" * 1000 + ".ip6.arpa"
        result = analyze_hostname(long_hostname)
        self.assertIsInstance(result, ScoringResult)

    def test_unicode_hostname(self):
        """Unicode characters in hostname should not crash."""
        result = analyze_hostname("tëst.arpa")
        self.assertIsInstance(result, ScoringResult)

    def test_xss_in_hostname_does_not_propagate(self):
        """HTML/JS in hostname should be safely handled."""
        result = analyze_hostname('<script>alert(1)</script>.arpa')
        self.assertIsInstance(result, ScoringResult)
        # The hostname should be stored but not cause issues
        self.assertIn("arpa", result.features.hostname)

    def test_null_bytes_in_hostname(self):
        result = analyze_hostname("test\x00.arpa")
        self.assertIsInstance(result, ScoringResult)

    def test_url_with_credentials(self):
        """URL with embedded credentials should parse without crashing."""
        result = analyze_url("https://user:pass@test.ip6.arpa/path")
        self.assertIsInstance(result, ScoringResult)
        self.assertTrue(result.features.is_arpa_tld)

    def test_url_with_port(self):
        result = analyze_url("https://test.ip6.arpa:8443/path")
        self.assertIsInstance(result, ScoringResult)
        self.assertTrue(result.features.is_arpa_tld)

    def test_url_with_query_and_fragment(self):
        result = analyze_url("https://test.ip6.arpa/path?q=1&r=2#frag")
        self.assertIsInstance(result, ScoringResult)

    def test_ftp_scheme_not_http_context(self):
        f = self.fx.extract_from_url("ftp://test.arpa/file")
        self.assertFalse(f.used_in_http_context)

    def test_javascript_scheme_not_http_context(self):
        f = self.fx.extract_from_url("javascript://test.arpa")
        self.assertFalse(f.used_in_http_context)


if __name__ == "__main__":
    unittest.main()
