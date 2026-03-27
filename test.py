import detector
from detector import analyze_hostname


# Use cloudflare.com as a proxy test — not .arpa but confirms the pipeline
from dns_utils import get_resolution_summary
from extractor import FeatureExtractor
from scorer import Scorer

# Manually simulate what happens when a .arpa domain resolves to a CDN
fx = FeatureExtractor()
features = fx.extract_from_hostname("abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa")

# Manually inject what DNS would have returned
features.dns_was_checked = True
features.dns_resolved = True
features.dns_cdn_resolved = True
features.dns_ips = "104.16.132.229"  # a real Cloudflare IP

result = Scorer().score(features, cdn_resolved=True)
result.pretty_print()