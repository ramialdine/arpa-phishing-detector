"""
email_parser.py — Extract URLs from raw email content.

Handles both HTML emails (href attributes, src attributes) and plaintext emails.
Specifically looks for .arpa domains hidden in image hyperlinks — the exact
delivery mechanism used in the campaign documented by Infoblox (Feb 2026).

Attack pattern:
    <a href="http://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa">
      <img src="https://legitimate-cdn.com/prize-image.png" />
    </a>

The domain is never displayed to the user — only the image is visible.
"""

import re
import logging
from html.parser import HTMLParser
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# URLs in plain text — http/https/ftp
_URL_RE = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

# href="..." or href='...'
_HREF_RE = re.compile(
    r'href=["\']([^"\']+)["\']',
    re.IGNORECASE
)

# src="..." (for image src links)
_SRC_RE = re.compile(
    r'src=["\']([^"\']+)["\']',
    re.IGNORECASE
)

# .arpa domain pattern — used to flag .arpa-specific links quickly
_ARPA_RE = re.compile(r'\.arpa\b', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ExtractedLink:
    url: str
    hostname: str
    source: str          # "href", "src", "plaintext"
    is_arpa: bool = False
    is_image_link: bool = False   # was it inside an <a> wrapping an <img>?
    line_number: Optional[int] = None

    def to_dict(self) -> dict:
        return self.__dict__


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------

class _LinkCollector(HTMLParser):
    """
    Custom HTMLParser that tracks <a href> wrapping <img src>.
    This is the exact phishing delivery pattern: victim sees the image,
    never the malicious .arpa domain in the href.
    """

    def __init__(self):
        super().__init__()
        self.links: list[ExtractedLink] = []
        self._current_href: Optional[str] = None
        self._in_anchor: bool = False
        self._anchor_has_img: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple]):
        attr_dict = dict(attrs)

        if tag == "a":
            self._in_anchor = True
            self._anchor_has_img = False
            self._current_href = attr_dict.get("href")

        elif tag == "img":
            src = attr_dict.get("src")
            if src:
                link = _make_link(src, source="src", is_image_link=False)
                self.links.append(link)

            # If this img is inside an <a>, mark the href as image-wrapped
            if self._in_anchor and self._current_href:
                self._anchor_has_img = True

    def handle_endtag(self, tag: str):
        if tag == "a" and self._current_href:
            link = _make_link(
                self._current_href,
                source="href",
                is_image_link=self._anchor_has_img
            )
            self.links.append(link)
            self._in_anchor = False
            self._current_href = None
            self._anchor_has_img = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_links(email_content: str) -> list[ExtractedLink]:
    """
    Extract all URLs/hostnames from raw email content (HTML or plain text).

    Returns a list of ExtractedLink objects, deduplicated by URL.
    .arpa links are flagged automatically.
    """
    links: list[ExtractedLink] = []
    seen: set[str] = set()

    # --- HTML extraction ---
    if _looks_like_html(email_content):
        collector = _LinkCollector()
        try:
            collector.feed(email_content)
            for link in collector.links:
                if link.url not in seen:
                    seen.add(link.url)
                    links.append(link)
        except Exception:
            log.debug("HTML parsing failed, falling back to regex extraction")

        # Also extract href/src via regex as a backup
        for m in _HREF_RE.finditer(email_content):
            url = m.group(1)
            if url not in seen:
                seen.add(url)
                links.append(_make_link(url, source="href"))

    # --- Plaintext / regex extraction ---
    for m in _URL_RE.finditer(email_content):
        url = m.group(0).rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            links.append(_make_link(url, source="plaintext"))

    return links


def extract_arpa_links(email_content: str) -> list[ExtractedLink]:
    """
    Convenience function — returns only .arpa domain links from email content.
    These are the highest-priority candidates for phishing analysis.
    """
    return [link for link in extract_links(email_content) if link.is_arpa]


def summarize_links(links: list[ExtractedLink]) -> dict:
    """Return a summary dict for display in CLI / Streamlit."""
    arpa = [l for l in links if l.is_arpa]
    image_wrapped = [l for l in links if l.is_image_link]
    return {
        "total_links": len(links),
        "arpa_links": len(arpa),
        "image_wrapped_links": len(image_wrapped),
        "arpa_image_links": len([l for l in arpa if l.is_image_link]),
        "links": [l.to_dict() for l in links],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_link(url: str, source: str, is_image_link: bool = False) -> ExtractedLink:
    url = url.strip()
    hostname = _extract_hostname(url)
    return ExtractedLink(
        url=url,
        hostname=hostname,
        source=source,
        is_arpa=bool(_ARPA_RE.search(url)),
        is_image_link=is_image_link,
    )


def _extract_hostname(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.hostname or url
    except Exception:
        return url


def _looks_like_html(content: str) -> bool:
    sample = content[:2000].lower()
    return "<html" in sample or "<body" in sample or "<a " in sample or "<img" in sample
