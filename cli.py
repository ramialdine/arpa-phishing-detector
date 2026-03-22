#!/usr/bin/env python3
"""
cli.py — Command-line interface for the .arpa phishing detector.

Usage:
    python cli.py --url "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
    python cli.py --hostname "abcdefghij.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
    python cli.py --email email_sample.html
    python cli.py --url "..." --dns           # live DNS resolution
    python cli.py --url "..." --json          # JSON output
"""

import argparse
import json
import sys
import os

# Allow running from project root without install
sys.path.insert(0, os.path.dirname(__file__))

from detector import analyze_url, analyze_hostname, extract_links, summarize_links
from email_parser import extract_arpa_links


BANNER = r"""
 █████╗ ██████╗ ██████╗  █████╗      ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗     ██╔══██╗██║  ██║██║██╔════╝██║  ██║
███████║██████╔╝██████╔╝███████║     ██████╔╝███████║██║███████╗███████║
██╔══██║██╔══██╗██╔═══╝ ██╔══██║     ██╔═══╝ ██╔══██║██║╚════██║██╔══██║
██║  ██║██║  ██║██║     ██║  ██║     ██║     ██║  ██║██║███████║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝

  .arpa Phishing Detection Engine  |  github.com/ramialdine
  Based on Infoblox Threat Intel research (Feb 2026)
"""


def main():
    parser = argparse.ArgumentParser(
        description=".arpa Phishing Detector — identifies abuse of .arpa DNS infrastructure in phishing campaigns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --url "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
  python cli.py --hostname "xkzpqmwrtu.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"
  python cli.py --email samples/phish_email.html
  python cli.py --url "..." --email-delivered --dns --json
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", metavar="URL", help="Analyze a URL")
    group.add_argument("--hostname", metavar="HOST", help="Analyze a bare hostname")
    group.add_argument("--email", metavar="FILE", help="Parse email file and analyze all extracted links")

    parser.add_argument(
        "--email-delivered", action="store_true",
        help="Flag: input was delivered via email (adds +10 to score)"
    )
    parser.add_argument(
        "--dns", action="store_true",
        help="Perform live DNS resolution (CDN check). Adds latency."
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress banner and verbose output"
    )

    args = parser.parse_args()

    if not args.quiet and not args.json:
        print(BANNER)

    # ── URL mode ──────────────────────────────────────────────────────────
    if args.url:
        result = analyze_url(
            args.url,
            is_email_delivered=args.email_delivered,
            run_dns=args.dns
        )
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            result.pretty_print()
            _print_dns_note(args.dns)

    # ── Hostname mode ─────────────────────────────────────────────────────
    elif args.hostname:
        result = analyze_hostname(
            args.hostname,
            is_email_delivered=args.email_delivered,
            run_dns=args.dns
        )
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            result.pretty_print()
            _print_dns_note(args.dns)

    # ── Email file mode ───────────────────────────────────────────────────
    elif args.email:
        try:
            with open(args.email, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.email}", file=sys.stderr)
            sys.exit(1)

        links = extract_links(content)
        summary = summarize_links(links)

        if not args.json and not args.quiet:
            print(f"  📧  Parsed: {args.email}")
            print(f"  🔗  Links found: {summary['total_links']}")
            print(f"  ⚠️   .arpa links: {summary['arpa_links']}")
            print(f"  🖼️   Image-wrapped links: {summary['image_wrapped_links']}")
            print()

        results = []
        for link in links:
            r = analyze_url(
                link.url,
                is_email_delivered=True,
                run_dns=args.dns
            )
            if args.json:
                results.append({**r.to_dict(), "source": link.source, "is_image_link": link.is_image_link})
            else:
                if r.score > 0:
                    print(f"  Source: {link.source} | Image-wrapped: {link.is_image_link}")
                    r.pretty_print()

        if args.json:
            print(json.dumps({"email_file": args.email, "summary": summary, "results": results}, indent=2))

        if not args.json and not args.quiet:
            _print_dns_note(args.dns)


def _print_dns_note(dns_enabled: bool):
    if not dns_enabled:
        print("  ℹ️  DNS resolution disabled. Use --dns flag for CDN detection.")
        print("     Note: live DNS adds latency and may alert defenders if target is monitored.\n")


if __name__ == "__main__":
    main()
