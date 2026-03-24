"""
app.py — Streamlit UI for the .arpa phishing detector.

Run with: streamlit run app.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
from detector import analyze_url, analyze_hostname, extract_links, summarize_links
from detector.extractor import FeatureExtractor
from detector.dns_utils import get_resolution_summary


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title=".arpa Phishing Detector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------

st.markdown("""
<style>
    .verdict-high   { color: #FF4B4B; font-size: 1.8rem; font-weight: bold; }
    .verdict-medium { color: #FFA500; font-size: 1.8rem; font-weight: bold; }
    .verdict-low    { color: #21C55D; font-size: 1.8rem; font-weight: bold; }
    .signal-card    { background: #1E1E2E; border-radius: 8px; padding: 12px 16px; margin: 6px 0; border-left: 4px solid #FF4B4B; }
    .signal-card-info { border-left-color: #3B82F6; }
    .score-bar-bg   { background: #2D2D3F; border-radius: 4px; height: 20px; }
    .monospace      { font-family: monospace; font-size: 0.85rem; }
    .ioc-tag        { background: #FF4B4B22; color: #FF4B4B; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-family: monospace; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.image("https://img.shields.io/badge/.arpa-Phish%20Detector-red?style=for-the-badge", use_column_width=True)
    st.markdown("### ⚙️ Settings")

    run_dns = st.toggle("🌐 Live DNS Resolution", value=False, help="Resolve hostname and check for CDN IPs. Adds latency.")
    email_delivered = st.toggle("📧 Mark as Email-Delivered", value=False, help="Flag if the input was extracted from an email.")

    st.divider()

    st.markdown("### 📖 About")
    st.markdown("""
    This tool detects abuse of the `.arpa` TLD for phishing delivery.

    **Attack Pattern:**
    - Attacker claims IPv6 /64 block via free tunnel service
    - Creates **A records** (not PTR) under their `.arpa` subdomain
    - Prepends random DGA prefix for uniqueness
    - Embeds domain in phishing email image hyperlink

    **Why it evades detection:**
    - `.arpa` has implicit trusted reputation
    - No WHOIS registration data
    - Not on traditional blocklists
    - Domain is hidden behind image in email

    **References:**
    - [Infoblox Blog (Feb 2026)](https://www.infoblox.com/blog/threat-intelligence/abusing-arpa-the-tld-that-isnt-supposed-to-host-anything/)
    """)

    st.divider()
    st.markdown("**Scoring Weights:**")
    weights = {
        "ARPA_TLD": 25, "IP6_ARPA_ZONE": 10, "INADDR_ARPA_ZONE": 5,
        "IPV6_NIBBLE_PATTERN": 20, "DGA_PREFIX": 15,
        "LONG_HOSTNAME": 10, "VERY_LONG_HOSTNAME": 5,
        "HTTP_CONTEXT": 10, "EMAIL_DELIVERED": 10, "CDN_RESOLUTION": 10
    }
    for name, w in weights.items():
        st.markdown(f"`{name}` → **{w} pts**")


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("🔍 .arpa Phishing Detection Engine")
st.caption("Detects abuse of `.arpa` DNS infrastructure as phishing delivery mechanism · Based on Infoblox Threat Intel (Feb 2026)")

# IOC quick reference
with st.expander("📋 Known IOC Patterns (from Infoblox report)", expanded=False):
    st.markdown("""
    | Pattern | Description |
    |---------|------------|
    | `<10 random letters>.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa` | IPv6 reverse DNS + DGA subdomain |
    | `<10 random letters>.d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa` | Variant IPv6 block |
    | `<10 random letters>.8.1.9.5.0.9.1.0.0.0.7.4.0.1.0.0.2.ip6.arpa` | Variant IPv6 block |
    | `<10 random letters>.9.a.d.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa` | Variant IPv6 block |
    """)

st.divider()


# ---------------------------------------------------------------------------
# Input tabs
# ---------------------------------------------------------------------------

tab1, tab2, tab3 = st.tabs(["🔗 URL / Hostname", "📧 Email Content", "🗂️ Batch"])


# ── Tab 1: Single URL/hostname ────────────────────────────────────────────

with tab1:
    col1, col2 = st.columns([3, 1])

    with col1:
        user_input = st.text_input(
            "Enter URL or hostname to analyze:",
            placeholder="https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
            key="url_input",
        )

    with col2:
        input_type = st.selectbox("Input type", ["Auto-detect", "URL", "Hostname"])

    analyze_btn = st.button("🔍 Analyze", type="primary", key="analyze_url")

    # Example buttons
    st.markdown("**Quick examples:**")
    ex_cols = st.columns(3)
    examples = [
        ("🔴 Known IOC", "https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"),
        ("🟡 Partial Signal", "https://5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa"),
        ("🟢 Benign PTR", "4.3.2.1.in-addr.arpa"),
    ]
    for i, (label, example_url) in enumerate(examples):
        if ex_cols[i].button(label, key=f"ex_{i}"):
            user_input = example_url
            analyze_btn = True

    if analyze_btn and user_input.strip():
        with st.spinner("Analyzing..."):
            # Determine input type
            if input_type == "URL" or (input_type == "Auto-detect" and "://" in user_input):
                result = analyze_url(user_input.strip(), is_email_delivered=email_delivered, run_dns=run_dns)
                is_url_mode = True
            else:
                result = analyze_hostname(user_input.strip(), is_email_delivered=email_delivered, run_dns=run_dns)
                is_url_mode = False

        _render_result(result)

        # DNS results are now embedded directly in triggered signals via
        # RESOLVES_AS_A_RECORD, CDN_RESOLUTION, and DNS_NO_RESPONSE signals.
        # No separate display block needed.


# ── Tab 2: Email content ──────────────────────────────────────────────────

with tab2:
    st.markdown("Paste raw email HTML or plain text. The detector will extract all links and analyze each one.")
    st.info("💡 Phishing emails using .arpa domains typically contain **a single hyperlinked image**. The malicious domain is hidden in the `href` — not visible to the user.")

    email_content = st.text_area(
        "Paste email content:",
        height=250,
        placeholder="<html><body><a href='https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa'><img src='https://cdn.example.com/promo.png'></a></body></html>",
        key="email_content"
    )

    # Sample email button
    if st.button("📩 Load sample phishing email"):
        email_content = """<html>
<body style="margin:0;padding:0;">
<p>You have been selected for a special reward!</p>
<a href="https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa/track?id=victim123">
  <img src="https://legitimate-cdn.cloudfront.net/prize-banner.png" 
       alt="Click here to claim your $500 gift card" 
       style="width:600px;border:0;" />
</a>
<p style="font-size:8px;color:#ccc;">To unsubscribe click <a href="https://unsubscribe.example.com">here</a></p>
</body></html>"""
        st.rerun()

    analyze_email_btn = st.button("🔍 Extract & Analyze Links", type="primary", key="analyze_email")

    if analyze_email_btn and email_content.strip():
        with st.spinner("Parsing email and analyzing links..."):
            links = extract_links(email_content)
            summary = summarize_links(links)

        # Summary metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Links", summary["total_links"])
        m2.metric(".arpa Links", summary["arpa_links"], delta="⚠️" if summary["arpa_links"] > 0 else None)
        m3.metric("Image-Wrapped", summary["image_wrapped_links"])
        m4.metric(".arpa in Images", summary["arpa_image_links"], delta="🔴" if summary["arpa_image_links"] > 0 else None)

        if not links:
            st.warning("No links found in email content.")
        else:
            st.markdown("### Extracted Links")
            for link in links:
                result = analyze_url(link.url, is_email_delivered=True, run_dns=run_dns)
                with st.expander(
                    f"{result.verdict_emoji} [{result.score}/100] `{link.url[:80]}...`" if len(link.url) > 80
                    else f"{result.verdict_emoji} [{result.score}/100] `{link.url}`",
                    expanded=result.score > 30
                ):
                    badge_cols = st.columns(3)
                    badge_cols[0].markdown(f"**Source:** `{link.source}`")
                    badge_cols[1].markdown(f"**Image-wrapped:** {'✅ Yes (hidden from user)' if link.is_image_link else 'No'}")
                    badge_cols[2].markdown(f"**Hostname:** `{result.features.hostname}`")
                    _render_result(result, compact=True)


# ── Tab 3: Batch ──────────────────────────────────────────────────────────

with tab3:
    st.markdown("Analyze multiple URLs or hostnames at once (one per line).")

    batch_input = st.text_area(
        "Enter URLs or hostnames (one per line):",
        height=200,
        placeholder="https://abcdefghij.5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa\n4.3.2.1.in-addr.arpa\nhttps://google.com"
    )

    analyze_batch_btn = st.button("🔍 Analyze All", type="primary", key="analyze_batch")

    if analyze_batch_btn and batch_input.strip():
        items = [l.strip() for l in batch_input.strip().splitlines() if l.strip() and not l.startswith("#")]
        results = []

        with st.spinner(f"Analyzing {len(items)} items..."):
            for item in items:
                is_url = "://" in item
                if is_url:
                    r = analyze_url(item, is_email_delivered=email_delivered, run_dns=run_dns)
                else:
                    r = analyze_hostname(item, is_email_delivered=email_delivered, run_dns=run_dns)
                results.append(r)

        # Summary
        high = sum(1 for r in results if r.verdict == "high")
        medium = sum(1 for r in results if r.verdict == "medium")
        low = sum(1 for r in results if r.verdict == "low")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total", len(results))
        c2.metric("🔴 High", high)
        c3.metric("🟡 Medium", medium)
        c4.metric("🟢 Low", low)

        st.markdown("### Results")
        for r in sorted(results, key=lambda x: x.score, reverse=True):
            verdict_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(r.verdict, "⚪")
            with st.expander(f"{verdict_icon} [{r.score}/100] `{r.features.hostname}`", expanded=r.score > 60):
                _render_result(r, compact=True)


# ---------------------------------------------------------------------------
# Render helpers  (defined after tabs so they can be called from tab code)
# ---------------------------------------------------------------------------

def _render_result(result, compact: bool = False):
    """Render score, verdict, signals, and explanation."""
    verdict_class = f"verdict-{result.verdict}"
    verdict_label = {"high": "🔴 HIGH RISK", "medium": "🟡 MEDIUM RISK", "low": "🟢 LOW RISK"}.get(result.verdict, result.verdict)

    col_score, col_verdict, col_host = st.columns([1, 2, 3])

    with col_score:
        st.metric("Risk Score", f"{result.score}/100")

    with col_verdict:
        st.markdown(f'<span class="{verdict_class}">{verdict_label}</span>', unsafe_allow_html=True)

    with col_host:
        st.markdown(f"**Hostname:** `{result.features.hostname}`")

    # Score bar
    bar_pct = result.score
    bar_color = {"high": "#FF4B4B", "medium": "#FFA500", "low": "#21C55D"}.get(result.verdict, "#888")
    st.markdown(
        f"""<div class="score-bar-bg"><div style="width:{bar_pct}%;background:{bar_color};height:20px;border-radius:4px;transition:width 0.5s;"></div></div>""",
        unsafe_allow_html=True
    )

    st.markdown("")

    # Triggered signals
    if result.triggered_signals:
        if not compact:
            st.markdown("#### 🚨 Triggered Signals")
        for sig in result.triggered_signals:
            detail_text = f" · `{sig.detail}`" if sig.detail else ""
            st.markdown(
                f"""<div class="signal-card">
                <b>[+{sig.weight} pts] {sig.name}</b>{detail_text}<br/>
                <small>{sig.description}</small>
                </div>""",
                unsafe_allow_html=True
            )
    else:
        st.success("No suspicious signals triggered.")

    # Explanation
    if not compact:
        st.markdown("#### 📝 Explanation")
    st.info(result.explanation)

    # Feature dump (expandable)
    with st.expander("🔬 Raw Feature Values", expanded=False):
        feat = result.features.to_dict()
        st.json(feat)


def _render_dns_info(dns_info: dict):
    """Render DNS resolution results."""
    st.markdown("#### 🌐 DNS Resolution")
    cols = st.columns(3)
    cols[0].metric("Resolved", "✅ Yes" if dns_info["resolved"] else "❌ No")
    cols[1].metric("CDN Detected", "⚠️ Yes" if dns_info["cdn_resolved"] else "✅ No")
    cols[2].metric("A Record Anomaly", "⚠️ Yes" if dns_info["resolution_anomaly"] else "✅ No")

    if dns_info["ip_addresses"]:
        st.markdown("**Resolved IPs:**")
        for ip in dns_info["ip_addresses"]:
            cdn_tag = " 🏭 CDN" if ip in dns_info["cdn_ips"] else ""
            st.code(f"{ip}{cdn_tag}")


# Re-render note: In Streamlit, functions used in tabs must be defined before
# the tab code runs, OR the tab code must be in a callback/function itself.
# Since Streamlit reruns top-to-bottom, define helpers at module level before use.
# The current structure works because Streamlit's button callbacks trigger reruns.