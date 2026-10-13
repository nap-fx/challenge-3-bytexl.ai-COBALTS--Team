"""
Block 1: Link & Metadata Extraction Engine
Parses suspect URLs, extracts OpenGraph metadata (og:image, og:description, og:title),
and triggers the Lexical Fallback Enricher when encountering Captchas, Cloudflare, or 404/down URLs.
"""

import re
import urllib.parse
import urllib.request
from typing import Dict, Any, Optional, List


SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".buzz", ".loan", ".work", ".cfd", ".monster", ".sbs"}

PLATFORM_PATTERNS = [
    (r"instagram\.com", "Instagram"),
    (r"(twitter\.com|x\.com)", "X"),
    (r"(t\.me|telegram\.me)", "Telegram"),
    (r"play\.google\.com", "Google Play"),
    (r"(facebook\.com|fb\.com)", "Facebook"),
    (r"linkedin\.com", "LinkedIn"),
]


def extract_platform_and_handle(url: str) -> Dict[str, str]:
    """Decomposes a raw URL to extract its target platform, handle slug, and domain."""
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = f"https://{clean_url}"

    parsed = urllib.parse.urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.strip("/")

    # Detect platform
    platform = "Web"
    for pattern, plat_name in PLATFORM_PATTERNS:
        if re.search(pattern, hostname):
            platform = plat_name
            break

    # Extract handle from path
    handle = ""
    if platform in ("Instagram", "X", "Telegram") and path:
        parts = [p for p in path.split("/") if p]
        if parts:
            handle = f"@{parts[0]}"
    elif platform == "Google Play":
        q = urllib.parse.parse_qs(parsed.query)
        if "id" in q and q["id"]:
            handle = f"@{q['id'][0]}"
    
    if not handle:
        # Fallback to domain root if not social handle
        handle = f"@{hostname.replace('www.', '')}"

    return {
        "platform": platform,
        "domain": hostname,
        "handle": handle,
        "clean_url": clean_url,
    }


def clean_bio_text_and_extract_urls(raw_text: str) -> Dict[str, Any]:
    """
    Separates raw description text from embedded URLs (Block 2 rule:
    NLP evaluates pure language semantics without link noise).
    """
    if not raw_text:
        return {"clean_text": "", "embedded_urls": []}

    url_pattern = r"https?://[^\s]+|bit\.ly/[^\s]+|t\.me/[^\s]+"
    embedded_urls = re.findall(url_pattern, raw_text)
    clean_text = re.sub(url_pattern, "", raw_text).strip()
    clean_text = re.sub(r"\s+", " ", clean_text)

    return {
        "clean_text": clean_text,
        "embedded_urls": embedded_urls,
    }


def extract_metadata_from_url(url: str, timeout_sec: float = 2.5) -> Dict[str, Any]:
    """
    Attempts live OpenGraph extraction. If Captcha or offline, activates Fallback Enricher.
    """
    decomp = extract_platform_and_handle(url)
    target_url = decomp["clean_url"]
    domain = decomp["domain"]

    # Check for high-risk TLD
    has_risky_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    og_data: Dict[str, Optional[str]] = {
        "og_title": None,
        "og_description": None,
        "og_image": None,
    }
    enricher_status = "LIVE_SCRAPE_OK"

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

            # Extract OpenGraph tags
            m_title = re.search(r'<meta\s+property=["\']og:title["\']\s+content=["\'](.*?)["\']', html, re.I)
            m_desc = re.search(r'<meta\s+property=["\']og:description["\']\s+content=["\'](.*?)["\']', html, re.I)
            m_img = re.search(r'<meta\s+property=["\']og:image["\']\s+content=["\'](.*?)["\']', html, re.I)

            if m_title:
                og_data["og_title"] = m_title.group(1).strip()
            if m_desc:
                og_data["og_description"] = m_desc.group(1).strip()
            if m_img:
                og_data["og_image"] = m_img.group(1).strip()

    except urllib.error.HTTPError as e:
        if e.code in (403, 503, 429):
            enricher_status = "CAPTCHA_FALLBACK"
        else:
            enricher_status = f"URL_OFFLINE_HTTP_{e.code}"
    except Exception:
        # DNS failure, timeout, or server connection refused
        enricher_status = "URL_OFFLINE_PARSED"

    # Separate raw URLs from bio text
    raw_desc = og_data["og_description"] or ""
    bio_cleaned = clean_bio_text_and_extract_urls(raw_desc)

    return {
        "target_url": target_url,
        "platform": decomp["platform"],
        "extracted_handle": decomp["handle"],
        "domain": domain,
        "has_risky_tld": has_risky_tld,
        "enricher_status": enricher_status,
        "title": og_data["og_title"] or decomp["handle"].lstrip("@"),
        "bio": bio_cleaned["clean_text"],
        "avatar_image_url": og_data["og_image"],
        "embedded_urls": bio_cleaned["embedded_urls"],
    }
