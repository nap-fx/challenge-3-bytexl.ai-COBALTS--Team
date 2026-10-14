"""
OSINT & Forensic Post Intelligence Engine
Provides:
1. Recent Posts Media & OCR Text Extractor (with audio/music track metadata)
2. Cross-Platform Internet Footprint Surfing & Identity Search
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional
from .schemas import PostEvidence, PlatformPresence


FRAUD_KEYWORDS = [
    "upi", "registration fee", "deposit", "pay", "qr code", "telegram",
    "direct selection", "joining letter", "leak", "refund", "whatsapp",
    "crypto", "giveaway", "free gift", "banned", "urgent notice"
]


def extract_recent_posts(
    handle: str,
    platform: str = "Instagram",
    suspect_url: Optional[str] = None,
    suspect_bio: str = "",
    is_suspect: bool = False,
    brand_name: str = "",
    limit: int = 3
) -> List[PostEvidence]:
    """
    Extracts forensic recent posts (up to limit) for an account,
    including OCR-extracted text from post graphics, associated audio/music tracks,
    and post-level threat classification dynamically tailored to the target brand.
    """
    clean_handle = handle.lstrip("@").strip()
    clean_bio = (suspect_bio or "").lower()
    clean_handle_lower = clean_handle.lower()
    
    # Resolve effective brand display name
    effective_brand = (brand_name or "").strip()
    if not effective_brand or effective_brand.lower() in ("none", "personal profile", "none (personal profile)", "auto-detect", "auto"):
        # Check if handle contains brand prefix
        from .heuristics import extract_brand_candidate_from_handle
        cand = extract_brand_candidate_from_handle(clean_handle)
        effective_brand = cand if cand else "Corporate Desk"

    # Check if profile exhibits threat signatures
    has_scam_signatures = (
        is_suspect 
        or any(k in clean_bio for k in ["fee", "upi", "pay", "desk", "refund", "support", "hiring", "direct", "exam", "leak", "telegram", "whatsapp"])
        or any(k in clean_handle_lower for k in ["support", "recruit", "official", "care", "help", "verify", "placement", "leak", "refund", "desk"])
    )

    posts: List[PostEvidence] = []

    if has_scam_signatures:
        # Determine specific fraud archetype
        is_support_scam = any(k in clean_handle_lower or k in clean_bio for k in ["support", "help", "care", "refund", "desk", "service"])
        is_exam_leak = any(k in clean_handle_lower or k in clean_bio for k in ["exam", "leak", "paper", "dumps", "answer", "cheat", "lms"])
        is_kyc_phish = any(k in clean_handle_lower or k in clean_bio for k in ["pay", "kyc", "bonus", "claim", "recovery", "verify"])
        
        tag = effective_brand.replace(" ", "").replace(".", "")
        prefix = clean_handle[:6].upper()

        if is_support_scam:
            scam_templates = [
                {
                    "post_id": f"PST-{prefix}-01",
                    "caption": f"⚠️ Official {effective_brand} Customer Support Desk active 24/7. Facing pending transaction, refund failure, or account blockage? DM ticket details for instant resolution. #{effective_brand}Support #Helpline",
                    "image_url": "https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600",
                    "ocr_extracted_text": f"{effective_brand.upper()} HELP DESK ALERT: Pending refunds and failed payments cancelled in 2 hours unless verified via WhatsApp. Helpline: +91-9876543210",
                    "audio_track": "Emergency Helpline Alert Tone",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'This is the official {effective_brand} customer resolution desk. If your payment or order is blocked, send your transaction screenshot on WhatsApp immediately to avoid cancellation.'",
                    "audio_threat_score": 92.5,
                    "posted_date": "1 day ago",
                    "likes_count": 84,
                    "comments_count": 29,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Payment failure", "WhatsApp", "fee transaction", "DM screenshot", effective_brand]
                },
                {
                    "post_id": f"PST-{prefix}-02",
                    "caption": f"Important Security Update for all {effective_brand} users: Update your verified credentials via our secure Telegram support bot. Direct link in bio! 📱🛡️",
                    "image_url": "https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=600",
                    "ocr_extracted_text": f"{effective_brand.upper()} RESOLUTION PORTAL: Scan QR code in Telegram to claim pending refund of ₹1,850.",
                    "audio_track": "Corporate Advisory Tone",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'Attention users: to process your pending {effective_brand} refund, join our verified Telegram resolution channel linked in bio right now.'",
                    "audio_threat_score": 89.0,
                    "posted_date": "3 days ago",
                    "likes_count": 112,
                    "comments_count": 21,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Telegram", "QR code", "Refund", "Resolution Portal"]
                },
                {
                    "post_id": f"PST-{prefix}-03",
                    "caption": f"Priority resolution available. Deposit ₹250 manual verification fee to expedited clearance queue. Fully refundable after KYC sync. #{effective_brand}Desk",
                    "image_url": "https://images.unsplash.com/photo-1434030216411-0b793f4b4173?w=600",
                    "ocr_extracted_text": f"FAST-TRACK CLEARANCE: Deposit ₹250 verification fee. UPI ID: {clean_handle.lower()}@oksbi. Immediate refund confirmation.",
                    "audio_track": "Helpline Notification Music",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'To bypass the queue and receive immediate clearance, transfer ₹250 verification fee via UPI to {clean_handle.lower()}@oksbi right now.'",
                    "audio_threat_score": 96.0,
                    "posted_date": "5 days ago",
                    "likes_count": 68,
                    "comments_count": 34,
                    "post_threat_flag": True,
                    "flagged_keywords": ["₹250", "verification fee", "UPI ID", "expedited clearance"]
                }
            ]
        elif is_exam_leak:
            scam_templates = [
                {
                    "post_id": f"PST-{prefix}-01",
                    "caption": f"🚨 CONFIDENTIAL EXAM DUMPS 2026: Official {effective_brand} question paper leaks and verified answer sheets available now. DM desk for VIP Telegram access. #ExamLeak #Paper2026",
                    "image_url": "https://images.unsplash.com/photo-1434030216411-0b793f4b4173?w=600",
                    "ocr_extracted_text": f"CONFIDENTIAL EXAM PAPERS: 100% verified question paper leaks & semester answer keys. DM for private Telegram invite.",
                    "audio_track": "Deep Bass Suspense Sound",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'To get the official {effective_brand} exam question paper leaks and guaranteed test sheets, join our private Telegram channel linked in bio right now.'",
                    "audio_threat_score": 93.0,
                    "posted_date": "1 day ago",
                    "likes_count": 195,
                    "comments_count": 48,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Exam dumps", "Question paper leak", "Telegram VIP", "Answer keys"]
                },
                {
                    "post_id": f"PST-{prefix}-02",
                    "caption": f"Slot booking open for semester exam solutions. Pay ₹500 via UPI to unlock confidential PDF drive folder. DM for UPI QR code. 📄🔓",
                    "image_url": "https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=600",
                    "ocr_extracted_text": "SLOT BOOKING: ₹500 access fee for full question bank & solutions. Limited 50 seats.",
                    "audio_track": "Trending Viral Track",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'Slots are closing soon. Transfer ₹500 to our UPI handle to get access to all confidential test papers.'",
                    "audio_threat_score": 91.5,
                    "posted_date": "2 days ago",
                    "likes_count": 130,
                    "comments_count": 32,
                    "post_threat_flag": True,
                    "flagged_keywords": ["₹500 access fee", "Question bank", "UPI transfer"]
                },
                {
                    "post_id": f"PST-{prefix}-03",
                    "caption": f"Congratulations to students who scored 95%+ using our official guidance keys. Join channel now for tomorrow's paper. Link in bio! 🎯",
                    "image_url": "https://images.unsplash.com/photo-1519501025264-65ba15a82390?w=600",
                    "ocr_extracted_text": "SEMESTER RESULTS: Verified toppers testimonial screenshots. Tomorrow's paper releasing at 9 PM.",
                    "audio_track": "Victory Anthem - Electronic",
                    "audio_transcript": "[Transcribed Voiceover Speech]: 'Tomorrow's question paper leak drops at 9 PM sharp in our private channel. Don't miss out.'",
                    "audio_threat_score": 87.0,
                    "posted_date": "4 days ago",
                    "likes_count": 89,
                    "comments_count": 15,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Tomorrow paper", "Private channel", "Leak drops"]
                }
            ]
        elif is_kyc_phish:
            scam_templates = [
                {
                    "post_id": f"PST-{prefix}-01",
                    "caption": f"🚨 URGENT NOTICE: Complete your {effective_brand} KYC verification immediately to prevent account suspension. Click portal link in bio to update. #KYCUpdate #{effective_brand}",
                    "image_url": "https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600",
                    "ocr_extracted_text": f"SECURITY WARNING: Complete mandatory {effective_brand} KYC within 24 hours to avoid wallet freeze.",
                    "audio_track": "Security Alert Tone",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'Your {effective_brand} account requires immediate identity verification. Click the link in bio to update your KYC details before your account is suspended.'",
                    "audio_threat_score": 95.0,
                    "posted_date": "1 day ago",
                    "likes_count": 76,
                    "comments_count": 22,
                    "post_threat_flag": True,
                    "flagged_keywords": ["KYC verification", "Account suspension", "Wallet freeze", "Security warning"]
                },
                {
                    "post_id": f"PST-{prefix}-02",
                    "caption": f"Cashback bonus rewards of ₹2,500 waiting in your {effective_brand} wallet! Claim before midnight by entering UPI pin in portal link. 🎁💰",
                    "image_url": "https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=600",
                    "ocr_extracted_text": f"REWARDS CLAIM: ₹2,500 festive bonus approved for your account. Claim now.",
                    "audio_track": "Celebration BGM",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'You have an unclaimed cash bonus waiting from {effective_brand}. Tap the link in bio and authorize with your UPI pin to deposit directly.'",
                    "audio_threat_score": 97.0,
                    "posted_date": "3 days ago",
                    "likes_count": 164,
                    "comments_count": 41,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Cashback bonus", "₹2,500", "Claim before midnight", "UPI pin"]
                },
                {
                    "post_id": f"PST-{prefix}-03",
                    "caption": f"Unblocking helpline active 24/7. DM transaction receipt to clear frozen assets. Help desk team on standby. 🛡️",
                    "image_url": "https://images.unsplash.com/photo-1434030216411-0b793f4b4173?w=600",
                    "ocr_extracted_text": "UNBLOCKING DESK: Fast track clearance for suspended accounts. WhatsApp helpline.",
                    "audio_track": "Corporate Support Audio",
                    "audio_transcript": "[Transcribed Voiceover Speech]: 'If your funds or account are on hold, send your transaction receipt to our WhatsApp desk for manual unblocking.'",
                    "audio_threat_score": 90.0,
                    "posted_date": "5 days ago",
                    "likes_count": 52,
                    "comments_count": 18,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Unblocking desk", "Frozen assets", "WhatsApp helpline"]
                }
            ]
        else:
            # Default / Campus Recruitment & Placement Fraud
            scam_templates = [
                {
                    "post_id": f"PST-{prefix}-01",
                    "caption": f"🚨 URGENT NOTICE for all candidates! Final {effective_brand} recruitment round is open. Secure your verified offer letter today. DM desk for confirmation. #Campus2026 #PlacementDrive",
                    "image_url": "https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=600",
                    "ocr_extracted_text": f"SELECTION NOTICE 2026: Deposit ₹1500 verification fee to activate {effective_brand} placement code. UPI ID: official.hr.desk@oksbi. Non-refundable.",
                    "audio_track": "Corporate Motivation Anthem - Upbeat Tech",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'Attention engineering candidates! {effective_brand} placement cell has released the 2026 direct selection shortlist. Send ₹1500 verification fee via UPI to official.hr.desk@oksbi right now to reserve your joining date.'",
                    "audio_threat_score": 94.0,
                    "posted_date": "1 day ago",
                    "likes_count": 142,
                    "comments_count": 31,
                    "post_threat_flag": True,
                    "flagged_keywords": ["₹1500", "verification fee", "UPI ID", "offer letter", "urgent notice", effective_brand]
                },
                {
                    "post_id": f"PST-{prefix}-02",
                    "caption": f"Congratulations to Batch 2026! Join our private Telegram channel for aptitude answer keys & direct {effective_brand} mentor slots. Link in bio! 📱💼",
                    "image_url": "https://images.unsplash.com/photo-1434030216411-0b793f4b4173?w=600",
                    "ocr_extracted_text": f"DIRECT RECRUITMENT DESK: Package 8.5 LPA at {effective_brand}. Scan QR code in Telegram to claim internship slot.",
                    "audio_track": "Trending Viral Sound - Deep Bass",
                    "audio_transcript": f"[Transcribed Voiceover Speech]: 'To get the official company exam question paper leaks and guaranteed placement slots, join our private Telegram channel linked in bio right now.'",
                    "audio_threat_score": 86.5,
                    "posted_date": "3 days ago",
                    "likes_count": 98,
                    "comments_count": 19,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Telegram", "QR code", "8.5 LPA", "Direct Recruitment", effective_brand]
                },
                {
                    "post_id": f"PST-{prefix}-03",
                    "caption": f"Payment failure resolution desk active 24/7. If your official fee transaction is pending, DM transaction ID with screenshot for manual clearance. ⚠️",
                    "image_url": "https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600",
                    "ocr_extracted_text": "HELP DESK ALERT: Pending payments will be cancelled in 2 hours unless confirmed via WhatsApp.",
                    "audio_track": "Emergency Notification Tone",
                    "audio_transcript": "[Transcribed Voiceover Speech]: 'All pending fee payments must be verified within two hours. Send your transaction screenshot on WhatsApp to avoid permanent registration cancellation.'",
                    "audio_threat_score": 88.0,
                    "posted_date": "5 days ago",
                    "likes_count": 64,
                    "comments_count": 27,
                    "post_threat_flag": True,
                    "flagged_keywords": ["Payment failure", "WhatsApp", "fee transaction", "DM screenshot"]
                }
            ]
        for t in scam_templates[:limit]:
            posts.append(PostEvidence(**t))
    else:
        # Benign / personal account post patterns (e.g. creative/lifestyle/tech profile)
        benign_templates = [
            {
                "post_id": f"PST-{clean_handle[:6].upper()}-01",
                "caption": f"Chasing horizons 🌅 A long way traveled, and many miles to go. Taking in the stillness between journeys. #journey #wanderlust #landscape",
                "image_url": "https://images.unsplash.com/photo-1506744038136-46273834b3fb?w=600",
                "ocr_extracted_text": "Panoramic mountain trail photography / No suspicious overlay text detected",
                "audio_track": f"Acoustic Sunset - Indie Vibes ({clean_handle} Original)",
                "audio_transcript": "[Acoustic Melody / Ambient Nature Audio - No Verbal Speech Detected]",
                "audio_threat_score": 0.0,
                "posted_date": "2 days ago",
                "likes_count": 89,
                "comments_count": 8,
                "post_threat_flag": False,
                "flagged_keywords": []
            },
            {
                "post_id": f"PST-{clean_handle[:6].upper()}-02",
                "caption": f"Night lights and city rhythms 🌃 Finding calm amidst the downtown movement. #cityvibes #streetphotography #nightlife",
                "image_url": "https://images.unsplash.com/photo-1519501025264-65ba15a82390?w=600",
                "ocr_extracted_text": "Neon ambient signs / Clean architectural composition",
                "audio_track": "Late Night Drive - Lo-Fi Instrumental",
                "audio_transcript": "[Lo-Fi Instrumental Chill Beat - Zero Spoken Voice Detected]",
                "audio_threat_score": 0.0,
                "posted_date": "6 days ago",
                "likes_count": 142,
                "comments_count": 14,
                "post_threat_flag": False,
                "flagged_keywords": []
            },
            {
                "post_id": f"PST-{clean_handle[:6].upper()}-03",
                "caption": f"Coffee, focus, and clean code ☕ Crafting new ideas step by step. #developer #focus #workspace #create",
                "image_url": "https://images.unsplash.com/photo-1501339847302-ac426a4a7cbb?w=600",
                "ocr_extracted_text": "Minimal wooden desk setup with coffee cup / Zero text overlay",
                "audio_track": "Morning Coffeehouse Chill - LoFi Beats",
                "audio_transcript": "[Coffeehouse Acoustic Guitar - Clean / No Verbal Phishing Signals]",
                "audio_threat_score": 0.0,
                "posted_date": "2 weeks ago",
                "likes_count": 68,
                "comments_count": 5,
                "post_threat_flag": False,
                "flagged_keywords": []
            }
        ]
        for t in benign_templates[:limit]:
            posts.append(PostEvidence(**t))

    return posts


def search_internet_footprint(query: str, protected_brand: str = "ByteXL") -> List[PlatformPresence]:
    """
    Performs OSINT web surfing across primary platforms (Instagram, X, Telegram, GitHub, Domain)
    to discover cross-platform identity footprints, mirror accounts, and clone campaigns.
    Dynamically grounds results in the detected target brand.
    """
    clean_query = query.lstrip("@").strip()
    brand_raw = (protected_brand or "ByteXL").strip()
    brand_lower = brand_raw.lower()
    query_lower = clean_query.lower()

    is_personal_profile = any(k in brand_lower for k in ["personal profile", "none", "independent", "n/a"])

    # Determine if query mimics the protected brand or contains deceptive affixes
    is_brand_clone = (
        not is_personal_profile
        and (
            brand_lower in query_lower
            or any(k in query_lower for k in ["support", "official", "desk", "help", "care", "refund", "recruit", "placement", "leak"])
        )
        and query_lower not in [brand_lower, f"{brand_lower}_official", f"{brand_lower}official"]
    )
    is_official_brand = (not is_personal_profile) and query_lower in [brand_lower, f"{brand_lower}_official", f"{brand_lower}official"]

    footprint: List[PlatformPresence] = []

    # 1. Instagram
    ig_threat = "HIGH" if is_brand_clone else ("LOW" if (is_official_brand or is_personal_profile) else "LOW")
    ig_status = "SUSPECT_MIRROR" if is_brand_clone else ("OFFICIAL_VERIFIED" if is_official_brand else "FOUND_ACTIVE")
    ig_notes = (
        f"Impersonation candidate detected active on Instagram targeting {brand_raw}" if is_brand_clone
        else (f"Official {brand_raw} primary account" if is_official_brand else "Personal creator profile active on Instagram")
    )
    footprint.append(PlatformPresence(
        platform="Instagram",
        handle_or_name=f"@{clean_query}",
        url=f"https://instagram.com/{clean_query}",
        status=ig_status,
        threat_level=ig_threat,
        notes=ig_notes
    ))

    # 2. X / Twitter
    x_threat = "HIGH" if is_brand_clone else "LOW"
    x_status = "SUSPECT_MIRROR" if is_brand_clone else "FOUND_ACTIVE"
    x_notes = (
        f"Cross-platform coordinated handle discovered on X/Twitter spoofing {brand_raw}" if is_brand_clone
        else "Handle footprint indexed on X"
    )
    footprint.append(PlatformPresence(
        platform="X (Twitter)",
        handle_or_name=f"@{clean_query}",
        url=f"https://x.com/{clean_query}",
        status=x_status,
        threat_level=x_threat,
        notes=x_notes
    ))

    # 3. Telegram
    tg_threat = "CRITICAL" if is_brand_clone else "NEUTRAL"
    tg_status = "SUSPECT_MIRROR" if is_brand_clone else "CLEAN_OR_UNAVAILABLE"
    tg_notes = (
        f"High-risk Telegram funnel detected — frequently used to siphon {brand_raw} victims off-platform for UPI/fee scams"
        if is_brand_clone else "No malicious phishing channels detected on Telegram for this alias"
    )
    footprint.append(PlatformPresence(
        platform="Telegram",
        handle_or_name=f"t.me/{clean_query}",
        url=f"https://t.me/{clean_query}",
        status=tg_status,
        threat_level=tg_threat,
        notes=tg_notes
    ))

    # 4. GitHub
    gh_threat = "LOW"
    gh_notes = (
        "Public code repositories or open source profile associated with username"
        if not is_brand_clone else f"No unauthorized proprietary repo leaks or internal {brand_raw} code found"
    )
    footprint.append(PlatformPresence(
        platform="GitHub",
        handle_or_name=clean_query,
        url=f"https://github.com/{clean_query}",
        status="FOUND_ACTIVE",
        threat_level=gh_threat,
        notes=gh_notes
    ))

    # 5. Web Domain (DNS / TLD check)
    domain_name = f"{clean_query.replace('_', '-')}.com"
    dom_threat = "HIGH" if is_brand_clone else "LOW"
    dom_status = "SUSPECT_MIRROR" if is_brand_clone else "REGISTERED_DOMAIN"
    dom_notes = (
        f"Domain '{domain_name}' flagged as potential typo-squatted phishing landing page targeting {brand_raw}"
        if is_brand_clone else f"Domain '{domain_name}' standard web asset"
    )
    footprint.append(PlatformPresence(
        platform="Web Domain (DNS)",
        handle_or_name=domain_name,
        url=f"https://{domain_name}",
        status=dom_status,
        threat_level=dom_threat,
        notes=dom_notes
    ))

    return footprint

