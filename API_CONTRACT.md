# 🔌 BrandShield AI — Frontend ↔ Backend API Contract

**Base URL (Local Dev):** `http://localhost:8000`  
**Swagger Interactive Docs:** `http://localhost:8000/docs`  
**CORS Enabled For:** `http://localhost:3000`, `http://localhost:4321` (Astro), `http://localhost:5173` (Vite), `*`  
**Flexible Routing:** All endpoints are mounted at `/api/v1/*`, `/api/*`, and `/*` (so `/api/v1/scan`, `/api/scan`, and `/scan` all work interchangeably).

---

## 1. Run Multi-Modal Threat Scan
**Endpoint:** `POST /api/v1/scan`

### Request Body (`application/json`)
*(Supports flexible field aliases: `suspect_handle` or `target_handle`, `suspect_bio` or `bio`, `suspect_url` or `profile_url`)*
```json
{
  "brand_name": "ByteXL",
  "suspect_handle": "@bytexl_support_official",
  "platform": "Instagram",
  "suspect_bio": "Official Support & Direct Hiring Desk for ByteXL! Send Rs. 500 registration fee via UPI to bytexl.hr@okhdfcbank",
  "suspect_url": "https://bit.ly/bytexl-direct-onboarding",
  "visual_tampering_mode": "cloned_logo",
  "account_age_days": 3,
  "dormancy_gap_days": 0,
  "followers_count": 38,
  "following_count": 4920
}
```

### Response Body (`200 OK`)
```json
{
  "scan_id": "4F41935B",
  "timestamp_utc": "2026-10-13 08:00:00 UTC",
  "brand_profile": {
    "brand_id": "BRD-001",
    "brand_name": "ByteXL",
    "official_handle": "@bytexl_official",
    "official_domain": "bytexl.com",
    "category": "EdTech & Engineering Transformation",
    "official_bio": "Official ByteXL | Transforming Engineering Colleges across India",
    "verified_followers": 148000,
    "logo_fingerprint_id": "vec_bytexl_512d_v1"
  },
  "suspect_handle": "@bytexl_support_official",
  "target_handle": "@bytexl_support_official",
  "platform": "Instagram",
  "suspect_bio": "Official Support & Direct Hiring Desk for ByteXL! Send Rs. 500 registration fee via UPI to bytexl.hr@okhdfcbank",
  "suspect_url": "https://bit.ly/bytexl-direct-onboarding",
  "enricher_status": "MANUAL_INPUT",
  "social_reach_score": 32.1,
  "unified_threat_score": 92.0,
  "impersonation_score": 92.0,
  "visual_match_percent": 96.4,
  "scam_intent_detected": true,
  "severity_level": "CRITICAL",
  "risk_level": "CRITICAL",
  "severity_color": "#EF4444",
  "recommended_action": "Confirmed Brand Impersonation Attack — 1-Click Automated Legal Takedown Package Unlocked",
  "takedown_unlocked": true,
  "flags": [
    "Exact brand logomark geometry matched in 512-dim CLIP embedding space",
    "UPI Payment Solicitation: 'bytexl.hr@okhdfcbank'",
    "Direct Monetary Demand: 'Rs. 500'",
    "Deceptive handle affixes: _official, _support",
    "Newly registered burner account (3 days old)"
  ],
  "victim_reviews": {
    "complaint_count": 14,
    "scam_sentiment_pct": 91.5,
    "compiled_snippets": [
      "User complaint: 'Sent registration fee via UPI, received no reply.'",
      "Community report: 'Fake ByteXL support handle reported to cyber desk.'",
      "Phishing alert: 'Directing users to unauthorized external payment links.'"
    ]
  },
  "total_latency_ms": 11.2,
  "pillar_1_vision": {
    "score": 96.4,
    "cosine_similarity": 0.964,
    "engine": "Dense Vector Inner-Product (512-d) + CLIP-ViT-B/32 (.onnx)",
    "inference_ms": 3.4,
    "detected_anomalies": ["Exact brand logomark geometry matched in 512-dim CLIP embedding space"],
    "bounding_box": { "x": 14, "y": 14, "width": 228, "height": 228 }
  },
  "pillar_2_nlp": {
    "score": 99.2,
    "engine": "DistilBERT-ScamIntent (.onnx) + Fraud Pattern Rules",
    "inference_ms": 4.8,
    "flagged_phrases": [
      { "phrase": "bytexl.hr@okhdfcbank", "category": "UPI Payment Solicitation", "risk_contribution": 38.0 },
      { "phrase": "Rs. 500", "category": "Direct Monetary Demand", "risk_contribution": 32.0 }
    ],
    "detected_categories": ["Advance-Fee Recruitment Fraud", "Direct Monetary Demand", "UPI Payment Solicitation"]
  },
  "pillar_3_heuristics": {
    "score": 94.0,
    "levenshtein_distance": 0,
    "normalized_handle_similarity": 100.0,
    "homoglyphs_detected": [],
    "malicious_affixes": ["_official", "_support"],
    "metadata_anomalies": ["Newly registered burner account (3 days old)"]
  }
}
```

---

## 2. Live Link Metadata Preview & Fallback Enricher
**Endpoint:** `POST /api/v1/extract-link`
```json
{
  "url": "https://instagram.com/bytexl_support_official"
}
```
**Response:** Returns parsed `platform`, `extracted_handle`, `domain`, `enricher_status` (`LIVE_SCRAPE_OK`, `CAPTCHA_FALLBACK`, or `URL_OFFLINE_PARSED`), `title`, `bio`, and `avatar_image_url`.

---

## 3. Persistent Scan Audit History
* `GET /api/v1/scans/history?limit=20` — Retrieves list of previously scanned investigations from SQLite database.
* `GET /api/v1/scans/{scan_id}` — Retrieves single past scan result.

---

## 4. Generate 1-Click Legal Takedown Notice
* **JSON Notice Endpoint:** `POST /api/v1/takedown` *(or `POST /api/v1/report`)*
* **Binary PDF Download Endpoint:** `POST /api/v1/takedown/pdf` *(returns printable `application/pdf` stream)*

---

## 5. Auxiliary Telemetry Endpoints
* `GET /api/v1/health` — System status & active ML models.
* `GET /api/v1/brands` — Monitored enterprise brands + SOC KPI counters.
* `GET /api/v1/presets` — 4 pre-loaded demo scenarios for 1-click judge testing.

---

## 6. Recent Posts Extractor (OCR + Audio Track Evidence)
**Endpoint:** `POST /api/v1/profile/posts`

### Request Body (`application/json`)
```json
{
  "url": "https://instagram.com/the_longwayx",
  "handle": "@the_longwayx",
  "platform": "Instagram",
  "limit": 3
}
```

### Response Body (`200 OK`)
```json
[
  {
    "post_id": "PST-THE_LO-01",
    "caption": "Chasing horizons 🌅 A long way traveled, and many miles to go...",
    "image_url": "https://images.unsplash.com/photo-1506744038136-46273834b3fb?w=600",
    "ocr_extracted_text": "Panoramic mountain trail photography / No suspicious overlay text detected",
    "audio_track": "Acoustic Sunset - Indie Vibes (the_longwayx Original)",
    "posted_date": "2 days ago",
    "likes_count": 89,
    "comments_count": 8,
    "post_threat_flag": false,
    "flagged_keywords": []
  }
]
```
*(Also automatically bundled inside the primary `POST /api/v1/scan` response as `recent_posts`!)*

---

## 7. OSINT Internet Surfing & Cross-Platform Footprint
**Endpoint:** `POST /api/v1/osint/footprint`

### Request Body (`application/json`)
```json
{
  "query": "the_longwayx",
  "protected_brand": "ByteXL"
}
```

### Response Body (`200 OK`)
```json
[
  {
    "platform": "Instagram",
    "handle_or_name": "@the_longwayx",
    "url": "https://instagram.com/the_longwayx",
    "status": "FOUND_ACTIVE",
    "threat_level": "LOW",
    "notes": "Active profile discovered on Instagram"
  },
  {
    "platform": "Telegram",
    "handle_or_name": "t.me/the_longwayx",
    "url": "https://t.me/the_longwayx",
    "status": "CLEAN_OR_UNAVAILABLE",
    "threat_level": "NEUTRAL",
    "notes": "No malicious phishing channels detected on Telegram for this alias"
  },
  {
    "platform": "GitHub",
    "handle_or_name": "the_longwayx",
    "url": "https://github.com/the_longwayx",
    "status": "FOUND_ACTIVE",
    "threat_level": "LOW",
    "notes": "Public code repositories or open source profile associated with username"
  }
]
```
*(Also automatically bundled inside the primary `POST /api/v1/scan` response as `cross_platform_footprint`!)*

---

## 8. App Store & Rogue Mobile App Forensics
**Endpoint:** `POST /api/v1/scan/app-store`  
*(Powered by Team COBALTS's 5-Pillar App Store Forensic Algorithm: AI synthetic reviews, astroturfing burst windows, publisher reverse OSINT, rating bimodal split, and hyperbolic cold-start detection)*

### Request Body (`application/json`)
```json
{
  "brand_name": "ByteXL",
  "app_title": "ByteXL Placement Exam & Student Desk",
  "package_id": "com.bytexl.placement.guide",
  "publisher_name": "Apex Global Studio LLC",
  "permissions_requested": [
    "android.permission.INTERNET",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS"
  ]
}
```

### Response Body (`200 OK`)
```json
{
  "scan_id": "4A19F8C2",
  "timestamp_utc": "2026-10-13 17:45:00 UTC",
  "brand_name": "ByteXL",
  "app_package_id": "com.bytexl.placement.guide",
  "app_title": "ByteXL Placement Exam & Student Desk",
  "publisher_name": "Apex Global Studio LLC",
  "store": "Google Play",
  "is_official_app": false,
  "publisher_verified": false,
  "publisher_mismatch_alert": "Rogue Publisher Impersonation: App published by unauthorized developer 'Apex Global Studio LLC' (Official publisher is 'ByteXL EdTech Pvt Ltd')",
  "app_threat_index": 85.4,
  "severity_level": "CRITICAL",
  "severity_color": "#EF4444",
  "review_forensics": {
    "total_reviews_analyzed": 52,
    "synthetic_bot_reviews_detected": 34,
    "bot_probability_pct": 88.5,
    "astroturfing_burst_detected": true,
    "temporal_burst_window_hours": 24,
    "rating_bimodal_split": {
      "5_star": 35,
      "4_star": 0,
      "3_star": 0,
      "2_star": 0,
      "1_star": 17
    },
    "hyperbolic_praise_detected": true,
    "flagged_review_snippets": [
      "Bot Review [Cluster A]: 'This is the app I was looking for years for my whole life! This app have maken my life very easier by now. Best app in the world!!'",
      "Real Victim Complaint [1-Star]: 'FRAUD APP! They asked for ₹500 placement registration fee claiming to be ByteXL...'"
    ]
  },
  "publisher_portfolio": {
    "publisher_name": "Apex Global Studio LLC",
    "total_apps_in_portfolio": 4,
    "average_app_lifespan_days": 18,
    "reputation_status": "HIGH_RISK_EPHEMERAL_DEVELOPER_RING",
    "cross_app_scam_flags": 4,
    "portfolio_apps": [
      {
        "app_title": "ByteXL Placement Helper",
        "package_id": "com.bytexl.placement.guide",
        "status": "FLAGGED_IMPERSONATION"
      },
      {
        "app_title": "Instant Loan Fast Cash Desk",
        "package_id": "com.apex.fastloan.instant",
        "status": "FLAGGED_MALWARE"
      }
    ]
  },
  "google_play_abuse_report": {
    "case_id": "GP-STRIKE-4A19F8C2",
    "policy_infringement_category": "Google Play Developer Program Policy - Impersonation (Section 1.3)"
  }
}
```

---

## 9. Dynamic Brand Profile Management
* **List All Brands:** `GET /api/v1/brands`
* **Get Single Brand:** `GET /api/v1/brands/BRD-001` *(or `/api/v1/brands/bytexl`)*
* **Register New Brand:** `POST /api/v1/brands`
```json
{
  "brand_name": "Swiggy",
  "official_handle": "@swiggy_official",
  "official_domain": "swiggy.com",
  "official_publisher": "Swiggy Logistics Pvt Ltd",
  "official_mobile_apps": ["in.swiggy.android"],
  "verified_followers": 980000
}
```
