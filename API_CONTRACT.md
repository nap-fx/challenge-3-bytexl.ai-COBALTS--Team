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
