from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException
from ....vision_engine import VERIFIED_BRANDS
from ....schemas import BrandProfile, BrandProfileCreateRequest

router = APIRouter()

PRESET_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "preset_bytexl_critical",
        "label": "CRITICAL: ByteXL Fake Placement / Fee Scam (@bytexl_support_official)",
        "brand_name": "ByteXL",
        "suspect_handle": "@bytexl_support_official",
        "platform": "Instagram",
        "suspect_bio": "Official Support & Direct Hiring Desk for ByteXL HacXLerate! Guaranteed placement offer letter. Send Rs. 500 registration fee via UPI to bytexl.hr@okhdfcbank or join t.me/bytexl_jobs_urgent",
        "suspect_url": "https://bit.ly/bytexl-direct-onboarding",
        "visual_tampering_mode": "cloned_logo",
        "account_age_days": 3,
        "followers_count": 38,
        "following_count": 4920,
    },
    {
        "id": "preset_zomato_critical",
        "label": "CRITICAL: Zomato Instant Refund UPI Phishing (@z0mato_refunds_care)",
        "brand_name": "Zomato",
        "suspect_handle": "@z0mato_refunds_care",
        "platform": "X",
        "suspect_bio": "24x7 Customer Care Official Zomato Refund Desk. For failed order instant refund, verify KYC & share OTP or pay Rs. 99 processing charge to zomatocare@paytm",
        "suspect_url": "https://zomato-instant-refund.xyz",
        "visual_tampering_mode": "cropped_tinted",
        "account_age_days": 2,
        "followers_count": 19,
        "following_count": 3100,
    },
    {
        "id": "preset_paytm_high",
        "label": "HIGH RISK: Paytm Homoglyph Rogue App (@paytrn_kyc_helpdesk)",
        "brand_name": "Paytm",
        "suspect_handle": "@paytrn_kyc_helpdesk",
        "platform": "Telegram",
        "suspect_bio": "Account blocked? Official support desk for immediate KYC update. Install AnyDesk verification tool from link below.",
        "suspect_url": "https://t.me/paytrn_kyc_portal",
        "visual_tampering_mode": "watermarked",
        "account_age_days": 9,
        "followers_count": 115,
        "following_count": 1890,
    },
    {
        "id": "preset_safe_community",
        "label": "SAFE / LOW: Student Coding Club Community Page (@cu_coding_community)",
        "brand_name": "ByteXL",
        "suspect_handle": "@cu_coding_community",
        "platform": "Instagram",
        "suspect_bio": "Unofficial student fan page & coding club at Chandigarh University sharing hackathon memories and algorithm notes.",
        "suspect_url": "https://github.com/cu-coding-club",
        "visual_tampering_mode": "unrelated_avatar",
        "account_age_days": 420,
        "followers_count": 1850,
        "following_count": 310,
    },
]


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "operational",
        "service": "BrandShield AI Multi-Modal Detection Engine",
        "version": "1.0.0",
        "pillars": {
            "pillar_1_vision": "FAISS IndexFlatIP (512-d) + CLIP (.onnx)",
            "pillar_2_nlp": "DistilBERT Scam Intent (.onnx) + Fraud Taxonomy",
            "pillar_3_heuristics": "Wagner-Fischer Levenshtein + Homoglyph Matrix",
        },
        "monitored_brands_count": len(VERIFIED_BRANDS),
    }


@router.get("/brands")
async def list_monitored_brands() -> Dict[str, Any]:
    return {
        "kpis": {
            "monitored_brands": len(VERIFIED_BRANDS),
            "total_accounts_scanned": 8450,
            "critical_impersonators_blocked": 6,
            "avg_scan_latency_ms": 14.2,
        },
        "brands": [b.model_dump() for b in VERIFIED_BRANDS.values()],
    }


@router.get("/brands/{brand_id}")
async def get_brand_profile(brand_id: str) -> Dict[str, Any]:
    for key, profile in VERIFIED_BRANDS.items():
        if profile.brand_id.lower() == brand_id.lower() or key == brand_id.lower():
            return profile.model_dump()
    raise HTTPException(status_code=404, detail=f"Brand profile '{brand_id}' not found.")


@router.post("/brands")
async def register_brand_profile(payload: BrandProfileCreateRequest) -> Dict[str, Any]:
    key = payload.brand_name.lower().strip()
    brand_id = f"BRD-{len(VERIFIED_BRANDS) + 1:03d}"
    new_profile = BrandProfile(
        brand_id=brand_id,
        brand_name=payload.brand_name,
        official_handle=payload.official_handle,
        official_domain=payload.official_domain,
        category=payload.category,
        official_bio=payload.official_bio,
        official_mobile_apps=payload.official_mobile_apps,
        official_publisher=payload.official_publisher,
        verified_followers=payload.verified_followers,
        logo_fingerprint_id=f"vec_{key}_512d_v1",
    )
    VERIFIED_BRANDS[key] = new_profile
    return {
        "status": "REGISTERED_SUCCESSFULLY",
        "brand_id": brand_id,
        "brand_profile": new_profile.model_dump(),
    }


@router.get("/presets")
async def get_demo_presets() -> Dict[str, Any]:
    return {"presets": PRESET_SCENARIOS}
