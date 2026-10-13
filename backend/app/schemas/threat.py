from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, AliasChoices, ConfigDict


class BrandProfile(BaseModel):
    brand_id: str
    brand_name: str
    official_handle: str
    official_domain: str
    category: str
    official_bio: str
    verified_followers: int
    logo_fingerprint_id: str


class ScanRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    brand_name: str = Field(..., min_length=1, max_length=100, description="Target brand being protected, e.g., ByteXL")
    suspect_handle: str = Field(
        default="@bytexl_support_official",
        validation_alias=AliasChoices("suspect_handle", "target_handle", "handle"),
        description="Suspect social handle or app package"
    )
    platform: str = Field(default="Instagram", description="Platform: Instagram, X, Telegram, Google Play, Web")
    suspect_bio: str = Field(
        default="",
        validation_alias=AliasChoices("suspect_bio", "bio", "description"),
        description="Bio or description text on the suspect profile/app"
    )
    suspect_url: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("suspect_url", "profile_url", "url"),
        description="External link or URL listed on the suspect profile"
    )
    visual_tampering_mode: str = Field(
        default="cloned_logo",
        description="Visual simulation mode: cloned_logo, cropped_tinted, watermarked, unrelated_avatar"
    )
    account_age_days: int = Field(default=3, ge=0, description="Age of suspect account in days")
    dormancy_gap_days: int = Field(default=0, ge=0, description="Days dormant before sudden activity (sleeper hack check)")
    followers_count: int = Field(default=42, ge=0)
    following_count: int = Field(default=4850, ge=0)


class HighlightedSpan(BaseModel):
    phrase: str
    category: str
    risk_contribution: float


class VisionResult(BaseModel):
    score: float = Field(..., description="0-100 visual similarity score")
    cosine_similarity: float = Field(..., description="0.0-1.0 raw vector inner product")
    engine: str = Field(default="FAISS IndexFlatIP + CLIP-ViT-B/32 (.onnx)")
    inference_ms: float
    detected_anomalies: List[str]
    bounding_box: Dict[str, int]


class NLPResult(BaseModel):
    score: float = Field(..., description="0-100 scam intent probability")
    engine: str = Field(default="DistilBERT-ScamIntent (.onnx) + Fraud Pattern Rules")
    inference_ms: float
    flagged_phrases: List[HighlightedSpan]
    detected_categories: List[str]


class HeuristicsResult(BaseModel):
    score: float = Field(..., description="0-100 handle deception & metadata score")
    levenshtein_distance: int
    normalized_handle_similarity: float
    homoglyphs_detected: List[str]
    malicious_affixes: List[str]
    metadata_anomalies: List[str]


class VictimReviewReport(BaseModel):
    complaint_count: int
    scam_sentiment_pct: float
    compiled_snippets: List[str]


class ScanResponse(BaseModel):
    scan_id: str
    timestamp_utc: str
    brand_profile: BrandProfile
    suspect_handle: str
    target_handle: str
    platform: str
    suspect_bio: str
    suspect_url: str
    enricher_status: str = Field(default="LIVE_SCRAPE_OK", description="LIVE_SCRAPE_OK, CAPTCHA_FALLBACK, URL_OFFLINE_PARSED, MANUAL_INPUT")
    social_reach_score: float = Field(default=24.0, description="0-100 exposure index based on followers/shares")
    # Primary & alias fields for seamless frontend compatibility
    unified_threat_score: float
    impersonation_score: float
    visual_match_percent: float
    scam_intent_detected: bool
    severity_level: str
    risk_level: str
    severity_color: str
    recommended_action: str
    takedown_unlocked: bool
    flags: List[str]
    victim_reviews: VictimReviewReport
    total_latency_ms: float
    pillar_1_vision: VisionResult
    pillar_2_nlp: NLPResult
    pillar_3_heuristics: HeuristicsResult


ThreatResult = ScanResponse


class TakedownRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    scan_id: str = Field(default="BS-2026")
    brand_name: str = Field(default="ByteXL")
    official_handle: str = Field(default="@bytexl_official")
    official_domain: str = Field(default="bytexl.com")
    suspect_handle: str = Field(
        default="@bytexl_support_official",
        validation_alias=AliasChoices("suspect_handle", "target_handle", "handle")
    )
    platform: str = Field(default="Instagram")
    suspect_url: str = Field(
        default="https://instagram.com/bytexl_support_official",
        validation_alias=AliasChoices("suspect_url", "profile_url", "url")
    )
    suspect_bio: str = Field(
        default="Official Support & Direct Hiring Desk. Send Rs. 500 registration fee.",
        validation_alias=AliasChoices("suspect_bio", "bio")
    )
    unified_threat_score: float = Field(
        default=96.0,
        validation_alias=AliasChoices("unified_threat_score", "impersonation_score", "score")
    )
    visual_similarity: float = Field(default=96.5)
    nlp_score: float = Field(default=94.0)
    heuristic_score: float = Field(default=92.0)
    flagged_evidence: List[str] = Field(default_factory=list)
    victim_reviews: Optional[VictimReviewReport] = None


class TakedownResponse(BaseModel):
    case_reference: str
    generated_at_utc: str
    recipient_abuse_desk: str
    recipient_email: str
    subject_line: str
    legal_notice_body: str
    statutory_citations: List[str]
    status: str = "READY_FOR_DISPATCH"
