from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, AliasChoices, ConfigDict


class BrandProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    brand_id: str = Field(default="BRD-001")
    brand_name: str = Field(..., description="Company / Brand Name")
    official_handle: str = Field(..., description="Official social media account handle, e.g., @bytexl_official")
    official_domain: str = Field(default="bytexl.com", description="Official website domain")
    category: str = Field(default="Enterprise Brand Asset")
    official_bio: str = Field(default="", description="Official verified biography / description")
    official_mobile_apps: List[str] = Field(
        default_factory=list,
        description="List of official mobile app package IDs, e.g. ['com.bytexl.app', 'com.bytexl.learning']"
    )
    official_publisher: str = Field(
        default="ByteXL EdTech Pvt Ltd",
        description="Official app store developer / publisher name"
    )
    verified_followers: int = Field(default=148000)
    logo_fingerprint_id: str = Field(default="vec_bytexl_512d_v1")


class ScanRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    brand_name: str = Field(..., min_length=1, max_length=100, description="Target brand being protected, e.g., ByteXL")
    suspect_handle: str = Field(
        default="@bytexl_support_official",
        validation_alias=AliasChoices("suspect_handle", "target_handle", "handle"),
        description="Suspect social handle or mobile app name/package"
    )
    platform: str = Field(
        default="Instagram",
        description="Platform: Instagram, X, Telegram, Google Play, App Store, Web"
    )
    suspect_bio: str = Field(
        default="",
        validation_alias=AliasChoices("suspect_bio", "bio", "description", "app_description"),
        description="Bio or description text on the suspect profile/app"
    )
    suspect_url: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("suspect_url", "profile_url", "url"),
        description="External link or URL listed on the suspect profile"
    )
    suspect_publisher: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("suspect_publisher", "publisher", "developer"),
        description="Developer/Publisher name on app store (used for App Store Monitoring)"
    )
    visual_tampering_mode: str = Field(
        default="cloned_logo",
        description="Visual simulation mode: cloned_logo, cropped_tinted, watermarked, unrelated_avatar"
    )
    account_age_days: int = Field(default=3, ge=0, description="Age of suspect account/app in days")
    dormancy_gap_days: int = Field(default=0, ge=0, description="Days dormant before sudden activity")
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
    app_publisher_anomaly: Optional[str] = None


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
    enricher_status: str = Field(default="LIVE_SCRAPE_OK")
    social_reach_score: float = Field(default=24.0)
    is_official_asset: bool = Field(default=False, description="True if verified as genuine official asset and excluded")
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
