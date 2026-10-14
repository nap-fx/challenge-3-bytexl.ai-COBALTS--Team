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

    brand_name: Optional[str] = Field(
        default="Auto-Detect",
        description="Target brand being protected, e.g., ByteXL or 'Auto-Detect'"
    )
    suspect_handle: Optional[str] = Field(
        default="@bytexl_support_official",
        validation_alias=AliasChoices("suspect_handle", "target_handle", "handle"),
        description="Suspect social handle or mobile app name/package"
    )
    platform: Optional[str] = Field(
        default="Instagram",
        description="Platform: Instagram, X, Telegram, Google Play, App Store, Web"
    )
    suspect_bio: Optional[str] = Field(
        default="",
        validation_alias=AliasChoices("suspect_bio", "bio", "description", "app_description"),
        description="Bio or description text on the suspect profile/app"
    )
    suspect_url: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("suspect_url", "profile_url", "url", "target_url"),
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


class FollowerVelocityTimeline(BaseModel):
    growth_classification: str = Field(default="ORGANIC_GROWTH", description="ORGANIC_GROWTH, PAID_PROMOTION_SPIKE, BOT_FARM_INFLATION, or SLEEPER_BURST")
    velocity_anomaly_score: float = Field(default=12.0)
    daily_timeline: List[Dict[str, Any]] = Field(default_factory=list)


class HeuristicsResult(BaseModel):
    score: float = Field(..., description="0-100 handle deception & metadata score")
    levenshtein_distance: int
    normalized_handle_similarity: float
    homoglyphs_detected: List[str]
    malicious_affixes: List[str]
    metadata_anomalies: List[str]
    app_publisher_anomaly: Optional[str] = None
    velocity_profile: FollowerVelocityTimeline = Field(default_factory=FollowerVelocityTimeline)


class VictimReviewReport(BaseModel):
    complaint_count: int
    scam_sentiment_pct: float
    compiled_snippets: List[str]


class PostEvidence(BaseModel):
    post_id: str = Field(..., description="Post identifier or shortcode")
    caption: str = Field(default="", description="Post caption / description text")
    image_url: Optional[str] = Field(default=None, description="Image thumbnail or media URL")
    ocr_extracted_text: Optional[str] = Field(default=None, description="Text extracted from image via OCR")
    audio_track: Optional[str] = Field(default=None, description="Music, song title, or audio track")
    audio_transcript: Optional[str] = Field(default=None, description="Transcribed spoken words/voiceover from video or reel audio")
    audio_threat_score: float = Field(default=0.0, description="Spoken voiceover threat score evaluated via NLP")
    posted_date: str = Field(default="Recent", description="Timestamp or human-readable relative date")
    likes_count: int = Field(default=0, ge=0)
    comments_count: int = Field(default=0, ge=0)
    post_threat_flag: bool = Field(default=False, description="True if post contains phishing/scam signals in caption, image, or audio")
    flagged_keywords: List[str] = Field(default_factory=list, description="Suspicious keywords identified in caption, OCR, or audio transcript")


class PlatformPresence(BaseModel):
    platform: str = Field(..., description="Social network or web surface (e.g. Instagram, X, Telegram, GitHub, Domain)")
    handle_or_name: str = Field(..., description="Username, handle, or domain name")
    url: str = Field(..., description="Direct link to profile or search URL")
    status: str = Field(..., description="FOUND_ACTIVE, SUSPECT_MIRROR, OFFICIAL_VERIFIED, or NOT_FOUND")
    threat_level: str = Field(default="LOW", description="HIGH, MEDIUM, LOW, or NEUTRAL")
    notes: str = Field(default="", description="Forensic notes about cross-platform footprint")


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
    recent_posts: List[PostEvidence] = Field(default_factory=list, description="Forensic recent posts with OCR & audio metadata")
    cross_platform_footprint: List[PlatformPresence] = Field(default_factory=list, description="Discovered identity footprint across the web")
    account_age_days: int = Field(default=3, description="Estimated or verified account age in days")
    account_age_label: str = Field(default="3 Days Old (High-Risk Burner)", description="Human-readable age category")
    account_creation_predicted: str = Field(default="October 2026", description="Predicted registration date")
    account_age_risk_score: float = Field(default=85.0, description="0-100 risk score derived from account youth and velocity")
    description_style: str = Field(default="Advance-Fee & Deceptive Phishing Solicitation", description="Style analysis of bio text")
    description_style_score: float = Field(default=90.0, description="0-100 style risk score based on phrasing patterns")
    description_style_category: str = Field(default="HIGH_RISK_SCAM_STYLE", description="HIGH_RISK_SCAM_STYLE, SUSPICIOUS_URGENCY, FAN_COMMUNITY, or AUTHENTIC_CORPORATE")


ThreatResult = ScanResponse


class PostExtractRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    url: Optional[str] = Field(default=None, description="Profile or post URL")
    handle: Optional[str] = Field(default=None, description="Account handle")
    platform: str = Field(default="Instagram", description="Platform name")
    limit: int = Field(default=3, ge=1, le=10, description="Number of recent posts to extract")


class OsintFootprintRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    query: str = Field(..., min_length=1, description="Username, brand, or person name to surf on the internet")
    protected_brand: Optional[str] = Field(default="ByteXL", description="Brand context for detecting impersonation mirrors")


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


class AppStoreScanRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    brand_name: str = Field(default="Auto-Detect", description="Protected brand name")
    app_url: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("app_url", "url", "store_url"),
        description="Google Play or Apple App Store URL"
    )
    package_id: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("package_id", "bundle_id", "app_id"),
        description="Android package name (e.g. com.bytexl.app) or iOS bundle ID"
    )
    app_title: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("app_title", "title", "name")
    )
    publisher_name: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("publisher_name", "publisher", "developer")
    )
    store: str = Field(default="Google Play", description="Store: Google Play, Apple App Store, Third-Party APK")
    permissions_requested: List[str] = Field(
        default_factory=lambda: [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS"
        ]
    )
    icon_tampering_mode: str = Field(default="cloned_icon")
    download_count_range: str = Field(default="10K+")


class AppStoreReviewAnalysis(BaseModel):
    total_reviews_analyzed: int = 45
    synthetic_bot_reviews_detected: int = 18
    bot_probability_pct: float = 82.5
    astroturfing_burst_detected: bool = True
    temporal_burst_window_hours: int = 36
    rating_bimodal_split: Dict[str, int] = Field(default_factory=lambda: {"5_star": 28, "1_star": 17, "2_to_4_star": 0})
    hyperbolic_praise_detected: bool = True
    flagged_review_snippets: List[str] = Field(default_factory=list)


class PublisherPortfolioProfile(BaseModel):
    publisher_name: str
    total_apps_in_portfolio: int = 4
    average_app_lifespan_days: int = 24
    reputation_status: str = "HIGH_RISK_EPHEMERAL_DEVELOPER"
    cross_app_scam_flags: int = 3
    portfolio_apps: List[Dict[str, Any]] = Field(default_factory=list)


class AppStoreScanResponse(BaseModel):
    scan_id: str
    timestamp_utc: str
    brand_name: str
    app_package_id: str
    app_title: str
    publisher_name: str
    store: str
    is_official_app: bool
    publisher_verified: bool
    publisher_mismatch_alert: Optional[str] = None
    package_id_spoofing_score: float
    permissions_risk_score: float
    flagged_permissions: List[str]
    visual_icon_match_pct: float
    app_threat_index: float
    severity_level: str
    severity_color: str
    recommended_action: str
    takedown_action: str
    review_forensics: AppStoreReviewAnalysis = Field(default_factory=AppStoreReviewAnalysis)
    publisher_portfolio: PublisherPortfolioProfile = Field(default_factory=lambda: PublisherPortfolioProfile(publisher_name="Unknown"))
    google_play_abuse_report: Dict[str, Any]


class BrandProfileCreateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    brand_name: str = Field(..., min_length=1)
    official_handle: str = Field(...)
    official_domain: str = Field(default="example.com")
    category: str = Field(default="Enterprise Brand")
    official_bio: str = Field(default="")
    official_mobile_apps: List[str] = Field(default_factory=list)
    official_publisher: str = Field(...)
    verified_followers: int = Field(default=50000)
