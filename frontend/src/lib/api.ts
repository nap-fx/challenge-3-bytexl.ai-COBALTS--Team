// BrandShield AI — API Client & Schema Types
// Synchronized with backend API_CONTRACT.md and schemas

export const API_BASE_URL = typeof window !== 'undefined' && window.location.hostname === 'localhost' 
  ? 'http://127.0.0.1:8000' 
  : 'http://127.0.0.1:8000';

export interface ScanRequest {
  brand_name: string;
  suspect_handle: string;
  platform?: string;
  suspect_bio?: string;
  suspect_url?: string;
  visual_tampering_mode?: string;
  account_age_days?: number;
  dormancy_gap_days?: number;
  followers_count?: number;
  following_count?: number;
}

export interface FlaggedPhrase {
  phrase: string;
  category: string;
  risk_contribution: number;
}

export interface PillarVision {
  score: number;
  cosine_similarity: number;
  engine: string;
  inference_ms: number;
  detected_anomalies: string[];
  bounding_box: { x: number; y: number; width: number; height: number };
}

export interface PillarNLP {
  score: number;
  engine: string;
  inference_ms: number;
  flagged_phrases: FlaggedPhrase[];
  detected_categories: string[];
}

export interface PillarHeuristics {
  score: number;
  levenshtein_distance: number;
  normalized_handle_similarity: number;
  homoglyphs_detected: string[];
  malicious_affixes: string[];
  metadata_anomalies: string[];
}

export interface PostEvidence {
  post_id: string;
  caption: string;
  image_url: string;
  ocr_extracted_text: string;
  audio_track: string;
  posted_date: string;
  likes_count: number;
  comments_count: number;
  post_threat_flag: boolean;
  flagged_keywords: string[];
}

export interface OsintFootprint {
  platform: string;
  handle_or_name: string;
  url: string;
  status: string;
  threat_level: string;
  notes: string;
}

export interface FollowerVelocityTimeline {
  anomaly_detected: boolean;
  anomaly_type: string;
  growth_multiplier: number;
  peak_gain_24h: number;
  daily_timeline: Array<{ day: string; followers: number; daily_gain: number }>;
}

export interface ScanResponse {
  scan_id: string;
  timestamp_utc: string;
  brand_profile: {
    brand_id: string;
    brand_name: string;
    official_handle: string;
    official_domain: string;
    category: string;
    official_bio: string;
    verified_followers: number;
    logo_fingerprint_id: string;
  };
  suspect_handle: string;
  platform: string;
  suspect_bio: string;
  suspect_url: string;
  social_reach_score: number;
  unified_threat_score: number;
  impersonation_score: number;
  visual_match_percent: number;
  scam_intent_detected: boolean;
  severity_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity_color: string;
  recommended_action: string;
  takedown_unlocked: boolean;
  flags: string[];
  victim_reviews?: {
    complaint_count: number;
    scam_sentiment_pct: number;
    compiled_snippets: string[];
  };
  total_latency_ms: number;
  pillar_1_vision: PillarVision;
  pillar_2_nlp: PillarNLP;
  pillar_3_heuristics: PillarHeuristics;
  recent_posts?: PostEvidence[];
  cross_platform_footprint?: OsintFootprint[];
  velocity_profile?: FollowerVelocityTimeline;
}

export interface AppStoreScanRequest {
  brand_name: string;
  app_title: string;
  package_id: string;
  publisher_name: string;
  store?: string;
  permissions_requested?: string[];
}

export interface AppStoreScanResponse {
  scan_id: string;
  timestamp_utc: string;
  brand_name: string;
  app_package_id: string;
  app_title: string;
  publisher_name: string;
  store: string;
  is_official_app: boolean;
  publisher_verified: boolean;
  publisher_mismatch_alert?: string;
  package_id_spoofing_score: number;
  permissions_risk_score: number;
  flagged_permissions: string[];
  visual_icon_match_pct: number;
  app_threat_index: number;
  severity_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity_color: string;
  recommended_action: string;
  takedown_action: string;
  review_forensics: {
    total_reviews_analyzed: number;
    synthetic_bot_reviews_detected: number;
    bot_probability_pct: number;
    astroturfing_burst_detected: boolean;
    temporal_burst_window_hours: number;
    rating_bimodal_split: {
      "5_star": number;
      "4_star": number;
      "3_star": number;
      "2_star": number;
      "1_star": number;
    };
    hyperbolic_praise_detected: boolean;
    flagged_review_snippets: string[];
  };
  publisher_portfolio: {
    publisher_name: string;
    total_apps_in_portfolio: number;
    average_app_lifespan_days: number;
    reputation_status: string;
    cross_app_scam_flags: number;
    portfolio_apps: Array<{
      app_title: string;
      package_id: string;
      rating: number;
      status: string;
    }>;
  };
  google_play_abuse_report: {
    case_id: string;
    violator_package_name: string;
    violator_publisher: string;
    protected_trademark_owner: string;
    official_developer: string;
    policy_infringement_category: string;
    evidence_citations: string[];
  };
}

export interface BrandProfile {
  brand_id: string;
  brand_name: string;
  official_handle: string;
  official_domain: string;
  category: string;
  official_bio: string;
  official_mobile_apps?: string[];
  official_publisher?: string;
  verified_followers: number;
  logo_fingerprint_id: string;
}

export interface BrandsResponse {
  kpis: {
    monitored_brands: number;
    total_accounts_scanned: number;
    critical_impersonators_blocked: number;
    avg_scan_latency_ms: number;
  };
  brands: BrandProfile[];
}

// API Functions
export async function apiFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {})
    },
    ...options
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API error ${response.status}: ${errorText}`);
  }
  return response.json();
}
