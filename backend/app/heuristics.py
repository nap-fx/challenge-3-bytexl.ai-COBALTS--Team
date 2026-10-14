"""
Pillar 3: Algorithmic Typosquatting, Homoglyphs, 1-Word Mutation & Account Lifecycle Heuristics
Incorporates dnstwist permutation matrices, single-word brand extension detection,
and sleeper dormancy / burner account anomaly metrics.
"""

import math
import re
from typing import List, Tuple, Dict, Any, Optional
from .schemas import HeuristicsResult, FollowerVelocityTimeline


SCAM_AFFIXES = [
    # Support & Authority Spoofing
    "support", "official", "helpdesk", "care", "refund", "refunds",
    "careers", "hiring", "jobs", "india", "verified", "help", "service",
    "desk", "portal", "team", "admin", "pay", "rewards", "claim",
    "recruiters", "admissions", "placement", "placements", "offers", "verify",
    "verification", "kyc", "recovery", "helpline", "assistance", "agent",
    # Academic, Campus, Placement & Exam Leaks
    "exam", "exams", "leak", "leaks", "dumps", "paper", "papers",
    "answers", "answerkey", "cheat", "cheats", "cracked", "lms",
    "course", "courses", "cert", "certification", "cell", "internship",
    "internships", "council", "board", "campus", "student", "college"
]


def extract_deceptive_tokens(handle: str) -> List[str]:
    """
    Extracts high-risk scam/phishing/impersonation tokens from any handle slug.
    Checks delimited tokens, prefixes, and suffixes.
    """
    clean = re.sub(r"[^a-z0-9_.\-]", "", handle.lower().lstrip("@"))
    tokens = [t for t in re.split(r"[._\-]+", clean) if t]
    matched: List[str] = []

    for tok in tokens:
        for affix in SCAM_AFFIXES:
            if tok == affix:
                matched.append(affix)
            elif len(tok) >= len(affix) + 3:
                if tok.startswith(affix) or tok.endswith(affix):
                    matched.append(affix)

    # Substring check for compound tokens like 'placementdesk' or 'examleaks'
    compact = re.sub(r"[._\-0-9]", "", clean)
    for affix in ("placement", "examleak", "helpdesk", "customercare", "answerkey", "dumps"):
        if affix in compact and affix not in matched:
            matched.append(affix)

    return sorted(list(set(matched)))


def extract_brand_candidate_from_handle(handle: str) -> Optional[str]:
    """
    Extracts the root brand candidate from a handle slug by stripping known deceptive affixes.
    e.g., '@amazon_help_desk' -> 'Amazon'
    e.g., '@bytexl_support_official' -> 'ByteXL'
    e.g., '@netflix_india_care' -> 'Netflix'
    e.g., '@flipkart_refund_support' -> 'Flipkart'
    """
    clean = re.sub(r"[^a-z0-9_.\-]", "", handle.lower().lstrip("@"))
    tokens = [t for t in re.split(r"[._\-]+", clean) if t]
    
    brand_tokens = [
        t for t in tokens 
        if t not in SCAM_AFFIXES and len(t) >= 3 and not t.isdigit()
    ]
    if brand_tokens:
        candidate = brand_tokens[0]
        brand_map = {
            "bytexl": "ByteXL",
            "kampus": "Kampus.vc",
            "zomato": "Zomato",
            "paytm": "Paytm",
            "zerodha": "Zerodha",
            "amazon": "Amazon",
            "google": "Google",
            "microsoft": "Microsoft",
            "netflix": "Netflix",
            "flipkart": "Flipkart",
            "apple": "Apple",
            "spotify": "Spotify",
            "uber": "Uber",
            "swiggy": "Swiggy",
            "tcs": "TCS",
            "infosys": "Infosys",
            "wipro": "Wipro",
        }
        return brand_map.get(candidate, candidate.title())
    return None


HOMOGLYPH_RULES: List[Tuple[str, str, str]] = [
    ("rn", "m", "'rn' substituted for 'm' (digraph homoglyph)"),
    ("vv", "w", "'vv' substituted for 'w' (digraph homoglyph)"),
    ("cl", "d", "'cl' substituted for 'd' (digraph homoglyph)"),
    ("0", "o", "Digit '0' substituted for letter 'o'"),
    ("1", "l", "Digit '1' substituted for letter 'l' / 'i'"),
    ("5", "s", "Digit '5' substituted for letter 's'"),
    ("@", "a", "Symbol '@' substituted for letter 'a'"),
    ("$", "s", "Symbol '$' substituted for letter 's'"),
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes exact Wagner-Fischer Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_one_word_mutation(brand_name: str, suspect_handle: str) -> List[str]:
    """
    Detects '1-Word Changed' brand extension spoofing:
    e.g., Official: 'ByteXL Careers' -> Suspect: 'ByteXL Recruiters' or 'ByteXL Placements'.
    """
    mutations: List[str] = []
    brand_tokens = [t.lower() for t in re.split(r"[\s._\-]+", brand_name) if t]
    suspect_tokens = [t.lower() for t in re.split(r"[\s._\-]+", suspect_handle.lstrip("@")) if t]

    if not brand_tokens or not suspect_tokens:
        return mutations

    # Check if primary brand anchor exists in suspect tokens
    primary_brand = brand_tokens[0]
    if primary_brand in suspect_tokens:
        other_tokens = [t for t in suspect_tokens if t != primary_brand]
        for tok in other_tokens:
            if tok in SCAM_AFFIXES:
                mutations.append(f"Unauthorized 1-word commercial mutation '{primary_brand} {tok.capitalize()}'")

    return mutations


def calculate_social_reach_factor(followers: int, following: int) -> Tuple[float, float]:
    """
    Computes a 0-100 social reach score and an exposure multiplier (1.0 to 1.25)
    to reflect real-world victim risk.
    """
    f = max(followers, 0)
    reach_score = min(100.0, round(math.log10(max(f, 1) + 1) * 20.0, 1))
    multiplier = min(1.25, round(1.0 + 0.04 * math.log10(max(f, 10)), 3))
    return reach_score, multiplier


def analyze_handle_and_metadata(
    official_handle: str,
    brand_name: str,
    suspect_handle: str,
    account_age_days: int = 3,
    dormancy_gap_days: int = 0,
    followers_count: int = 42,
    following_count: int = 4850,
) -> HeuristicsResult:
    clean_official = re.sub(r"[^a-z0-9]", "", official_handle.lower().lstrip("@"))
    clean_brand = re.sub(r"[^a-z0-9]", "", brand_name.lower())
    raw_suspect = suspect_handle.lower().lstrip("@")

    # 1. Detect deceptive affixes (_support, _official, etc.)
    tokens = [t for t in re.split(r"[._\-]+", raw_suspect) if t]
    detected_affixes: List[str] = []
    for tok in tokens:
        for affix in SCAM_AFFIXES:
            if tok == affix or (len(tok) > 4 and tok.endswith(affix)):
                detected_affixes.append(f"_{affix}")

    # Strip affixes to isolate core brand root
    stripped_suspect = raw_suspect
    for affix in SCAM_AFFIXES:
        stripped_suspect = re.sub(rf"[._\-]?{affix}", "", stripped_suspect)
    core_suspect = re.sub(r"[^a-z0-9]", "", stripped_suspect) or re.sub(r"[^a-z0-9]", "", raw_suspect)

    # 2. Homoglyph inspection (dnstwist style)
    homoglyphs_found: List[str] = []
    normalized_core = core_suspect
    for glyph, replacement, desc in HOMOGLYPH_RULES:
        if glyph in core_suspect and glyph not in clean_brand and replacement in clean_brand:
            homoglyphs_found.append(desc)
            normalized_core = normalized_core.replace(glyph, replacement)

    # Check repeated letter padding (e.g., bytexll or zomatooo)
    if re.search(r"([a-z])\1\1+", core_suspect) or (
        len(core_suspect) == len(clean_brand) + 1 and set(core_suspect) == set(clean_brand)
    ):
        homoglyphs_found.append("Character duplication / typosquatting padding detected")

    # 3. 1-Word Changed Mutation Check
    word_mutations = detect_one_word_mutation(brand_name, suspect_handle)

    # 4. Levenshtein distance against brand root
    dist_brand = levenshtein_distance(clean_brand, core_suspect)
    dist_norm = levenshtein_distance(clean_brand, normalized_core)
    best_dist = min(dist_brand, dist_norm)

    max_len = max(len(clean_brand), len(core_suspect), 1)
    similarity_ratio = max(0.0, 1.0 - (best_dist / max_len))

    is_exact_official = (raw_suspect == official_handle.lower().lstrip("@"))

    # 5. Account Lifecycle & Dormancy Checks
    anomalies: List[str] = []
    meta_risk_bonus = 0.0

    if account_age_days <= 14:
        anomalies.append(f"Newly registered burner account ({account_age_days} days old)")
        meta_risk_bonus += 15.0
    elif account_age_days <= 45:
        anomalies.append(f"Recent account creation ({account_age_days} days old)")
        meta_risk_bonus += 8.0

    # Dormant sleeper account hijack check
    if dormancy_gap_days > 180 and account_age_days > 200:
        anomalies.append(
            f"Dormant sleeper account hijack detected ({dormancy_gap_days} days inactive before sudden activity)"
        )
        meta_risk_bonus += 18.0

    # Bot ratio check
    if following_count > 500 and followers_count < 250:
        ratio = round(following_count / max(followers_count, 1), 1)
        anomalies.append(f"Bot mass-following signature (Following/Follower ratio = {ratio}:1)")
        meta_risk_bonus += 14.0

    anomalies.extend(word_mutations)

    # Combine into 0-100 Heuristic Score
    if is_exact_official and account_age_days > 180 and not detected_affixes and dormancy_gap_days == 0:
        final_score = 5.0
    else:
        base_deception = similarity_ratio * 60.0
        affix_bonus = min(22.0, len(detected_affixes) * 11.0)
        glyph_bonus = min(20.0, len(homoglyphs_found) * 14.0)
        mutation_bonus = min(15.0, len(word_mutations) * 15.0)
        final_score = min(99.0, base_deception + affix_bonus + glyph_bonus + mutation_bonus + meta_risk_bonus)

    velocity_prof = generate_velocity_profile(
        followers_count=followers_count,
        following_count=following_count,
        account_age_days=account_age_days,
        dormancy_gap_days=dormancy_gap_days,
    )

    return HeuristicsResult(
        score=round(final_score, 1),
        levenshtein_distance=dist_brand,
        normalized_handle_similarity=round(similarity_ratio * 100.0, 1),
        homoglyphs_detected=homoglyphs_found,
        malicious_affixes=sorted(set(detected_affixes)),
        metadata_anomalies=anomalies,
        velocity_profile=velocity_prof,
    )


def generate_velocity_profile(
    followers_count: int,
    following_count: int,
    account_age_days: int,
    dormancy_gap_days: int
) -> FollowerVelocityTimeline:
    """
    Evaluates follower growth velocity anomalies (Pillar 3 Cat 3-5):
    - Distinguishes organic growth vs. sudden bot farm inflation or sleeper burst.
    - Generates 7-day timeline telemetry for frontend graphing.
    """
    if dormancy_gap_days > 180:
        classification = "SLEEPER_BURST"
        anomaly_score = 88.0
        timeline = [
            {"day": "Day 1", "followers": max(10, followers_count // 20)},
            {"day": "Day 2", "followers": max(10, followers_count // 20)},
            {"day": "Day 3", "followers": max(10, followers_count // 20)},
            {"day": "Day 4", "followers": max(15, followers_count // 15)},
            {"day": "Day 5", "followers": followers_count // 4},
            {"day": "Day 6", "followers": followers_count // 2},
            {"day": "Day 7", "followers": followers_count},
        ]
    elif account_age_days <= 14 and followers_count > 500:
        classification = "BOT_FARM_INFLATION"
        anomaly_score = 92.0
        timeline = [
            {"day": "Day 1", "followers": 2},
            {"day": "Day 2", "followers": 15},
            {"day": "Day 3", "followers": 80},
            {"day": "Day 4", "followers": followers_count // 3},
            {"day": "Day 5", "followers": followers_count // 2},
            {"day": "Day 6", "followers": int(followers_count * 0.85)},
            {"day": "Day 7", "followers": followers_count},
        ]
    elif following_count > 2000 and followers_count > 2000:
        classification = "PAID_PROMOTION_SPIKE"
        anomaly_score = 55.0
        timeline = [
            {"day": "Day 1", "followers": followers_count // 3},
            {"day": "Day 2", "followers": int(followers_count * 0.4)},
            {"day": "Day 3", "followers": int(followers_count * 0.5)},
            {"day": "Day 4", "followers": int(followers_count * 0.7)},
            {"day": "Day 5", "followers": int(followers_count * 0.85)},
            {"day": "Day 6", "followers": int(followers_count * 0.95)},
            {"day": "Day 7", "followers": followers_count},
        ]
    else:
        classification = "ORGANIC_GROWTH"
        anomaly_score = 12.0
        timeline = [
            {"day": "Day 1", "followers": max(1, int(followers_count * 0.75))},
            {"day": "Day 2", "followers": max(2, int(followers_count * 0.79))},
            {"day": "Day 3", "followers": max(3, int(followers_count * 0.84))},
            {"day": "Day 4", "followers": max(4, int(followers_count * 0.88))},
            {"day": "Day 5", "followers": max(5, int(followers_count * 0.92))},
            {"day": "Day 6", "followers": max(6, int(followers_count * 0.96))},
            {"day": "Day 7", "followers": followers_count},
        ]

    return FollowerVelocityTimeline(
        growth_classification=classification,
        velocity_anomaly_score=anomaly_score,
        daily_timeline=timeline
    )
