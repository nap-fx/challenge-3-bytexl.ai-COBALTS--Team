"""
Pillar 3: Algorithmic Typosquatting, Homoglyphs, 1-Word Mutation & Account Lifecycle Heuristics
Incorporates dnstwist permutation matrices, single-word brand extension detection,
and sleeper dormancy / burner account anomaly metrics.
"""

import math
import re
from typing import List, Tuple, Dict, Any
from .schemas import HeuristicsResult


SCAM_AFFIXES = [
    "support", "official", "helpdesk", "care", "refund", "refunds",
    "careers", "hiring", "jobs", "india", "verified", "help", "service",
    "desk", "portal", "team", "admin", "pay", "rewards", "claim",
    "recruiters", "admissions", "placement", "offers", "verify"
]

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

    return HeuristicsResult(
        score=round(final_score, 1),
        levenshtein_distance=dist_brand,
        normalized_handle_similarity=round(similarity_ratio * 100.0, 1),
        homoglyphs_detected=homoglyphs_found,
        malicious_affixes=sorted(set(detected_affixes)),
        metadata_anomalies=anomalies,
    )
