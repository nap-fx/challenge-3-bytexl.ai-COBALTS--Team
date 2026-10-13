"""
End-to-End Automated Test Suite for BrandShield AI Backend
Verifies all 3 detection pillars, Block 1-4 upgrades (Link Extraction,
Homoglyphs, 1-Word Mutation, Victim Reviews, and SQLite History).
"""

import os
import sys

# Ensure backend directory is on sys.path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas import ScanRequest, TakedownRequest
from app.models.detector import ThreatDetector
from app.takedown import generate_takedown_notice, build_takedown_pdf_bytes
from app.link_extractor import extract_metadata_from_url
from app.database import get_scan_history


def run_all_tests():
    detector = ThreatDetector.load()

    # Test 1: Critical Impersonation Case (ByteXL Fake Support + UPI Extortion)
    req_critical = ScanRequest(
        brand_name="ByteXL",
        suspect_handle="@bytexl_support_official",
        platform="Instagram",
        suspect_bio="Official Support & Direct Hiring Desk! Send Rs. 500 registration fee to bytexl.hr@okhdfcbank",
        suspect_url="https://bit.ly/bytexl-direct-onboarding",
        visual_tampering_mode="cloned_logo",
        account_age_days=3,
        dormancy_gap_days=0,
        followers_count=38,
        following_count=4920,
    )
    res_critical = detector.predict(req_critical)
    assert res_critical.unified_threat_score >= 88.0, f"Expected CRITICAL >=88, got {res_critical.unified_threat_score}"
    assert res_critical.severity_level in ("CRITICAL", "HIGH")
    assert res_critical.takedown_unlocked is True
    assert res_critical.victim_reviews.complaint_count >= 1, "Expected victim complaints synthesized"
    print(f"[PASS] Test 1 (Critical ByteXL Scam): Score = {res_critical.unified_threat_score}% ({res_critical.severity_level})")

    # Test 2: Homoglyph Detection (paytrn -> paytm)
    req_glyph = ScanRequest(
        brand_name="Paytm",
        target_handle="@paytrn_kyc_helpdesk",
        platform="Telegram",
        bio="Verify KYC immediately via AnyDesk or account blocked.",
        visual_tampering_mode="watermarked",
        account_age_days=5,
        followers_count=20,
        following_count=2000,
    )
    res_glyph = detector.predict(req_glyph)
    assert len(res_glyph.pillar_3_heuristics.homoglyphs_detected) > 0, "Expected homoglyph 'rn'->'m' detection"
    print(f"[PASS] Test 2 (Homoglyph paytrn->paytm): Score = {res_glyph.unified_threat_score}% | Homoglyphs = {res_glyph.pillar_3_heuristics.homoglyphs_detected}")

    # Test 3: 1-Word Changed Mutation Check (ByteXL Recruiters)
    req_mutation = ScanRequest(
        brand_name="ByteXL",
        target_handle="@bytexl_recruiters",
        platform="X",
        bio="ByteXL recruitment partner.",
        visual_tampering_mode="cloned_logo",
        account_age_days=10,
        followers_count=45,
        following_count=300,
    )
    res_mutation = detector.predict(req_mutation)
    assert any("mutation" in a.lower() for a in res_mutation.pillar_3_heuristics.metadata_anomalies), "Expected 1-word mutation detected"
    print(f"[PASS] Test 3 (1-Word Mutation ByteXL Recruiters): Score = {res_mutation.unified_threat_score}%")

    # Test 4: Block 1 Fallback Enricher on Offline/Mock Link
    mock_link = "https://bytexl-fake-interview.xyz/support_desk"
    extracted = extract_metadata_from_url(mock_link, timeout_sec=0.5)
    assert extracted["has_risky_tld"] is True, "Expected .xyz flagged as risky TLD"
    assert extracted["enricher_status"] in ("URL_OFFLINE_PARSED", "CAPTCHA_FALLBACK"), f"Got {extracted['enricher_status']}"
    print(f"[PASS] Test 4 (Block 1 Fallback Enricher): Status = {extracted['enricher_status']} | Risky TLD = {extracted['has_risky_tld']}")

    # Test 5: 1-Click Automated Takedown with Victim Reviews & PDF Generation
    td_req = TakedownRequest(
        scan_id=res_critical.scan_id,
        brand_name="ByteXL",
        official_handle=res_critical.brand_profile.official_handle,
        official_domain=res_critical.brand_profile.official_domain,
        suspect_handle=res_critical.suspect_handle,
        platform=res_critical.platform,
        suspect_url=res_critical.suspect_url,
        suspect_bio=res_critical.suspect_bio,
        unified_threat_score=res_critical.unified_threat_score,
        visual_similarity=res_critical.pillar_1_vision.score,
        nlp_score=res_critical.pillar_2_nlp.score,
        heuristic_score=res_critical.pillar_3_heuristics.score,
        flagged_evidence=res_critical.flags,
        victim_reviews=res_critical.victim_reviews,
    )
    td_notice = generate_takedown_notice(td_req)
    pdf_bytes = build_takedown_pdf_bytes(td_req)
    assert td_notice.status == "READY_FOR_DISPATCH"
    assert pdf_bytes.startswith(b"%PDF"), "Expected valid PDF binary header"
    print(f"[PASS] Test 5 (1-Click Legal Takedown & PDF with Reviews): Case = {td_notice.case_reference} | PDF Size = {len(pdf_bytes)} bytes")

    # Test 6: SQLite Audit History Persistence
    history = get_scan_history(limit=5)
    assert len(history) >= 1, "Expected scan history in SQLite database"
    print(f"[PASS] Test 6 (SQLite History): Found {len(history)} persistent scans in scans_audit.db")

    print("\n==============================================")
    print("ALL 6 PRODUCTION BACKEND TESTS PASSED (100% OK)")
    print("==============================================")


if __name__ == "__main__":
    run_all_tests()
