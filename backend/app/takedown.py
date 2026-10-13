"""
1-Click Automated Legal Takedown & Forensic PDF Generator
Generates statutory Cease & Desist / DMCA takedown notices and binary PDF packages,
including compiled victim reviews and forensic evidence tables.
"""

import io
from datetime import datetime, timezone
from typing import Dict, Tuple
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from .schemas import TakedownRequest, TakedownResponse


ABUSE_DESK_DIRECTORY: Dict[str, Tuple[str, str]] = {
    "instagram": ("Meta Platforms, Inc. — IP & Brand Enforcement Operations", "ip-infringement@support.instagram.com"),
    "x": ("X Corp. — Trust & Safety Trademark Abuse Desk", "trademark-notices@x.com"),
    "telegram": ("Telegram FZ-LLC — Abuse & Phishing Mitigation Team", "abuse@telegram.org"),
    "google play": ("Google LLC — Play Store App Security & Impersonation Review", "play-legal-removals@google.com"),
    "web": ("ICANN Registrar & Cloudflare Trust & Safety Abuse Desk", "abuse@cloudflare.com"),
}


def generate_takedown_notice(req: TakedownRequest) -> TakedownResponse:
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    plat_key = req.platform.strip().lower()
    desk_name, desk_email = ABUSE_DESK_DIRECTORY.get(
        plat_key,
        ("Platform Trust & Safety / Intellectual Property Desk", "abuse-enforcement@platform-security.org")
    )

    case_ref = f"BS-ENF-{req.scan_id.upper()}"
    subject = (
        f"[URGENT TAKEDOWN NOTICE] Brand Impersonation & Fraudulent Account ({req.suspect_handle}) "
        f"Targeting {req.brand_name} | Case Ref: {case_ref}"
    )

    evidence_bullets = "\n".join(f"  • {item}" for item in req.flagged_evidence) if req.flagged_evidence else (
        f"  • Unauthorized reproduction of protected {req.brand_name} visual mark ({req.visual_similarity}% FAISS match)\n"
        f"  • High-risk fraudulent solicitation / phishing bio intent ({req.nlp_score}% NLP probability)\n"
        f"  • Deceptive handle typosquatting targeting official handle {req.official_handle}"
    )

    reviews_text = ""
    if req.victim_reviews and req.victim_reviews.compiled_snippets:
        reviews_text = "\n\n4. COMPILED VICTIM REPORTS & COMMUNITY COMPLAINTS:\n" + "\n".join(
            f"  [Report] {snippet}" for snippet in req.victim_reviews.compiled_snippets
        )

    body = f"""FORMAL NOTICE OF TRADEMARK INFRINGEMENT, BRAND IMPERSONATION & PHISHING
================================================================================
Case Reference ID   : {case_ref}
Timestamp (UTC)     : {now_utc}
To                  : {desk_name} ({desk_email})
Protected Entity    : {req.brand_name} (Official Handle: {req.official_handle} | Domain: {req.official_domain})
Infringing Target   : {req.suspect_handle} on {req.platform}
Infringing URL      : {req.suspect_url}
Unified Threat Score: {req.unified_threat_score}% [CRITICAL SEVERITY]
================================================================================

1. STATEMENT OF AUTHORITY & PROTECTED INTELLECTUAL PROPERTY
This automated legal enforcement package is dispatched via BrandShield AI Digital Risk Protection
on behalf of {req.brand_name} ({req.official_domain}). {req.brand_name} holds exclusive trademark and brand
rights to its official name, logomark, and verified digital identity ({req.official_handle}).

2. FORENSIC AI EVIDENCE SUMMARY (SCAN ID: {req.scan_id})
Our multi-modal detection engine has confirmed malicious brand impersonation with the following telemetry:
  • Pillar 1 (Visual Logo Match - FAISS/CLIP 512-d) : {req.visual_similarity}% Cosine Similarity
  • Pillar 2 (NLP Scam & Extortion Intent)          : {req.nlp_score}% Fraud Probability
  • Pillar 3 (Handle Typosquatting & Heuristics)    : {req.heuristic_score}% Deception Index
  • Captured Bio / Description Text                 : "{req.suspect_bio}"

Specific Forensic Indicators Flagged:
{evidence_bullets}{reviews_text}

3. STATUTORY & PLATFORM POLICY VIOLATIONS
The reported account violates:
  (a) Section 66D of the Information Technology Act, 2000 (Punishment for cheating by personation by using computer resource);
  (b) Section 29 of the Trade Marks Act, 1999 & Digital Millennium Copyright Act (17 U.S.C. § 512);
  (c) {req.platform} Terms of Service prohibiting deceptive impersonation, advance-fee fraud, and credential harvesting.

4. DEMAND FOR IMMEDIATE EXPEDITED REMOVAL
Given the active financial and reputational harm posed to students and consumers, we formally request
that {desk_name} immediately suspend and permanently remove "{req.suspect_handle}" ({req.suspect_url})
and preserve associated registration metadata for law enforcement review.

Signed Electronically,
BrandShield AI — Autonomous Digital Risk Protection & Enforcement Engine
Authorized Security Operations Dispatch for {req.brand_name}
"""

    citations = [
        "Section 66D, Information Technology Act, 2000 — Cheating by personation using computer resource",
        "Section 29, Trade Marks Act, 1999 — Infringement of registered trade marks",
        "17 U.S.C. § 512(c) (DMCA) — Expedited takedown of infringing digital assets",
        f"{req.platform} Community Guidelines — Prohibition on Brand Impersonation & Financial Scams"
    ]

    return TakedownResponse(
        case_reference=case_ref,
        generated_at_utc=now_utc,
        recipient_abuse_desk=desk_name,
        recipient_email=desk_email,
        subject_line=subject,
        legal_notice_body=body,
        statutory_citations=citations,
        status="READY_FOR_DISPATCH"
    )


def build_takedown_pdf_bytes(req: TakedownRequest) -> bytes:
    """Generates a printable A4 Forensic Cease & Desist PDF in memory with victim reviews."""
    notice = generate_takedown_notice(req)
    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"Forensic Takedown Notice - {notice.case_reference}"
    )

    styles = getSampleStyleSheet()
    title_st = ParagraphStyle("TTitle", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=colors.HexColor("#991B1B"))
    sub_st = ParagraphStyle("TSub", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=colors.HexColor("#1E293B"), spaceAfter=6)
    h_st = ParagraphStyle("TH", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#0F172A"), spaceBefore=8, spaceAfter=4)
    body_st = ParagraphStyle("TB", parent=styles["Normal"], fontName="Helvetica", fontSize=9.2, leading=13, textColor=colors.HexColor("#1E293B"), spaceAfter=4)
    cell_st = ParagraphStyle("TC", parent=styles["Normal"], fontName="Helvetica", fontSize=8.8, leading=11.5, textColor=colors.HexColor("#0F172A"))

    story = [
        Paragraph("FORMAL LEGAL TAKEDOWN & IMPERSONATION ENFORCEMENT NOTICE", title_st),
        Paragraph(f"Case Reference: {notice.case_reference} | Generated: {notice.generated_at_utc}", sub_st),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#DC2626")),
        Spacer(1, 6),
    ]

    summary_rows = [
        [Paragraph("<b>Recipient Abuse Desk:</b>", cell_st), Paragraph(f"{notice.recipient_abuse_desk} ({notice.recipient_email})", cell_st)],
        [Paragraph("<b>Protected Brand Entity:</b>", cell_st), Paragraph(f"{req.brand_name} (Official: {req.official_handle} | {req.official_domain})", cell_st)],
        [Paragraph("<b>Infringing Target Handle:</b>", cell_st), Paragraph(f"<b>{req.suspect_handle}</b> on {req.platform} ({req.suspect_url})", cell_st)],
        [Paragraph("<b>Unified AI Threat Score:</b>", cell_st), Paragraph(f"<b>{req.unified_threat_score}% — CRITICAL IMPERSONATION</b>", cell_st)],
        [Paragraph("<b>3-Pillar Breakdown:</b>", cell_st), Paragraph(f"Vision (FAISS/CLIP): {req.visual_similarity}% | NLP Bio Scam: {req.nlp_score}% | Handle Heuristics: {req.heuristic_score}%", cell_st)],
    ]
    tbl = Table(summary_rows, colWidths=[48 * mm, 130 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#FEF2F2")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#FCA5A5")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FECACA")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)

    story.append(Paragraph("1. Captured Fraudulent Profile Bio & Solicitation Evidence", h_st))
    story.append(Paragraph(f"<i>\"{req.suspect_bio}\"</i>", body_st))

    if req.victim_reviews and req.victim_reviews.compiled_snippets:
        story.append(Paragraph(f"2. Compiled Victim Reports ({req.victim_reviews.complaint_count} Flags | {req.victim_reviews.scam_sentiment_pct}% Scam Sentiment)", h_st))
        for snip in req.victim_reviews.compiled_snippets:
            story.append(Paragraph(f"• {snip}", body_st))

    story.append(Paragraph("3. Statutory & Policy Violations Cited", h_st))
    for cit in notice.statutory_citations:
        story.append(Paragraph(f"• {cit}", body_st))

    story.append(Paragraph("4. Formal Enforcement Demand", h_st))
    story.append(Paragraph(
        f"On behalf of <b>{req.brand_name}</b>, we demand the immediate suspension and permanent removal of "
        f"<b>{req.suspect_handle}</b> ({req.suspect_url}) to prevent ongoing financial and credential fraud against users.",
        body_st
    ))

    doc.build(story)
    return buf.getvalue()
