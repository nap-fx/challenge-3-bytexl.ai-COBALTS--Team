from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Request, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from ....schemas import (
    ScanRequest,
    ScanResponse,
    PostEvidence,
    PlatformPresence,
    PostExtractRequest,
    OsintFootprintRequest,
    AppStoreScanRequest,
    AppStoreScanResponse,
)
from ....models.detector import ThreatDetector
from ....link_extractor import extract_metadata_from_url
from ....osint_engine import extract_recent_posts, search_internet_footprint
from ....app_store_engine import scan_mobile_app_asset
from ....database import get_scan_history, get_scan_by_id

router = APIRouter()


class LinkExtractRequest(BaseModel):
    url: str = Field(..., description="Raw suspect URL to inspect")


@router.post("/scan", response_model=ScanResponse)
async def scan_profile(payload: ScanRequest, request: Request) -> ScanResponse:
    detector: ThreatDetector = getattr(request.app.state, "detector", None) or ThreatDetector.load()
    result = await run_in_threadpool(detector.predict, payload)
    return result


@router.post("/extract-link")
async def inspect_url(payload: LinkExtractRequest) -> Dict[str, Any]:
    """
    Inspects a raw URL, attempts OpenGraph extraction,
    and falls back to lexical enricher if captcha-blocked or down.
    """
    return await run_in_threadpool(extract_metadata_from_url, payload.url)


@router.get("/scans/history")
async def list_recent_scans(limit: int = 20) -> Dict[str, Any]:
    records = await run_in_threadpool(get_scan_history, limit)
    return {"total": len(records), "records": records}


@router.get("/scans/{scan_id}")
async def get_single_scan(scan_id: str) -> Dict[str, Any]:
    record = await run_in_threadpool(get_scan_by_id, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
    return record


@router.post("/profile/posts", response_model=List[PostEvidence])
async def get_recent_posts(payload: PostExtractRequest) -> List[PostEvidence]:
    """
    Extracts recent posts from a profile, including OCR-extracted text
    from post graphics and audio/music track metadata.
    """
    handle = payload.handle or (payload.url or "user")
    return await run_in_threadpool(
        extract_recent_posts,
        handle=handle,
        platform=payload.platform,
        suspect_url=payload.url,
        limit=payload.limit,
    )


@router.post("/osint/footprint", response_model=List[PlatformPresence])
async def check_internet_footprint(payload: OsintFootprintRequest) -> List[PlatformPresence]:
    """
    Surfs the web across social platforms, code repos, and domain registries
    to uncover cross-platform identity footprints and clone campaigns.
    """
    return await run_in_threadpool(
        search_internet_footprint,
        query=payload.query,
        protected_brand=payload.protected_brand or "ByteXL",
    )


@router.post("/scan/app-store", response_model=AppStoreScanResponse)
async def scan_app_store(payload: AppStoreScanRequest) -> AppStoreScanResponse:
    """
    Executes deep 5-pillar App Store Forensics on mobile apps:
    - AI-generated synthetic bot review identification
    - Temporal burst astroturfing detection (< 48hr coordinate bursts)
    - Publisher cross-store reverse portfolio OSINT & rogue developer rings
    - Bimodal U-shaped rating polarization split
    - Cold-start anomaly with hyperbolic praise detection
    """
    return await run_in_threadpool(scan_mobile_app_asset, payload)
