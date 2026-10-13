from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Request, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from ....schemas import ScanRequest, ScanResponse
from ....models.detector import ThreatDetector
from ....link_extractor import extract_metadata_from_url
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
