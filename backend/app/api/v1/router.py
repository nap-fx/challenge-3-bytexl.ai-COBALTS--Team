from fastapi import APIRouter
from .endpoints import health, scan, report

api_router = APIRouter()
api_router.include_router(health.router, tags=["System & Telemetry"])
api_router.include_router(scan.router, tags=["Multi-Modal Threat Detection"])
api_router.include_router(report.router, tags=["Automated Legal Enforcement"])
