"""
AegisMark AI — Production FastAPI Service
HacXLerate 2026 | Challenge 03: Digital Risk Protection Platform (Kampus.vc)
"""

from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .models.detector import ThreatDetector
from .api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load 3-Pillar ThreatDetector & FAISS 512-d vector index once on startup
    app.state.detector = ThreatDetector.load()
    yield
    app.state.detector = None


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Autonomous Multi-Modal Brand Impersonation, Scam Account & Rogue App Detection Engine "
        "(Pillar 1: FAISS/CLIP Vision | Pillar 2: NLP Scam Intent | Pillar 3: Typosquatting Heuristics)"
    ),
    version=settings.VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount under /api/v1, /api, and root so any frontend base URL convention works out of the box
app.include_router(api_router, prefix="/api/v1")
app.include_router(api_router, prefix="/api", include_in_schema=False)
app.include_router(api_router, prefix="", include_in_schema=False)


@app.get("/")
async def root_status() -> Dict[str, Any]:
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "docs_url": "/docs",
        "endpoints": {
            "health": "/api/v1/health",
            "brands": "/api/v1/brands",
            "presets": "/api/v1/presets",
            "scan": "POST /api/v1/scan",
            "takedown": "POST /api/v1/takedown",
            "takedown_pdf": "POST /api/v1/takedown/pdf",
        },
    }
