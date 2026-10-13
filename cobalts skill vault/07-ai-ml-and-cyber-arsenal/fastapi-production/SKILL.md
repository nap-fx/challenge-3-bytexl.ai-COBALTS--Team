---
name: fastapi-production
description: Production-grade FastAPI patterns for high-performance AI/ML model serving, async endpoints, Pydantic v2 validation, CORS, streaming, and background task orchestration.
---

# FastAPI Production Best Practices

Use this skill when developing Python backend services, especially for serving AI/ML inference endpoints to React/Next.js frontends.

## 1. Project Architecture
```
backend/
├── app/
│   ├── api/
│   │   ├── v1/
│   │   │   ├── endpoints/
│   │   │   │   ├── scan.py
│   │   │   │   ├── report.py
│   │   │   │   └── health.py
│   │   │   └── router.py
│   ├── core/
│   │   ├── config.py       # Pydantic Settings
│   │   └── security.py
│   ├── models/             # ML Models & FAISS indices
│   │   └── detector.py
│   ├── schemas/            # Pydantic v2 schemas
│   │   └── threat.py
│   └── main.py             # FastAPI App instance
├── requirements.txt
└── Dockerfile
```

## 2. Lifespan Events (Load ML Models Once)
Never load models inside endpoint handlers. Use FastAPI's lifespan:
```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.models.detector import ThreatDetector

ml_models = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load model and FAISS index into memory on startup
    ml_models["detector"] = ThreatDetector.load()
    yield
    # Clean up GPU memory on shutdown
    ml_models.clear()

app = FastAPI(title="BrandShield API", lifespan=lifespan)
```

## 3. Pydantic v2 Validation & Response Models
```python
from pydantic import BaseModel, Field
from typing import List, Optional

class ScanRequest(BaseModel):
    brand_name: str = Field(..., min_length=2, max_length=100)
    target_handle: str = Field(..., min_length=2, max_length=100)
    profile_url: Optional[str] = None

class ThreatResult(BaseModel):
    impersonation_score: float = Field(..., ge=0.0, le=100.0)
    visual_match_percent: float
    scam_intent_detected: bool
    risk_level: str # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    flags: List[str]
```

## 4. CORS Setup for Local Dev & Production
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://*.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## 5. Non-blocking Async vs Sync Model Inference
If running heavy CPU/GPU PyTorch inference, run in threadpool so FastAPI event loop doesn't stall:
```python
from fastapi.concurrency import run_in_threadpool

@router.post("/scan", response_model=ThreatResult)
async def scan_profile(request: ScanRequest):
    detector = ml_models["detector"]
    # Offload heavy ML inference to threadpool
    result = await run_in_threadpool(detector.predict, request.target_handle)
    return result
```