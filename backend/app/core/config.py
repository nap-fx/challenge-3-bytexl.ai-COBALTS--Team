"""
Core Application Settings & Constants for AegisMark AI Backend
"""

from typing import List


class Settings:
    PROJECT_NAME: str = "AegisMark AI — Digital Risk Protection Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    EMBEDDING_DIM: int = 512

    # Unified Risk Scoring Weights (Pillar 1 + Pillar 2 + Pillar 3 = 1.00)
    WEIGHT_VISION: float = 0.40
    WEIGHT_NLP: float = 0.35
    WEIGHT_HEURISTICS: float = 0.25

    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4321",
        "http://127.0.0.1:4321",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "*",
    ]


settings = Settings()
