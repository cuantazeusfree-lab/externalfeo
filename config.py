import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    database_path: str = os.getenv("DATABASE_PATH", "./external.db")
    license_days: int = int(os.getenv("LICENSE_DAYS", "365"))
    challenge_ttl_seconds: int = int(os.getenv("CHALLENGE_TTL_SECONDS", "120"))
    allow_reactivation: bool = os.getenv("ALLOW_REACTIVATION", "true").lower() == "true"

settings = Settings()
