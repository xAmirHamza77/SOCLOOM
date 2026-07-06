from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openai_api_key: str = ""
    anthropic_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"
    aegis_llm_provider: str = "openai"
    aegis_llm_model: str = "gpt-4o-mini"

    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""

    aegis_skills_path: str = str(
        ROOT_DIR.parent / "Downloads" / "Anthropic-Cybersecurity-Skills-main"
    )
    aegis_database_url: str = f"sqlite:///{ROOT_DIR / 'data' / 'aegis.db'}"
    aegis_api_host: str = "0.0.0.0"
    aegis_api_port: int = 8000
    aegis_cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    aegis_ml_confidence_threshold: int = 55
    aegis_ai_confidence_threshold: int = 60

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.aegis_cors_origins.split(",") if o.strip()]

    @property
    def skills_index_path(self) -> Path:
        return Path(self.aegis_skills_path) / "index.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()