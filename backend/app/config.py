from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/sih.db"
    raw_email_dir: str = "./data/raw_emails"
    cors_origins: str = "http://localhost:5173"

    # Optional enrichment — the pipeline works fully without any of these.
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    # Enables LLMContentAnalyzer (real AI content analysis via Claude) in place of
    # the local keyword heuristic — see app/nlp/llm_analyzer.py.
    anthropic_api_key: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def raw_email_path(self) -> Path:
        path = Path(self.raw_email_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()
