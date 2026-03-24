from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "sqlite:///./reconscan.db"
    redis_url: str = "redis://localhost:6379"
    use_arq_queue: bool = True
    allowed_hosts: str = "localhost,127.0.0.1"
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:5173,http://localhost:8000"
    allow_byo_api_key: bool = False
    openrouter_api_key: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    rate_limit_per_minute: int = 10
    rate_limit_per_day: int = 200

    class Config:
        env_file = ".env"

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

settings = Settings()
