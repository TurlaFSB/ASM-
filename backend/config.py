from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    database_url: str
    redis_url: str
    app_env: str = "development"
    app_host: str = "0.0.0.0"  # nosec B104
    app_port: int = 8000
    default_rate_limit: int = 10
    scan_timeout: int = 300
    secret_key: str          # no default — must be set via env/.env, app fails to start otherwise
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    cookie_secure: bool = False   # set true when served over HTTPS (production)
    cors_origins: str = "http://localhost:5173,http://localhost:5174,http://localhost:3000"  # comma-separated allow-list, override via env per deployment

    @field_validator("secret_key")
    @classmethod
    def _secret_key_strong(cls, v: str) -> str:
        if len(v) < 32 or v.startswith("CHANGE_ME"):
            raise ValueError(
                "SECRET_KEY must be at least 32 characters and not a placeholder. "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()