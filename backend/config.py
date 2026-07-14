from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    database_url: str
    redis_url: str
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    default_rate_limit: int = 10
    scan_timeout: int = 300
    secret_key: str = "changeme"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()