import os

# Settings are read at import time; provide safe throwaway values for tests.
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/asm_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-0123456789abcdef0123456789")
