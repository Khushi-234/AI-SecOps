from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration for the AI-SecOps Framework.

    Every module should import configuration only from this class.
    """

    # -------------------------
    # LLM
    # -------------------------
    GROQ_API_KEY: str = ""

    MODEL_NAME: str = "llama-3.3-70b-versatile"

    TEMPERATURE: float = 0.2

    MAX_TOKENS: int = 2048

    # -------------------------
    # Application
    # -------------------------
    APP_NAME: str = "AI-SecOps"

    DEBUG: bool = True

    # -------------------------
    # Database (PostgreSQL)
    # -------------------------
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/aisecops_db"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "aisecops_db"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"
    DB_POOL_MIN: int = 1
    DB_POOL_MAX: int = 10
    DB_CONNECT_TIMEOUT: int = 5
    DB_SSLMODE: str = "prefer"
    DATABASE_PATH: str = "data/database.db"

    # -------------------------
    # Reports
    # -------------------------
    REPORT_PATH: str = "reports/"

    # -------------------------
    # Logging
    # -------------------------
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
