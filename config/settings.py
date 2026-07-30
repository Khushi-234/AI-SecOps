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
    # Database
    # -------------------------
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
