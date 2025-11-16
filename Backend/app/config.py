from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "OSINT Cyber Threat Detection"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "postgresql://postgres:user@locsalhost:5432/threat_detection"
    
    # API
    API_PREFIX: str = "/api"
    
    # CORS
    CORS_ORIGINS: list = ["http://localhost:4200", "http://127.0.0.1:4200"]
    
    # OSINT Settings
    OSINT_UPDATE_INTERVAL: int = 1800  # 30 minutes in seconds
    ALIENVAULT_OTX_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    
    # ML Model
    ML_MODEL_PATH: str = "ml_models/threat_detection_model.pkl"
    
    # Log Collection
    LOG_FETCH_INTERVAL: int = 60  # 1 minute
    MAX_LOG_LINES: int = 1000
    
    # Analysis
    THREAT_DETECTION_THRESHOLD: float = 0.7
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
