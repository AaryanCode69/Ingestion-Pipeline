"""
Configuration management for the ingestion service.
Uses environment variables with sensible defaults.
"""
import os
from typing import Optional
from pydantic import BaseSettings

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Member B forwarding settings
    member_b_url: str = "https://35a161c372d1.ngrok-free.app/events"  # Updated Member B endpoint
    max_forward_retries: int = 3
    forward_retry_backoff: float = 1.0  # Base for exponential backoff
    
    # Continuous monitoring settings (DISABLED - now using webhooks)
    dummy_backend_url: str = "http://localhost:9000"
    poll_interval_seconds: float = 2.0
    enable_continuous_polling: bool = False  # DISABLED: Now using webhooks instead of polling
    enable_prometheus_polling: bool = False  # Future feature
    
    # Detection settings
    min_detection_score: float = 0.3  # Minimum score to forward to Member B
    max_payload_length: int = 2000    # Max chars to include in forwarded payload
    
    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False
    
    # Logging
    log_level: str = "INFO"
    
    # Service info
    service_name: str = "ingestion"
    service_version: str = "2.0.0"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

# Global settings instance
settings = Settings()

def get_settings() -> Settings:
    """Get application settings."""
    return settings