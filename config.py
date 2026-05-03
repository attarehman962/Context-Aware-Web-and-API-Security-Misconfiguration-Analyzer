"""Central configuration for CAWASMA."""

from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-this")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() == "true"
    TESTING = os.getenv("FLASK_TESTING", "False").lower() == "true"

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'cawasma.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Celery / Redis
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", os.getenv("REDIS_URL", "redis://localhost:6379/1"))

    # Scanner controls
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "30"))
    MAX_CRAWL_DEPTH = int(os.getenv("MAX_CRAWL_DEPTH", "2"))
    MAX_ENDPOINTS = int(os.getenv("MAX_ENDPOINTS", "100"))
    RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "20"))

    # LLM keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    NLP_MODEL_NAME = os.getenv("NLP_MODEL_NAME", "all-MiniLM-L6-v2")
    REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", str(BASE_DIR / "reports"))
    TARGET_WORDLIST_SIZE = int(os.getenv("TARGET_WORDLIST_SIZE", "200"))


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


