"""App configuration."""
from __future__ import annotations
import os

class Config:
    SECRET_KEY = "devshop-prod-secret-2024"
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
