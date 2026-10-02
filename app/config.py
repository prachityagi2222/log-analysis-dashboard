import os
import sys
from pathlib import Path

# Project paths
if getattr(sys, "frozen", False):
    # Running inside PyInstaller standalone bundle
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    # Keep writable database and uploads in APPDATA or local data directory
    appdata = os.environ.get("APPDATA")
    if appdata:
        DATA_DIR = Path(appdata) / "LogDashboard" / "data"
    else:
        DATA_DIR = Path(sys.executable).parent / "data"
    BASE_DIR = BUNDLE_DIR
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
    BUNDLE_DIR = BASE_DIR
    DATA_DIR = BASE_DIR / "data"

STATIC_DIR = BUNDLE_DIR / "app" / "static"
SAMPLE_DIR = BUNDLE_DIR / "sample_logs"

RAW_DIR = DATA_DIR / "raw"
PARSED_DIR = DATA_DIR / "parsed"

# Ensure data directories exist
RAW_DIR.mkdir(parents=True, exist_ok=True)
PARSED_DIR.mkdir(parents=True, exist_ok=True)

# Database
DB_PATH = DATA_DIR / "log_dashboard.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")

# Ollama settings
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "2.0")) # Quick failover to mock mode
