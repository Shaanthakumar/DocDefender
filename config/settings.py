import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# Security & Secret Management
SECRET_KEY = os.getenv("SECRET_KEY", "docsdefender_dev_secret_key_32bytes_default!!")
AES_MASTER_KEY_HEX = os.getenv("AES_MASTER_KEY", "4a6f9c2d7e1b3f8a5c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e0f2a4b")
try:
    AES_MASTER_KEY = bytes.fromhex(AES_MASTER_KEY_HEX)
except ValueError:
    AES_MASTER_KEY = AES_MASTER_KEY_HEX.encode('utf-8').ljust(32, b'\0')[:32]

# Database Setup
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/storage/dlp_audit.db")

# Storage Paths
STORAGE_DIR = BASE_DIR / "storage"
PROTECTED_DIR = STORAGE_DIR / "protected"
EVIDENCE_DIR = STORAGE_DIR / "evidence"
TEMP_DIR = STORAGE_DIR / "temporary"
CONFIDENTIAL_DIR = Path(os.getenv("CONFIDENTIAL_DIR", str(STORAGE_DIR / "confidential")))
REPORTS_DIR = BASE_DIR / "reports"

# Ensure essential directories exist
for path in [STORAGE_DIR, PROTECTED_DIR, EVIDENCE_DIR, TEMP_DIR, CONFIDENTIAL_DIR, REPORTS_DIR]:
    path.mkdir(parents=True, exist_ok=True)

# Authentication & JWT Settings
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

# Computer Vision Settings
YOLO_MODEL_PATH = os.getenv("YOLO_MODEL_PATH", "yolov8n.pt")
YOLO_CONF_THRESHOLD = float(os.getenv("YOLO_CONF_THRESHOLD", "0.70"))
CAMERA_GUARD_CONF_THRESHOLD = float(os.getenv("CAMERA_GUARD_CONF_THRESHOLD", "0.70"))
PHONE_DETECTION_PERSISTENCE_SEC = float(os.getenv("PHONE_DETECTION_PERSISTENCE_SEC", "2.0"))

# Monitoring Settings
NETWORK_SIMULATION_MODE = os.getenv("NETWORK_SIMULATION_MODE", "True").lower() in ("true", "1", "t")
FS_SIMULATION_MODE = os.getenv("FS_SIMULATION_MODE", "False").lower() in ("true", "1", "t")
MAX_EXFILTRATION_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
