import os
import time
from typing import Dict, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from sqlalchemy.orm import Session

from config.settings import CONFIDENTIAL_DIR
from services.audit_logger import AuditLogger
from database.database import SessionLocal

class ConfidentialFolderHandler(FileSystemEventHandler):
    """Watchdog event handler for monitoring confidential directory activity."""

    def __init__(self):
        super().__init__()
        self.last_event_time: Dict[str, float] = {}

    def _log_event(self, event_type: str, src_path: str, dest_path: Optional[str] = None):
        now = time.time()
        key = f"{event_type}:{src_path}"
        if now - self.last_event_time.get(key, 0) < 1.0:
            return  # Debounce duplicate events within 1s
        self.last_event_time[key] = now

        filename = os.path.basename(src_path)
        desc = f"Confidential directory activity: [{event_type}] on '{filename}'"
        if dest_path:
            desc += f" -> '{os.path.basename(dest_path)}'"

        db = SessionLocal()
        try:
            AuditLogger.log_alert(
                event_type="FS_UNAUTHORIZED_ACCESS",
                description=desc,
                severity="HIGH",
                metadata={"action": event_type, "src_path": src_path, "dest_path": dest_path},
                db=db
            )
        finally:
            db.close()

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._log_event("CREATED", event.src_path)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._log_event("MODIFIED", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self._log_event("MOVED", event.src_path, getattr(event, "dest_path", None))

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self._log_event("DELETED", event.src_path)

class FilesystemMonitorService:
    """Service for managing Watchdog observer lifecycle."""

    def __init__(self, watch_dir: str = str(CONFIDENTIAL_DIR)):
        self.watch_dir = watch_dir
        self.observer: Optional[Observer] = None
        self.handler = ConfidentialFolderHandler()

    def start(self):
        """Start directory observer."""
        os.makedirs(self.watch_dir, exist_ok=True)
        if self.observer is not None and self.observer.is_alive():
            return
        self.observer = Observer()
        self.observer.schedule(self.handler, path=self.watch_dir, recursive=False)
        self.observer.start()

    def stop(self):
        """Stop directory observer."""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()

_global_fs_monitor: Optional[FilesystemMonitorService] = None

def get_filesystem_monitor() -> FilesystemMonitorService:
    """Get or initialize global Watchdog filesystem monitor singleton."""
    global _global_fs_monitor
    if _global_fs_monitor is None:
        _global_fs_monitor = FilesystemMonitorService()
        _global_fs_monitor.start()
    return _global_fs_monitor

def perform_real_confidential_file_op(action: str, filename: str, content: bytes = b"CONFIDENTIAL DATA PAYLOAD") -> Dict[str, Any]:
    """Perform a physical file system operation inside the confidential storage folder.
    This triggers real kernel filesystem events picked up by Watchdog."""
    watch_dir = str(CONFIDENTIAL_DIR)
    os.makedirs(watch_dir, exist_ok=True)
    filepath = os.path.join(watch_dir, filename)

    if action == "CREATE":
        with open(filepath, "wb") as f:
            f.write(content)
        result = f"Physically created file '{filename}' ({len(content)} bytes) in {watch_dir}"
    elif action == "MODIFY":
        with open(filepath, "ab") as f:
            f.write(b"\n[APPENDED UNAUTHORIZED MODIFICATION DATA]\n")
        result = f"Physically appended modifications to '{filename}' in {watch_dir}"
    elif action == "DELETE":
        if os.path.exists(filepath):
            os.remove(filepath)
            result = f"Physically removed file '{filename}' from {watch_dir}"
        else:
            result = f"File '{filename}' not found to delete, created then deleted."
            with open(filepath, "wb") as f:
                f.write(b"temp")
            os.remove(filepath)
    else:
        result = f"Unknown action {action}"

    return {"status": "SUCCESS", "action": action, "filepath": filepath, "details": result}

def simulate_filesystem_event(
    db: Session,
    user_id: int,
    action: str = "UNAUTHORIZED_COPY",
    target_filename: str = "Q4_Financial_Strategy.pdf"
) -> Dict[str, Any]:
    """Simulate a confidential folder security event for demonstration."""
    desc = f"SIMULATED FS EVENT: Suspicious [{action}] operation detected on confidential file '{target_filename}'."

    AuditLogger.log_alert(
        event_type="FS_UNAUTHORIZED_ACCESS",
        description=desc,
        severity="HIGH",
        user_id=user_id,
        metadata={"action": action, "filename": target_filename, "simulated": True},
        db=db
    )

    return {
        "status": "ALERT_TRIGGERED",
        "event_type": "FS_UNAUTHORIZED_ACCESS",
        "action": action,
        "filename": target_filename,
        "severity": "HIGH"
    }
