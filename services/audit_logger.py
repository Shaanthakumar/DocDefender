from typing import Optional, Dict
from sqlalchemy.orm import Session
from database.repositories import log_audit_event, log_security_event
from database.database import SessionLocal

class AuditLogger:
    """Centralized Audit and Security Event Logger."""

    @staticmethod
    def log_action(
        action: str,
        user_id: Optional[int] = None,
        document_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        status: str = "SUCCESS",
        severity: str = "INFO",
        metadata: Optional[dict] = None,
        db: Optional[Session] = None
    ):
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True
        try:
            log_audit_event(
                db=db,
                action=action,
                user_id=user_id,
                document_id=document_id,
                ip_address=ip_address,
                status=status,
                severity=severity,
                metadata=metadata
            )
        finally:
            if should_close:
                db.close()

    @staticmethod
    def log_alert(
        event_type: str,
        description: str,
        severity: str = "HIGH",
        user_id: Optional[int] = None,
        document_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        db: Optional[Session] = None
    ):
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True
        try:
            log_security_event(
                db=db,
                event_type=event_type,
                description=description,
                severity=severity,
                user_id=user_id,
                document_id=document_id,
                metadata=metadata
            )
            # Also log to audit logs
            log_audit_event(
                db=db,
                action=f"SECURITY_ALERT:{event_type}",
                user_id=user_id,
                document_id=document_id,
                status="WARNING" if severity != "CRITICAL" else "FAILURE",
                severity=severity,
                metadata={"description": description, **(metadata or {})}
            )
        finally:
            if should_close:
                db.close()
