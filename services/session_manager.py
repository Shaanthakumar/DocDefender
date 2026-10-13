from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from database.models import UserSession
from database.repositories import (
    create_or_update_session,
    lock_session_by_id,
    lock_user_active_sessions,
    get_session_by_id,
    list_locked_sessions,
    unlock_user_sessions
)
from services.audit_logger import AuditLogger

def register_viewing_session(db: Session, user_id: int, doc_id: Optional[str] = None) -> UserSession:
    """Register a new active document viewing session."""
    sess = create_or_update_session(db, user_id=user_id, document_id=doc_id)
    AuditLogger.log_action("SESSION_STARTED", user_id=user_id, document_id=doc_id, db=db)
    return sess

def lock_active_user_sessions(db: Session, user_id: int, reason: str = "Mobile Phone Detected by Camera Guard") -> List[UserSession]:
    """Lock all active viewing sessions for a specific user."""
    locked_sessions = lock_user_active_sessions(db, user_id=user_id, reason=reason)
    if locked_sessions:
        AuditLogger.log_alert(
            event_type="SESSION_LOCKED",
            description=f"User session locked automatically. Reason: {reason}",
            severity="CRITICAL",
            user_id=user_id,
            document_id=locked_sessions[0].document_id if locked_sessions else None,
            metadata={"reason": reason, "locked_count": len(locked_sessions)},
            db=db
        )
    return locked_sessions

def unlock_session(db: Session, session_id: str, admin_user_id: int) -> Optional[UserSession]:
    """Unlock a locked session (Admin privilege required)."""
    sess = get_session_by_id(db, session_id)
    if sess:
        sess.session_status = "active"
        sess.locked_at = None
        sess.lock_reason = None
        db.commit()
        db.refresh(sess)
        AuditLogger.log_action("SESSION_UNLOCKED", user_id=admin_user_id, metadata={"target_session_id": session_id}, db=db)
    return sess

def unlock_user_all_sessions(db: Session, target_user_id: int, admin_user_id: int) -> List[UserSession]:
    """Unlock all locked document sessions for a user (Admin privilege)."""
    unlocked = unlock_user_sessions(db, target_user_id)
    if unlocked:
        AuditLogger.log_action(
            "SESSIONS_UNLOCKED_FOR_USER",
            user_id=admin_user_id,
            metadata={"target_user_id": target_user_id, "unlocked_count": len(unlocked)},
            db=db
        )
    return unlocked

def get_active_locked_sessions(db: Session) -> List[UserSession]:
    """List all currently locked sessions."""
    return list_locked_sessions(db)

def check_user_session_locked(db: Session, user_id: int, doc_id: Optional[str] = None) -> bool:
    """Check whether an active viewing session is locked for user and document."""
    query = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.session_status == "locked"
    )
    if doc_id:
        query = query.filter(UserSession.document_id == doc_id)
    return query.first() is not None
