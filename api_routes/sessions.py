from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import get_db
from database.repositories import create_or_update_session, get_session_by_id, lock_session_by_id
from services.auth_service import get_current_user
from database.models import User

router = APIRouter(prefix="/api/sessions", tags=["Sessions"])

class SessionCreateRequest(BaseModel):
    document_id: Optional[str] = None

class SessionLockRequest(BaseModel):
    reason: str = "Behavioral Security Event"

class SessionResponse(BaseModel):
    id: str
    user_id: int
    document_id: Optional[str] = None
    session_status: str
    created_at: str
    lock_reason: Optional[str] = None

@router.post("", response_model=SessionResponse)
def create_session(
    request: SessionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sess = create_or_update_session(db, user_id=current_user.id, document_id=request.document_id)
    return SessionResponse(
        id=sess.id,
        user_id=sess.user_id,
        document_id=sess.document_id,
        session_status=sess.session_status,
        created_at=sess.created_at.isoformat(),
        lock_reason=sess.lock_reason
    )

@router.get("/{session_id}", response_model=SessionResponse)
def get_session_status(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sess = get_session_by_id(db, session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
    return SessionResponse(
        id=sess.id,
        user_id=sess.user_id,
        document_id=sess.document_id,
        session_status=sess.session_status,
        created_at=sess.created_at.isoformat(),
        lock_reason=sess.lock_reason
    )

@router.post("/{session_id}/lock", response_model=SessionResponse)
def lock_session(
    session_id: str,
    request: SessionLockRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sess = lock_session_by_id(db, session_id, reason=request.reason)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
    return SessionResponse(
        id=sess.id,
        user_id=sess.user_id,
        document_id=sess.document_id,
        session_status=sess.session_status,
        created_at=sess.created_at.isoformat(),
        lock_reason=sess.lock_reason
    )
