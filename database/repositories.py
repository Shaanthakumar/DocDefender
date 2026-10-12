import json
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from database.models import User, Document, DocumentPermission, AuditLog, LeakReport, SecurityEvent, UserSession

# User Repository
def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, name: str, email: str, password_hash: str, role: str = "employee") -> User:
    user = User(name=name, email=email, password_hash=password_hash, role=role.lower())
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def list_users(db: Session, limit: int = 100, offset: int = 0) -> List[User]:
    return db.query(User).order_by(User.id.asc()).offset(offset).limit(limit).all()

def update_user_status(db: Session, user_id: int, is_active: bool) -> Optional[User]:
    user = get_user_by_id(db, user_id)
    if user:
        user.is_active = is_active
        db.commit()
        db.refresh(user)
    return user

# Document Repository
def create_document(
    db: Session,
    doc_id: str,
    name: str,
    description: str,
    classification: str,
    original_hash: str,
    protected_file_path: str,
    owner_id: int,
    processing_status: str = "processed"
) -> Document:
    doc = Document(
        id=doc_id,
        name=name,
        description=description,
        classification=classification,
        original_hash=original_hash,
        protected_file_path=protected_file_path,
        owner_id=owner_id,
        processing_status=processing_status
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return doc

def get_document_by_id(db: Session, doc_id: str) -> Optional[Document]:
    return db.query(Document).filter(Document.id == doc_id).first()

def list_documents(db: Session) -> List[Document]:
    return db.query(Document).order_by(Document.upload_date.desc()).all()

def list_documents_for_user(db: Session, user_id: int) -> List[Document]:
    # Owner or explicitly permitted
    user = get_user_by_id(db, user_id)
    if user and user.role == "administrator":
        return list_documents(db)
    
    permitted_doc_ids = db.query(DocumentPermission.document_id).filter(DocumentPermission.user_id == user_id).subquery()
    return db.query(Document).filter(
        (Document.owner_id == user_id) | (Document.id.in_(permitted_doc_ids))
    ).order_by(Document.upload_date.desc()).all()

def grant_document_permission(db: Session, doc_id: str, user_id: int, granted_by: int) -> DocumentPermission:
    existing = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == user_id
    ).first()
    if existing:
        return existing
    perm = DocumentPermission(document_id=doc_id, user_id=user_id, granted_by=granted_by)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm

def has_document_permission(db: Session, doc_id: str, user_id: int) -> bool:
    user = get_user_by_id(db, user_id)
    if user and user.role in ("administrator", "investigator"):
        return True
    doc = get_document_by_id(db, doc_id)
    if doc and doc.owner_id == user_id:
        return True
    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == user_id
    ).first()
    return perm is not None

# Audit Log Repository
def log_audit_event(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    document_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    status: str = "SUCCESS",
    severity: str = "INFO",
    metadata: Optional[dict] = None
) -> AuditLog:
    meta_str = json.dumps(metadata) if metadata else None
    audit = AuditLog(
        user_id=user_id,
        document_id=document_id,
        action=action,
        ip_address=ip_address,
        status=status,
        severity=severity,
        metadata_json=meta_str
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return audit

def query_audit_logs(db: Session, limit: int = 100, offset: int = 0) -> List[AuditLog]:
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

# Security Event Repository
def log_security_event(
    db: Session,
    event_type: str,
    description: str,
    severity: str = "HIGH",
    user_id: Optional[int] = None,
    document_id: Optional[str] = None,
    metadata: Optional[dict] = None
) -> SecurityEvent:
    meta_str = json.dumps(metadata) if metadata else None
    sec_event = SecurityEvent(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        document_id=document_id,
        metadata_json=meta_str
    )
    db.add(sec_event)
    db.commit()
    db.refresh(sec_event)
    return sec_event

def list_security_events(db: Session, limit: int = 50) -> List[SecurityEvent]:
    return db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

# User Session Repository
def create_or_update_session(db: Session, user_id: int, document_id: Optional[str] = None) -> UserSession:
    session = UserSession(
        user_id=user_id,
        document_id=document_id,
        session_status="active",
        created_at=datetime.utcnow(),
        last_activity_at=datetime.utcnow()
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session

def lock_session_by_id(db: Session, session_id: str, reason: str = "Behavioral Security Event") -> Optional[UserSession]:
    sess = db.query(UserSession).filter(UserSession.id == session_id).first()
    if sess:
        sess.session_status = "locked"
        sess.locked_at = datetime.utcnow()
        sess.lock_reason = reason
        db.commit()
        db.refresh(sess)
    return sess

def lock_user_active_sessions(db: Session, user_id: int, reason: str = "Behavioral Phone Detection") -> List[UserSession]:
    sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.session_status == "active"
    ).all()
    now = datetime.utcnow()
    for s in sessions:
        s.session_status = "locked"
        s.locked_at = now
        s.lock_reason = reason
    db.commit()
    return sessions

def get_session_by_id(db: Session, session_id: str) -> Optional[UserSession]:
    return db.query(UserSession).filter(UserSession.id == session_id).first()

# Leak Report Repository
def create_leak_report(
    db: Session,
    leaked_file_path: str,
    evidence_hash: str,
    extraction_status: str,
    document_id: Optional[str] = None,
    extracted_user_id: Optional[int] = None,
    confidence_score: float = 1.0,
    metadata: Optional[dict] = None
) -> LeakReport:
    meta_str = json.dumps(metadata) if metadata else None
    report = LeakReport(
        document_id=document_id,
        leaked_file_path=leaked_file_path,
        evidence_hash=evidence_hash,
        extracted_user_id=extracted_user_id,
        confidence_score=confidence_score,
        extraction_status=extraction_status,
        report_metadata_json=meta_str
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report

def list_leak_reports(db: Session) -> List[LeakReport]:
    return db.query(LeakReport).order_by(LeakReport.created_at.desc()).all()
