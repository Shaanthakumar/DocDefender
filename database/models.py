import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, Text
from sqlalchemy.orm import relationship
from database.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="employee")  # administrator, employee, investigator
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    documents = relationship("Document", back_populates="owner", foreign_keys="Document.owner_id")
    permissions = relationship("DocumentPermission", back_populates="user", foreign_keys="DocumentPermission.user_id")

class Document(Base):
    __tablename__ = "documents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    classification = Column(String(50), nullable=False, default="Confidential")
    original_hash = Column(String(64), nullable=False, index=True)
    protected_file_path = Column(String(500), nullable=False)
    upload_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    processing_status = Column(String(20), nullable=False, default="processed")  # pending, processed, failed

    owner = relationship("User", back_populates="documents", foreign_keys=[owner_id])
    permissions = relationship("DocumentPermission", back_populates="document", cascade="all, delete-orphan")

class DocumentPermission(Base):
    __tablename__ = "document_permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    document = relationship("Document", back_populates="permissions")
    user = relationship("User", back_populates="permissions", foreign_keys=[user_id])

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    document_id = Column(String(36), ForeignKey("documents.id"), nullable=True)
    action = Column(String(100), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(20), nullable=False, default="SUCCESS")  # SUCCESS, FAILURE, WARNING
    severity = Column(String(20), nullable=False, default="INFO")    # INFO, WARNING, CRITICAL
    metadata_json = Column(Text, nullable=True)

class LeakReport(Base):
    __tablename__ = "leak_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    document_id = Column(String(36), ForeignKey("documents.id"), nullable=True)
    leaked_file_path = Column(String(500), nullable=False)
    evidence_hash = Column(String(64), nullable=False)
    extracted_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    confidence_score = Column(Float, nullable=True, default=1.0)
    extraction_status = Column(String(30), nullable=False)  # VERIFIED, UNVERIFIED, FAILED
    investigation_status = Column(String(20), nullable=False, default="OPEN")  # OPEN, CLOSED
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    report_metadata_json = Column(Text, nullable=True)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    document_id = Column(String(36), ForeignKey("documents.id"), nullable=True)
    event_type = Column(String(50), nullable=False)  # PHONE_DETECTED, EXFILTRATION_ATTEMPT, FS_UNAUTHORIZED_ACCESS, SESSION_LOCKED
    severity = Column(String(20), nullable=False, default="HIGH") # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = Column(String(20), nullable=False, default="ACTIVE")  # ACTIVE, RESOLVED, IGNORED
    metadata_json = Column(Text, nullable=True)

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    document_id = Column(String(36), ForeignKey("documents.id"), nullable=True)
    session_status = Column(String(20), nullable=False, default="active")  # active, locked, expired
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    locked_at = Column(DateTime, nullable=True)
    lock_reason = Column(String(255), nullable=True)
