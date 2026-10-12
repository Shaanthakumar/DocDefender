from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import get_db
from database.repositories import query_audit_logs
from services.auth_service import require_role
from database.models import User

router = APIRouter(prefix="/api/audit-logs", tags=["Audit Logs"])

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    document_id: Optional[str] = None
    action: str
    timestamp: str
    ip_address: Optional[str] = None
    status: str
    severity: str
    metadata_json: Optional[str] = None

@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("administrator", "investigator"))
):
    logs = query_audit_logs(db, limit=limit, offset=offset)
    return [
        AuditLogResponse(
            id=log.id,
            user_id=log.user_id,
            document_id=log.document_id,
            action=log.action,
            timestamp=log.timestamp.isoformat(),
            ip_address=log.ip_address,
            status=log.status,
            severity=log.severity,
            metadata_json=log.metadata_json
        )
        for log in logs
    ]
