from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import get_db
from database.repositories import list_security_events
from services.auth_service import require_role
from database.models import User

router = APIRouter(prefix="/api/monitoring", tags=["Monitoring"])

class SecurityEventResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    document_id: Optional[str] = None
    event_type: str
    severity: str
    description: str
    timestamp: str
    status: str

@router.get("/events", response_model=List[SecurityEventResponse])
def get_security_events(
    limit: int = 50,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("administrator", "investigator"))
):
    events = list_security_events(db, limit=limit)
    return [
        SecurityEventResponse(
            id=e.id,
            user_id=e.user_id,
            document_id=e.document_id,
            event_type=e.event_type,
            severity=e.severity,
            description=e.description,
            timestamp=e.timestamp.isoformat(),
            status=e.status
        )
        for e in events
    ]
