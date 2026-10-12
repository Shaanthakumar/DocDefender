from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import get_db
from database.repositories import list_leak_reports
from services.auth_service import require_role
from database.models import User

router = APIRouter(prefix="/api/forensics", tags=["Forensics"])

class LeakReportResponse(BaseModel):
    id: int
    document_id: Optional[str] = None
    leaked_file_path: str
    evidence_hash: str
    extracted_user_id: Optional[int] = None
    confidence_score: Optional[float] = 1.0
    extraction_status: str
    investigation_status: str
    created_at: str

@router.get("/reports", response_model=List[LeakReportResponse])
def get_forensic_reports(
    db: Session = Depends(get_db),
    user: User = Depends(require_role("administrator", "investigator"))
):
    reports = list_leak_reports(db)
    return [
        LeakReportResponse(
            id=r.id,
            document_id=r.document_id,
            leaked_file_path=r.leaked_file_path,
            evidence_hash=r.evidence_hash,
            extracted_user_id=r.extracted_user_id,
            confidence_score=r.confidence_score,
            extraction_status=r.extraction_status,
            investigation_status=r.investigation_status,
            created_at=r.created_at.isoformat()
        )
        for r in reports
    ]
