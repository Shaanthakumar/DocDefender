from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import get_db
from database.repositories import list_documents_for_user, get_document_by_id, has_document_permission
from services.auth_service import get_current_user
from database.models import User

router = APIRouter(prefix="/api/documents", tags=["Documents"])

class DocumentResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    classification: str
    original_hash: str
    upload_date: str
    owner_id: int
    processing_status: str

@router.get("", response_model=List[DocumentResponse])
def get_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    docs = list_documents_for_user(db, current_user.id)
    return [
        DocumentResponse(
            id=d.id,
            name=d.name,
            description=d.description,
            classification=d.classification,
            original_hash=d.original_hash,
            upload_date=d.upload_date.isoformat(),
            owner_id=d.owner_id,
            processing_status=d.processing_status
        )
        for d in docs
    ]

@router.get("/{document_id}", response_model=DocumentResponse)
def get_document(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not has_document_permission(db, document_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied to this document.")
    doc = get_document_by_id(db, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")
    return DocumentResponse(
        id=doc.id,
        name=doc.name,
        description=doc.description,
        classification=doc.classification,
        original_hash=doc.original_hash,
        upload_date=doc.upload_date.isoformat(),
        owner_id=doc.owner_id,
        processing_status=doc.processing_status
    )

@router.get("/{document_id}/download")
def download_document(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from fastapi.responses import Response
    from services.document_service import generate_watermarked_copy_for_user

    if not has_document_permission(db, document_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied to this document.")
    doc = get_document_by_id(db, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    file_bytes, filename, mime_type = generate_watermarked_copy_for_user(db, document_id, current_user.id)
    return Response(
        content=file_bytes,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
