from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from database.database import get_db
from database.repositories import list_users, get_user_by_email, create_user, update_user_status, get_user_by_id
from services.auth_service import require_role, hash_password, get_current_user
from services.audit_logger import AuditLogger
from database.models import User

router = APIRouter(prefix="/api/users", tags=["Users"])

class UserCreateRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "employee"

class UserUpdateRequest(BaseModel):
    is_active: bool

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    is_active: bool

@router.get("", response_model=List[UserResponse])
def get_users(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("administrator"))
):
    users = list_users(db)
    return [
        UserResponse(id=u.id, name=u.name, email=u.email, role=u.role, is_active=u.is_active)
        for u in users
    ]

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_new_user(
    request: UserCreateRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("administrator"))
):
    existing = get_user_by_email(db, request.email)
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists.")
    
    hashed = hash_password(request.password)
    user = create_user(db, name=request.name, email=request.email, password_hash=hashed, role=request.role)
    AuditLogger.log_action("CREATE_USER", user_id=admin_user.id, metadata={"new_user_id": user.id, "email": user.email}, db=db)
    
    return UserResponse(id=user.id, name=user.name, email=user.email, role=user.role, is_active=user.is_active)

@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    request: UserUpdateRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("administrator"))
):
    user = update_user_status(db, user_id=user_id, is_active=request.is_active)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    AuditLogger.log_action("UPDATE_USER_STATUS", user_id=admin_user.id, metadata={"target_user_id": user.id, "is_active": user.is_active}, db=db)
    return UserResponse(id=user.id, name=user.name, email=user.email, role=user.role, is_active=user.is_active)
