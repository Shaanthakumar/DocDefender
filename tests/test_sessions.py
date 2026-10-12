import pytest
from database.database import init_db, SessionLocal
from database.repositories import create_user, get_user_by_email
from database.models import UserSession
from services.auth_service import hash_password
from services.session_manager import (
    register_viewing_session,
    lock_active_user_sessions,
    unlock_session,
    check_user_session_locked
)

@pytest.fixture(scope="module")
def setup_session_db():
    init_db()
    db = SessionLocal()
    admin = get_user_by_email(db, "admin_sess_test@docsdefender.local")
    if not admin:
        admin = create_user(db, "Sess Admin", "admin_sess_test@docsdefender.local", hash_password("pass"), "administrator")
    emp = get_user_by_email(db, "emp_sess_test@docsdefender.local")
    if not emp:
        emp = create_user(db, "Sess Employee", "emp_sess_test@docsdefender.local", hash_password("pass"), "employee")
    
    # Clean up previous sessions for test user
    db.query(UserSession).filter(UserSession.user_id == emp.id).delete()
    db.commit()

    admin_id, emp_id = admin.id, emp.id
    db.close()
    return admin_id, emp_id

def test_session_registration_and_locking(setup_session_db):
    admin_id, emp_id = setup_session_db
    db = SessionLocal()
    try:
        # Register session
        sess = register_viewing_session(db, user_id=emp_id, doc_id="doc-test-123")
        assert sess.id is not None
        assert sess.session_status == "active"
        assert check_user_session_locked(db, user_id=emp_id, doc_id="doc-test-123") is False

        # Lock session
        locked_list = lock_active_user_sessions(db, user_id=emp_id, reason="Test Phone Lock")
        assert len(locked_list) >= 1
        assert check_user_session_locked(db, user_id=emp_id, doc_id="doc-test-123") is True

        # Unlock session
        unlocked = unlock_session(db, session_id=sess.id, admin_user_id=admin_id)
        assert unlocked.session_status == "active"
        assert check_user_session_locked(db, user_id=emp_id, doc_id="doc-test-123") is False
    finally:
        db.close()
