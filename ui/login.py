import streamlit as st
from database.database import SessionLocal
from database.repositories import get_user_by_email
from services.auth_service import verify_password, create_access_token
from services.audit_logger import AuditLogger

def render_login_page():
    """Render DocsDefender login page."""
    st.markdown("<h2 style='text-align: center; color: #58a6ff;'>🛡️ DocsDefender Login</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #8b949e;'>Enterprise Document Leak Prevention & Forensic Tracing System</p>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        if st.session_state.get("camera_threat_detected"):
            threat_uid = st.session_state.get("threat_user_id", "Unknown")
            threat_uname = st.session_state.get("threat_user_name", "Employee")
            threat_reason = st.session_state.get("threat_reason", "Mobile phone detected in camera feed.")
            st.error(
                f"🚨 **SECURITY ALERT: IMMEDIATE FORCED LOGOUT TRIGGERED!**\n\n"
                f"**Employee**: {threat_uname} (ID: `{threat_uid}`)\n\n"
                f"**Violation**: {threat_reason}\n\n"
                f"This incident and employee ID have been recorded in the Central Audit Trail."
            )
        with st.form("login_form"):
            email = st.text_input("Email Address", value="admin@docsdefender.local")
            password = st.text_input("Password", type="password", value="AdminSecure2026!")
            submit = st.form_submit_button("Log In", use_container_width=True)

            if submit:
                db = SessionLocal()
                try:
                    user = get_user_by_email(db, email.strip())
                    if user and verify_password(password, user.password_hash):
                        if not user.is_active:
                            st.error("Account is disabled. Contact Administrator.")
                            AuditLogger.log_action("LOGIN_FAILED_DISABLED", user_id=user.id, status="FAILURE", db=db)
                        else:
                            token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role})
                            st.session_state["authenticated"] = True
                            st.session_state["camera_threat_detected"] = False
                            st.session_state.pop("threat_user_id", None)
                            st.session_state.pop("threat_user_name", None)
                            st.session_state.pop("threat_reason", None)
                            st.session_state["user"] = {
                                "id": user.id,
                                "name": user.name,
                                "email": user.email,
                                "role": user.role
                            }
                            st.session_state["token"] = token
                            AuditLogger.log_action("USER_LOGIN_UI", user_id=user.id, status="SUCCESS", db=db)
                            st.success(f"Welcome back, {user.name}!")
                            st.rerun()
                    else:
                        st.error("Invalid email or password.")
                        AuditLogger.log_action("LOGIN_FAILED_UI", metadata={"email": email}, status="FAILURE", db=db)
                finally:
                    db.close()

        st.markdown("---")
        st.caption("Quick Demo Credentials:")
        st.caption("- **Admin**: `admin@docsdefender.local` / `AdminSecure2026!`")
        st.caption("- **Employee**: `employee1@docsdefender.local` / `EmployeePass2026!`")
        st.caption("- **Investigator**: `investigator@docsdefender.local` / `InvestigatorPass2026!`")
