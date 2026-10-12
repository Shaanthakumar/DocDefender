import streamlit as st
import pandas as pd
from database.database import SessionLocal
from database.repositories import list_users, get_user_by_email, create_user, update_user_status
from services.auth_service import hash_password
from ui.components import render_header

def render_user_management():
    render_header("User Account & Permission Management", "Manage employee user accounts, assign roles, and toggle access status")

    db = SessionLocal()
    try:
        tab1, tab2 = st.tabs(["👥 User Directory", "➕ Create New Account"])

        with tab1:
            users = list_users(db)
            if users:
                data = []
                for u in users:
                    data.append({
                        "User ID": u.id,
                        "Full Name": u.name,
                        "Email Address": u.email,
                        "Role": u.role.upper(),
                        "Active Status": "Active" if u.is_active else "Disabled",
                        "Created At": u.created_at.strftime("%Y-%m-%d %H:%M")
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)

                st.markdown("---")
                st.markdown("#### Account Status Toggle")
                user_options = {f"{u.name} ({u.email}, ID: {u.id})": u for u in users}
                selected_label = st.selectbox("Select User Account to Toggle Status", list(user_options.keys()))
                target_user = user_options[selected_label]

                col1, col2 = st.columns(2)
                with col1:
                    new_status = st.checkbox("Account Active Status", value=target_user.is_active)
                with col2:
                    if st.button("Update Account Status", use_container_width=True):
                        update_user_status(db, target_user.id, new_status)
                        st.success(f"Status for user {target_user.name} updated to {'Active' if new_status else 'Disabled'}.")
                        st.rerun()

        with tab2:
            st.markdown("#### Create New User Account")
            with st.form("create_user_form", clear_on_submit=True):
                name = st.text_input("Full Name", placeholder="e.g. John Doe")
                email = st.text_input("Email Address", placeholder="e.g. john.doe@docsdefender.local")
                password = st.text_input("Temporary Password", type="password")
                role = st.selectbox("Assigned Role", ["employee", "administrator", "investigator"])

                submit = st.form_submit_button("Create Account", use_container_width=True)
                if submit:
                    if not name or not email or not password:
                        st.error("Please fill in all required fields.")
                    else:
                        existing = get_user_by_email(db, email.strip())
                        if existing:
                            st.error("A user with this email address already exists.")
                        else:
                            pw_hash = hash_password(password)
                            u = create_user(db, name=name, email=email.strip(), password_hash=pw_hash, role=role)
                            st.success(f"Account for '{u.name}' ({u.role}) successfully created! (User ID: {u.id})")
                            st.rerun()
    finally:
        db.close()
