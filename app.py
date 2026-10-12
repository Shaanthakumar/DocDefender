import streamlit as st
from ui.styles import get_custom_css
from ui.login import render_login_page
from ui.admin_dashboard import render_admin_dashboard
from ui.document_management import render_document_management
from ui.employee_viewer import render_employee_viewer
from ui.monitoring_dashboard import render_monitoring_dashboard
from ui.forensic_tool import render_forensic_tool
from ui.user_management import render_user_management

# Page Configuration
st.set_page_config(
    page_title="DocsDefender — Enterprise Document Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Custom Dark CSS & Dynamic Overlay Styles
st.markdown(get_custom_css(), unsafe_allow_html=True)

# Authentication State Check
if not st.session_state.get("authenticated", False):
    render_login_page()
else:
    user = st.session_state.get("user", {})
    role = user.get("role", "employee").lower()

    # Sidebar Header
    st.sidebar.markdown(f"### 🛡️ DocsDefender")
    st.sidebar.markdown(f"**Logged in as**: `{user.get('name', 'User')}`")
    st.sidebar.markdown(f"**Role**: `{role.upper()}`")
    st.sidebar.markdown("---")

    # Define Allowed Navigation Pages per Role
    if role == "administrator":
        pages = {
            "📊 Executive Dashboard": render_admin_dashboard,
            "📁 Document Ingestion": render_document_management,
            "👁️ Employee Document Viewer": render_employee_viewer,
            "🔍 Forensic Tracing Tool": render_forensic_tool,
            "🚨 Security Monitoring": render_monitoring_dashboard,
            "👥 User Account Management": render_user_management,
        }
    elif role == "investigator":
        pages = {
            "🔍 Forensic Tracing Tool": render_forensic_tool,
            "👁️ Employee Document Viewer": render_employee_viewer,
            "🚨 Security Monitoring": render_monitoring_dashboard,
        }
    else:  # Employee
        pages = {
            "👁️ Secure Document Viewer": render_employee_viewer
        }

    # Navigation Menu
    selection = st.sidebar.radio("Navigation Menu", list(pages.keys()))

    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Log Out", use_container_width=True):
        st.session_state.clear()
        st.rerun()

    # Render Selected View
    view_func = pages[selection]
    view_func()
