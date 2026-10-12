import streamlit as st
from typing import Optional

def render_header(title: str, subtitle: str):
    """Render standardized enterprise security header."""
    st.markdown(
        f"""
        <div class="sec-header">
            <h1 class="sec-title">🛡️ {title}</h1>
            <p class="sec-subtitle">{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

def render_metric_card(title: str, value: str, status_cls: str = "normal"):
    """Render modern glass metric card."""
    cls_map = {"normal": "", "critical": "critical", "warning": "warning", "success": "success"}
    cls_name = cls_map.get(status_cls, "")
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">{title}</div>
            <div class="metric-value {cls_name}">{value}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

def render_badge(classification: str) -> str:
    """Return HTML tag for classification badge."""
    c_lower = classification.lower().replace(" ", "")
    return f'<span class="badge badge-{c_lower}">{classification}</span>'

def render_session_locked_banner(reason: str = "Mobile Phone Detected by Computer Vision Guard"):
    """Render locked-screen shield alert."""
    st.markdown(
        f"""
        <div class="session-locked-banner">
            <div class="session-locked-title">⚠️ DOCUMENT VIEWING SESSION LOCKED</div>
            <p style="color: #c9d1d9; font-size: 1.1rem; margin-top: 10px;">
                Access to protected document bytes has been automatically suspended by DocsDefender Behavioral Security.
            </p>
            <p style="color: #f85149; font-weight: 600;">
                Reason: {reason}
            </p>
            <p style="color: #8b949e; font-size: 0.85rem;">
                This security event has been logged to the Central Audit Trail. Contact your Administrator to unlock.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )
