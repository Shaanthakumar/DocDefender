import streamlit as st
import pandas as pd
from database.database import SessionLocal
from database.repositories import (
    list_users,
    list_documents,
    list_security_events,
    query_audit_logs
)
from ui.components import render_header, render_metric_card

def render_admin_dashboard():
    render_header("Administrator Security Operations Center", "Real-time enterprise metrics, system audit logs, and security alert overview")

    db = SessionLocal()
    try:
        users = list_users(db)
        docs = list_documents(db)
        sec_events = list_security_events(db)
        audit_logs = query_audit_logs(db, limit=20)

        unresolved_alerts = [e for e in sec_events if e.status == "ACTIVE"]

        # KPI Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            render_metric_card("Total Registered Users", str(len(users)), "normal")
        with col2:
            render_metric_card("Protected Documents", str(len(docs)), "success")
        with col3:
            render_metric_card("Total Security Events", str(len(sec_events)), "warning" if len(sec_events) > 0 else "normal")
        with col4:
            render_metric_card("Active Unresolved Alerts", str(len(unresolved_alerts)), "critical" if len(unresolved_alerts) > 0 else "success")

        st.markdown("### 📊 Security Events Breakdown")
        if sec_events:
            df_sec = pd.DataFrame([
                {
                    "ID": e.id,
                    "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "Event Type": e.event_type,
                    "Severity": e.severity,
                    "Description": e.description,
                    "Status": e.status
                }
                for e in sec_events
            ])
            st.dataframe(df_sec, use_container_width=True)
        else:
            st.info("No security events recorded yet.")

        st.markdown("### 📜 Recent Audit Trail")
        if audit_logs:
            df_audit = pd.DataFrame([
                {
                    "Timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "User ID": a.user_id or "System",
                    "Action": a.action,
                    "Status": a.status,
                    "Severity": a.severity,
                    "IP Address": a.ip_address or "127.0.0.1"
                }
                for a in audit_logs
            ])
            st.dataframe(df_audit, use_container_width=True)
        else:
            st.info("No audit logs available.")
    finally:
        db.close()
