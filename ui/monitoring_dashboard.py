import cv2
import numpy as np
import streamlit as st
import pandas as pd
from database.database import SessionLocal
from database.repositories import list_security_events, list_users
from core.vision_monitor import VisionGuardTracker, create_simulated_phone_frame
from core.network_monitor import simulate_network_exfiltration
from core.filesystem_monitor import simulate_filesystem_event
from services.session_manager import lock_active_user_sessions, unlock_session
from ui.components import render_header, render_metric_card

def render_monitoring_dashboard():
    render_header("Behavioral & Egress Security Monitoring Center", "Real-time AI camera guard, network traffic analyzer, confidential folder observer, and security incident controls")

    user_info = st.session_state.get("user", {})
    current_user_id = user_info.get("id", 1)

    db = SessionLocal()
    try:
        sec_events = list_security_events(db, limit=50)
        active_alerts = [e for e in sec_events if e.status == "ACTIVE"]
        users = list_users(db)

        # Overview Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            render_metric_card("Total Security Events", str(len(sec_events)), "normal")
        with col2:
            render_metric_card("Active Unresolved Alerts", str(len(active_alerts)), "critical" if len(active_alerts) > 0 else "success")
        with col3:
            render_metric_card("Camera Guard Status", "ACTIVE (YOLOv8n)", "success")
        with col4:
            render_metric_card("Egress & FS Observers", "MONITORING", "success")

        st.markdown("---")
        tab1, tab2, tab3 = st.tabs(["🎥 Behavioral AI Camera Guard", "🧪 Incident Simulation Suite", "🚨 Security Event Log & Actions"])

        with tab1:
            st.markdown("#### Real-time YOLOv8 Mobile Phone Detection Guard")
            st.caption("The camera guard analyzes webcam frames for cell phones. Continuous detection > 2 seconds triggers an immediate document session lock.")

            col_cam1, col_cam2 = st.columns([2, 1])

            with col_cam1:
                run_test_frame = st.button("Run YOLOv8 Phone Detection on Test Frame", use_container_width=True)
                if run_test_frame:
                    tracker = VisionGuardTracker()
                    sim_frame = create_simulated_phone_frame()
                    detected, conf, locked, annotated_frame = tracker.process_frame(current_user_id, sim_frame, db)

                    st.image(cv2.cvtColor(annotated_frame, cv2.COLOR_BGR2RGB), use_container_width=True, caption=f"YOLOv8 Frame Output (Detected: {detected}, Conf: {conf*100:.1f}%)")

                    if locked:
                        st.error("🚨 SECURITY ALERT: Continuous phone detection triggered an active document session lock!")
                    elif detected:
                        st.warning(f"⚠️ Phone detected ({conf*100:.1f}% confidence). Continuous detection >2s will lock active session.")
                    else:
                        st.success("✅ No phone detected in frame.")

            with col_cam2:
                st.markdown("**Guard Configuration**")
                st.info("- **Model**: `YOLOv8n` (Nano CPU-Optimized)\n- **Threshold**: `70%` Confidence\n- **Persistence Limit**: `2.0 Seconds`\n- **Action**: Automatic Document Obfuscation")

        with tab2:
            st.markdown("#### Controlled Security Simulation Suite")
            st.caption("Simulate threat vectors for demonstration and compliance validation without needing elevated OS privileges.")

            sim_col1, sim_col2, sim_col3 = st.columns(3)

            with sim_col1:
                st.markdown("**📱 Behavioral Phone Detection**")
                if st.button("Simulate Phone Detection Event", use_container_width=True):
                    lock_active_user_sessions(db, current_user_id, reason="SIMULATED: Mobile Phone Detected for >2s")
                    st.error("Triggered Simulated Phone Detection & Session Lock!")
                    st.rerun()

            with sim_col2:
                st.markdown("**🌐 Network Data Exfiltration**")
                if st.button("Simulate >5MB Outbound Transfer", use_container_width=True):
                    res = simulate_network_exfiltration(db, current_user_id, destination_domain="mail.gmail.com", size_mb=12.4)
                    st.error(f"Triggered Simulated Exfiltration Alert (12.4 MB to {res['destination']})!")
                    st.rerun()

            with sim_col3:
                st.markdown("**📁 Confidential Folder Activity**")
                if st.button("Simulate Unauthorized FS Activity", use_container_width=True):
                    res = simulate_filesystem_event(db, current_user_id, action="UNAUTHORIZED_COPY", target_filename="Top_Secret_Plan.pdf")
                    st.warning(f"Triggered Simulated FS Observer Alert ({res['filename']})!")
                    st.rerun()

        with tab3:
            st.markdown("#### Security Incident Log & Administrative Resolution")
            if sec_events:
                data = []
                for e in sec_events:
                    data.append({
                        "Event ID": e.id,
                        "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "Event Type": e.event_type,
                        "Severity": e.severity,
                        "Description": e.description,
                        "Status": e.status,
                        "User ID": e.user_id or "System"
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)
            else:
                st.info("No security events logged.")
    finally:
        db.close()
