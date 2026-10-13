import pytest
import numpy as np
from database.database import init_db, SessionLocal
from database.repositories import create_user, get_user_by_email, list_security_events
from services.auth_service import hash_password
from core.vision_monitor import PhoneDetector, VisionGuardTracker, create_simulated_phone_frame
from core.network_monitor import simulate_network_exfiltration
from core.filesystem_monitor import simulate_filesystem_event

@pytest.fixture(scope="module")
def setup_mon_db():
    init_db()
    db = SessionLocal()
    user = get_user_by_email(db, "mon_user_test@docsdefender.local")
    if not user:
        user = create_user(db, "Mon User", "mon_user_test@docsdefender.local", hash_password("pass"), "employee")
    uid = user.id
    db.close()
    return uid

def test_phone_detector_initialization():
    detector = PhoneDetector()
    assert detector is not None
    # Model should be loaded or load_error set cleanly
    assert detector.model_loaded is True or detector.load_error is not None

def test_vision_guard_tracker(setup_mon_db):
    uid = setup_mon_db
    db = SessionLocal()
    try:
        tracker = VisionGuardTracker(persistence_sec=0.1) # Fast threshold for test
        sim_frame = create_simulated_phone_frame()

        # Frame 1
        det1, conf1, lock1, _ = tracker.process_frame(uid, sim_frame, db)
        assert isinstance(det1, bool)

        # Frame 2 after time delay
        import time
        time.sleep(0.15)
        det2, conf2, lock2, _ = tracker.process_frame(uid, sim_frame, db)
        assert isinstance(det2, bool)
    finally:
        db.close()

def test_network_and_fs_simulation(setup_mon_db):
    uid = setup_mon_db
    db = SessionLocal()
    try:
        net_res = simulate_network_exfiltration(db, uid, destination_domain="dropbox.com", size_mb=10.0)
        assert net_res["status"] == "ALERT_TRIGGERED"
        assert net_res["destination"] == "dropbox.com"

        fs_res = simulate_filesystem_event(db, uid, action="DELETED", target_filename="Secret_Report.pdf")
        assert fs_res["status"] == "ALERT_TRIGGERED"
        assert fs_res["action"] == "DELETED"

        events = list_security_events(db, limit=10)
        assert len(events) >= 2
    finally:
        db.close()

def test_real_time_phone_guard_processor_threshold(setup_mon_db):
    from ui.camera_guard import RealTimePhoneGuardProcessor, CAMERA_GUARD_THRESHOLD
    import av

    assert CAMERA_GUARD_THRESHOLD == 0.70
    processor = RealTimePhoneGuardProcessor()
    assert processor.conf_threshold == 0.70

    # Ensure processor defaults with user_id
    uid = setup_mon_db
    processor.user_id = uid
    processor.user_name = "Test Employee"

    # Frame with no phone should not trigger lock
    empty_frame = av.VideoFrame.from_ndarray(np.zeros((100, 100, 3), dtype=np.uint8), format="bgr24")
    out_frame = processor.recv(empty_frame)
    assert out_frame is not None
    assert processor.lock_triggered_flag is False
    assert processor.phone_detected_flag is False

