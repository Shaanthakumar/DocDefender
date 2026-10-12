import cv2
import numpy as np

def generate_diagram():
    # Create 1200x800 image canvas
    canvas = np.full((800, 1200, 3), 22, dtype=np.uint8)

    # Background Panels
    cv2.rectangle(canvas, (40, 40), (1160, 120), (35, 45, 60), -1)
    cv2.rectangle(canvas, (40, 40), (1160, 120), (88, 166, 255), 2)
    cv2.putText(canvas, "DOCSDEFENDER SYSTEM ARCHITECTURE", (320, 85), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (88, 166, 255), 2, cv2.LINE_AA)

    # Subsystems
    boxes = [
        ("STREAMLIT FRONTEND", "(app.py, UI Pages, CSS Overlays)", 60, 180, 340, 320, (30, 40, 55), (88, 166, 255)),
        ("FASTAPI BACKEND API", "(api.py, REST Routers, RBAC)", 430, 180, 770, 320, (30, 40, 55), (88, 166, 255)),
        ("SQLITE / SQLALCHEMY ORM", "(database/models.py, repos)", 860, 180, 1140, 320, (30, 40, 55), (88, 166, 255)),
        
        ("CRYPTO & STEG ENGINE", "(AES-256-GCM, LSB, DCT, SHA-256)", 60, 380, 380, 520, (35, 50, 40), (63, 185, 80)),
        ("COMPUTER VISION GUARD", "(YOLOv8n Mobile Phone Detector)", 430, 380, 770, 520, (50, 35, 35), (248, 81, 73)),
        ("NETWORK & FS OBSERVERS", "(Scapy Egress, Watchdog Observer)", 820, 380, 1140, 520, (50, 45, 30), (210, 153, 34)),

        ("FORENSIC EXTRACTION ENGINE", "(Payload Recovery & DB Correlation)", 200, 580, 600, 720, (45, 35, 55), (188, 140, 255)),
        ("AUDIT & SESSION LOGGERS", "(AuditLogger & SessionManager)", 660, 580, 1000, 720, (40, 40, 50), (139, 148, 158)),
    ]

    for title, subtitle, x1, y1, x2, y2, bg_color, border_color in boxes:
        cv2.rectangle(canvas, (x1, y1), (x2, y2), bg_color, -1)
        cv2.rectangle(canvas, (x1, y1), (x2, y2), border_color, 2)
        cv2.putText(canvas, title, (x1 + 15, y1 + 50), cv2.FONT_HERSHEY_SIMPLEX, 0.6, border_color, 2, cv2.LINE_AA)
        cv2.putText(canvas, subtitle, (x1 + 15, y1 + 90), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (200, 210, 220), 1, cv2.LINE_AA)

    # Connecting Arrows / Lines
    lines = [
        ((200, 320), (200, 380)),
        ((600, 320), (600, 380)),
        ((1000, 320), (1000, 380)),
        ((220, 520), (400, 580)),
        ((600, 520), (400, 580)),
        ((600, 520), (830, 580)),
        ((980, 520), (830, 580)),
    ]

    for start, end in lines:
        cv2.line(canvas, start, end, (100, 110, 125), 2, cv2.LINE_AA)

    cv2.imwrite("Architecture_Diagram.png", canvas)
    print("[OK] Architecture_Diagram.png successfully generated.")

if __name__ == "__main__":
    generate_diagram()
