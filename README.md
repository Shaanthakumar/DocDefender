# DocsDefender — Enterprise Document Leak Prevention & Forensic Tracing System

DocsDefender is a comprehensive enterprise document security platform designed to protect sensitive corporate documents from insider threats (unauthorized copying, mobile phone screen photography, and network exfiltration) and enable security investigators to forensically trace leaked document photos back to the responsible employee.

---

## Key Features

1. **Document Cryptography & Integrity**:
   - SHA-256 original document hash calculation and verification.
   - AES-256-GCM encryption of structured metadata payloads (`doc_id`, `employee_id`, `issued_at`, `watermark_id`, `doc_hash_ref`) with unique 96-bit random nonces and tag verification.

2. **Dual-Layer Invisible Watermarking**:
   - **LSB Spatial Steganography**: Embeds encrypted payloads into image bit planes with PSNR > 70 dB image quality.
   - **DCT Frequency Domain Watermarking**: Block-based (8x8) Discrete Cosine Transform watermarking resilient to analog-hole attacks (screen photos, recompression).
   - **Zero-Width Unicode Steganography**: Encodes watermarks into plain text documents without affecting readability.

3. **Dynamic Screen Watermark Overlay**:
   - Real-time semi-transparent, diagonal rotated CSS overlay (`-45°` rotation, `0.15` opacity) in the Employee Document Viewer displaying Employee ID, Name, Document ID, Current Timestamp, and IP Address.

4. **Behavioral AI Camera Guard (Computer Vision)**:
   - Real-time **YOLOv8n** cell phone detection on webcam stream.
   - Continuous detection persistence tracker (> 2.0 seconds) that automatically locks active employee document viewing sessions and obfuscates protected document content.

5. **Network Egress & Confidential Folder Observers**:
   - **Scapy Network Sniffer**: Monitors large outbound data transfers (> 5 MB) and non-whitelisted destinations. Includes a built-in unprivileged **Simulation Mode**.
   - **Watchdog Observer**: Monitors the `storage/confidential/` directory for unauthorized file creation, modification, movement, or deletion.

6. **Forensic Extraction & Leak Attribution Engine**:
   - Uploads suspected leaked document photos (JPEG/PNG).
   - Recovers spatial (LSB) and frequency (DCT) payloads, decrypts AES ciphertext, and verifies cryptographic authentication tags.
   - Correlates watermark metadata with database records (`User` and `Document`).
   - Produces structured JSON and Markdown forensic reports with 100% verified attribution.

7. **Multi-Role Security Operations Portal**:
   - **Administrator**: System overview metrics, document ingestion, employee permission assignment matrix, user account management, and security alert center.
   - **Employee**: Secure document portal with dynamic visible screen overlays and active session guard protection.
   - **Investigator**: Forensic extraction pipeline, historical leak report archive, and evidence hash management.

---

## Technology Stack

- **Language**: Python 3.11
- **Frontend**: Streamlit multipage architecture, custom CSS theme
- **Backend API**: FastAPI, Uvicorn, Pydantic v2
- **Database**: SQLite, SQLAlchemy ORM
- **Cryptography**: PyCryptodome (AES-256-GCM, SHA-256), Argon2-cffi, PyJWT
- **Image & PDF Processing**: OpenCV, NumPy, SciPy, Pillow, PyMuPDF (`fitz`)
- **Computer Vision**: Ultralytics YOLOv8n
- **Network & Filesystem**: Scapy, Watchdog
- **Testing**: Pytest, Pytest-cov

---

## System Architecture

```
                                    +-----------------------+
                                    | Streamlit Frontend    |
                                    | (app.py / UI Modules) |
                                    +-----------+-----------+
                                                |
                                                v
                                    +-----------------------+
                                    |  FastAPI Backend API  |
                                    |       (api.py)        |
                                    +-----------+-----------+
                                                |
            +-----------------------------------+-----------------------------------+
            |                                   |                                   |
            v                                   v                                   v
+-----------------------+           +-----------------------+           +-----------------------+
|  Crypto & Steg Engine |           |  Computer Vision      |           | Network & FS Observers|
| (AES-256-GCM, LSB,    |           | (YOLOv8n Camera Guard)|           | (Scapy & Watchdog)    |
|  DCT, SHA-256)        |           +-----------------------+           +-----------------------+
+-----------+-----------+                       |                                   |
            |                                   v                                   v
            |                       +-----------------------+           +-----------------------+
            |                       | Active Session Lock   |           | Central Audit Logger  |
            |                       +-----------------------+           +-----------------------+
            |                                   |                                   |
            +-----------------------------------+-----------------------------------+
                                                |
                                                v
                                    +-----------------------+
                                    | SQLite / SQLAlchemy   |
                                    | (storage/dlp_audit.db)|
                                    +-----------------------+
```

---

## Quick Start & Setup Instructions

### 1. Environment Setup

Clone the repository and set up a Python 3.11 virtual environment:

```bash
git clone https://github.com/org/DocsDefender.git
cd DocsDefender

# Create & activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Seed Initial Demo Accounts & Sample Documents

Execute the seeding script to initialize the SQLite database and create sample accounts:

```bash
python seed_demo.py
```

**Default Seed Credentials**:
- **Administrator**: `admin@docsdefender.local` / `AdminSecure2026!`
- **Employee 1**: `employee1@docsdefender.local` / `EmployeePass2026!`
- **Employee 2**: `employee2@docsdefender.local` / `EmployeePass2026!`
- **Investigator**: `investigator@docsdefender.local` / `InvestigatorPass2026!`

---

## Running the Application

### Option A: Launch Streamlit Security Portal
Run the main Streamlit application:

```bash
streamlit run app.py
```
Open **[http://localhost:8501](http://localhost:8501)** in your browser.

### Option B: Launch FastAPI REST Backend
Start the FastAPI REST server:

```bash
python api.py
```
Open **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)** to test API endpoints interactively.

### Option C: Run Terminal Showcase Script
Run the automated CLI showcase script:

```bash
python demo_phase1.py
```

---

## Running Automated Unit Tests

Execute the unit test suite across all security modules:

```bash
python -m pytest -v tests/
```

To view code coverage:

```bash
pytest --cov=core --cov=services --cov=api_routes tests/
```

---

## Docker Deployment

Build and start the containerized application using Docker Compose:

```bash
docker-compose up --build
```

- **Streamlit Frontend**: `http://localhost:8501`
- **FastAPI REST Server**: `http://localhost:8000/docs`

---

## Demonstration Workflow

1. **Admin Ingestion**: Log in as `admin@docsdefender.local`. Navigate to **Document Ingestion**, upload `sample_documents/architecture_plan.pdf`, select **Top Secret**, choose **DCT Watermarking**, and assign access to `Alice Johnson (Employee 1)`.
2. **Employee Viewing**: Log out and log in as `employee1@docsdefender.local`. Open **Secure Document Viewer**. The document renders with a dynamic, rotated, semi-transparent visible watermark overlay displaying `EMP:2 (Alice Johnson)`.
3. **Behavioral Phone Detection**: Open **Behavioral AI Camera Guard**. Run the YOLOv8 phone detector test frame (or simulate detection). Detection for > 2 seconds immediately locks Alice's document viewing session and obfuscates document content.
4. **Forensic Attribution**: Log in as `investigator@docsdefender.local`. Navigate to **Forensic Tracing Tool**, upload `storage/protected/{doc_id}.png`. Click **Execute Forensic Extraction Pipeline**. The engine recovers the encrypted payload, verifies the AES authentication tag, correlates DB records, attributes the leak to `Alice Johnson`, and generates a JSON forensic report.

---

## Project Structure

```
DocsDefender/
├── app.py                      # Streamlit Multipage Entry Point
├── api.py                      # FastAPI REST Backend App
├── seed_demo.py                # Demo Seeding Script
├── demo_phase1.py              # CLI Showcase Script
├── requirements.txt            # Python Dependencies
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Docker composition file
├── README.md                   # System Documentation
├── .env                        # Environment configuration
│
├── config/                     # System & secret settings
├── database/                   # SQLAlchemy ORM models & repositories
├── core/                       # Crypto, Steganography, Vision, Network, FS & Forensic Engines
├── services/                   # Auth, Document, Session & Audit services
├── api_routes/                 # FastAPI REST endpoint routers
├── ui/                         # Streamlit pages, styles, & components
├── tests/                      # Pytest unit test suite
├── storage/                    # Encrypted protected storage & evidence storage
├── sample_documents/           # Test PDFs, PNGs, TXT files
└── reports/                    # Generated forensic JSON & Markdown reports
```

---

## Security Considerations & Limitations

- **Privilege Scoping**: Live Scapy packet capture requires Administrator/root privileges. DocsDefender provides a built-in simulation mode for non-privileged execution environments.
- **DCT Watermark Bounds**: Extreme perspective transformations or severe cropping of screen photos may degrade watermark extraction. AES-256-GCM authentication tags strictly guarantee zero false positives.
- **Secrets Management**: Master AES keys and JWT secret keys must be loaded from environment variables in production deployments.
