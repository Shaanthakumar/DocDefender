def get_custom_css() -> str:
    """Return dark enterprise security theme CSS with dynamic screen overlay styles."""
    return """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

    /* Premium Cybersecurity Dark SOC Palette */
    :root {
        --bg-deep: #07090e;
        --bg-surface: #0e131f;
        --bg-surface-elevated: #141c2e;
        --border-subtle: #1e293b;
        --border-glow: rgba(0, 242, 254, 0.25);
        --accent-cyan: #00f2fe;
        --accent-blue: #4facfe;
        --accent-emerald: #10b981;
        --accent-amber: #f59e0b;
        --accent-crimson: #ff3366;
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
    }

    .stApp {
        background: radial-gradient(circle at 15% 15%, #0e1626 0%, #07090e 100%) !important;
        color: var(--text-primary) !important;
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    /* Streamlit Containers & Cards Polish */
    div[data-testid="stVerticalBlock"] > div {
        transition: all 0.2s ease-in-out;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #090d15 0%, #07090e 100%) !important;
        border-right: 1px solid rgba(30, 41, 59, 0.8) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.5);
    }
    section[data-testid="stSidebar"] .stMarkdown h1, 
    section[data-testid="stSidebar"] .stMarkdown h2, 
    section[data-testid="stSidebar"] .stMarkdown h3 {
        background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        letter-spacing: -0.02em;
    }

    /* Modern Glass-like Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, rgba(20, 28, 46, 0.75) 0%, rgba(14, 19, 31, 0.85) 100%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-top: 1px solid rgba(0, 242, 254, 0.3);
        border-radius: 12px;
        padding: 20px 22px;
        margin-bottom: 16px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(12px);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: rgba(0, 242, 254, 0.4);
        box-shadow: 0 12px 28px rgba(0, 0, 0, 0.6), 0 0 16px rgba(0, 242, 254, 0.15);
    }
    .metric-title {
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        margin-bottom: 8px;
    }
    .metric-value {
        font-size: 2.1rem;
        font-weight: 800;
        color: #00f2fe;
        letter-spacing: -0.03em;
        font-feature-settings: "tnum";
    }
    .metric-value.critical {
        color: #ff3366;
        text-shadow: 0 0 20px rgba(255, 51, 102, 0.4);
    }
    .metric-value.warning {
        color: #f59e0b;
        text-shadow: 0 0 20px rgba(245, 158, 11, 0.4);
    }
    .metric-value.success {
        color: #10b981;
        text-shadow: 0 0 20px rgba(16, 185, 129, 0.4);
    }

    /* High-contrast Classification Badges */
    .badge {
        display: inline-block;
        padding: 4px 12px;
        font-size: 0.72rem;
        font-weight: 700;
        border-radius: 20px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    .badge-confidential {
        background: rgba(0, 242, 254, 0.12);
        color: #00f2fe;
        border: 1px solid rgba(0, 242, 254, 0.35);
        box-shadow: 0 0 8px rgba(0, 242, 254, 0.2);
    }
    .badge-topsecret {
        background: rgba(255, 51, 102, 0.15);
        color: #ff3366;
        border: 1px solid rgba(255, 51, 102, 0.4);
        box-shadow: 0 0 10px rgba(255, 51, 102, 0.25);
    }
    .badge-secret {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.4);
        box-shadow: 0 0 8px rgba(245, 158, 11, 0.2);
    }
    .badge-public {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }

    /* Security Header */
    .sec-header {
        background: linear-gradient(135deg, rgba(20, 28, 46, 0.9) 0%, rgba(10, 15, 26, 0.95) 100%);
        border: 1px solid rgba(30, 41, 59, 0.8);
        border-left: 4px solid #00f2fe;
        padding: 20px 28px;
        margin-bottom: 24px;
        border-radius: 12px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    .sec-title {
        font-size: 1.7rem;
        font-weight: 800;
        background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        letter-spacing: -0.02em;
    }
    .sec-subtitle {
        font-size: 0.92rem;
        color: #94a3b8;
        margin-top: 4px;
        font-weight: 500;
    }

    /* Control Panel Box */
    .sec-panel {
        background: rgba(14, 19, 31, 0.7);
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 18px 22px;
        margin-bottom: 16px;
    }

    /* Primary and Form Buttons Polish */
    .stButton > button {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important;
        color: #f1f5f9 !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 8px 18px !important;
        transition: all 0.2s ease !important;
    }
    .stButton > button:hover {
        border-color: #00f2fe !important;
        color: #00f2fe !important;
        box-shadow: 0 0 16px rgba(0, 242, 254, 0.25) !important;
        transform: translateY(-1px);
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%) !important;
        color: #07090e !important;
        border: none !important;
        font-weight: 700 !important;
        box-shadow: 0 4px 14px rgba(0, 242, 254, 0.35) !important;
    }
    .stButton > button[kind="primary"]:hover {
        box-shadow: 0 6px 20px rgba(0, 242, 254, 0.55) !important;
        transform: translateY(-1px);
    }

    /* Streamlit Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1e293b;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent !important;
        border-radius: 8px 8px 0 0 !important;
        color: #94a3b8 !important;
        padding: 10px 18px !important;
        font-weight: 600 !important;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(0, 242, 254, 0.08) !important;
        color: #00f2fe !important;
        border-bottom: 2px solid #00f2fe !important;
    }

    /* Dataframe & Tables */
    [data-testid="stDataFrame"] {
        border: 1px solid #1e293b;
        border-radius: 8px;
        overflow: hidden;
    }

    /* Dynamic Diagonal Visible Watermark Container Overlay */
    .watermarked-viewer-container {
        position: relative;
        overflow: hidden;
        border: 1px solid #1e293b;
        border-radius: 12px;
        background-color: #090d15;
        padding: 24px;
        user-select: none;
        -webkit-user-select: none;
        -webkit-touch-callout: none;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.6);
    }

    /* Transparent click/context-menu shield to block right-click 'Save Image As' */
    .viewer-protection-shield {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1000;
        background: transparent;
        cursor: default;
    }

    /* Disable drag and pointer interaction on document images */
    .watermarked-viewer-container img {
        pointer-events: none !important;
        -webkit-user-drag: none !important;
        user-select: none !important;
        border-radius: 6px;
    }

    .watermark-overlay {
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        pointer-events: none;
        z-index: 999;
        display: flex;
        flex-wrap: wrap;
        align-content: space-around;
        justify-content: space-around;
        transform: rotate(-45deg);
        opacity: 0.18;
        user-select: none;
    }

    .watermark-text-tile {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.15rem;
        font-weight: 700;
        color: #00f2fe;
        padding: 40px 60px;
        text-shadow: 1px 1px 3px rgba(0,0,0,0.9);
        white-space: nowrap;
    }

    /* Locked Session Red Warning Shield Overlay */
    .session-locked-banner {
        background: radial-gradient(circle at center, rgba(255, 51, 102, 0.12) 0%, rgba(14, 19, 31, 0.9) 100%);
        border: 2px solid #ff3366;
        border-radius: 12px;
        padding: 32px;
        text-align: center;
        margin: 20px 0;
        box-shadow: 0 0 30px rgba(255, 51, 102, 0.3);
    }
    .session-locked-title {
        color: #ff3366;
        font-size: 1.7rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        margin-bottom: 12px;
        text-shadow: 0 0 20px rgba(255, 51, 102, 0.5);
    }
    </style>
    <script>
    document.addEventListener('contextmenu', function(e) {
        if (e.target.closest('.watermarked-viewer-container')) {
            e.preventDefault();
            return false;
        }
    }, false);
    </script>
    """

def get_visible_watermark_html(employee_id: str, employee_name: str, doc_id: str, ip_address: str, timestamp: str) -> str:
    """Generate dynamic diagonal semi-transparent CSS overlay HTML."""
    tile_text = f"CONFIDENTIAL | EMP:{employee_id} ({employee_name}) | DOC:{doc_id[:8]} | {timestamp} | IP:{ip_address}"
    tiles_html = "".join([f'<div class="watermark-text-tile">{tile_text}</div>' for _ in range(24)])
    return f'<div class="watermark-overlay">{tiles_html}</div>'
