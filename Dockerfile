# DocsDefender Container Definition
FROM python:3.11-slim

# Install system dependencies for OpenCV, PyMuPDF, and Npcap/Scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libgomp1 \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application codebase
COPY . .

# Expose Streamlit (8501) and FastAPI (8000) ports
EXPOSE 8501 8000

# Default command launches FastAPI backend and Streamlit frontend
CMD ["python", "seed_demo.py"]
