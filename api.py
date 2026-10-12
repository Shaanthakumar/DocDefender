from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.database import init_db
from api_routes import auth, users, documents, sessions, monitoring, forensics, audit

# Initialize Database Tables
init_db()

app = FastAPI(
    title="DocsDefender API",
    description="Enterprise Document Leak Prevention & Forensic Tracing REST API",
    version="1.0.0"
)

# Enable CORS for local Streamlit & dev access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(documents.router)
app.include_router(sessions.router)
app.include_router(monitoring.router)
app.include_router(forensics.router)
app.include_router(audit.router)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "DocsDefender Security Server",
        "version": "1.0.0"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
