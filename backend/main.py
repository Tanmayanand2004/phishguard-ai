from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router

# Create FastAPI app
app = FastAPI(
    title="PhishGuard AI",
    description="AI-powered phishing detection API",
    version="1.0.0"
)

# CORS — allows browser extensions and frontends to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes under /api/v1
app.include_router(router, prefix="/api/v1")


@app.get("/")
def root():
    return {
        "name": "PhishGuard AI",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health"
    }