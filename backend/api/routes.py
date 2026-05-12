from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import time
from backend.ml.model import predict, feature_names

router = APIRouter()


# Input schema — what the API accepts
class ScanRequest(BaseModel):
    features: dict


# Output schema — what the API returns
class ScanResponse(BaseModel):
    is_phishing: bool
    confidence: float
    risk_score: float
    risk_percentage: float
    label: str
    features_received: int
    scan_time_ms: float


@router.get("/health")
def health_check():
    """Check if the API is running."""
    return {
        "status": "healthy",
        "model": "XGBoost v1",
        "features_expected": len(feature_names)
    }


@router.post("/scan", response_model=ScanResponse)
def scan_url(request: ScanRequest):
    """
    Scan a URL for phishing.
    Accepts a dict of URL features and returns a prediction.
    """
    start = time.time()

    if not request.features:
        raise HTTPException(status_code=400, detail="No features provided")

    try:
        result = predict(request.features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

    elapsed = round((time.time() - start) * 1000, 2)

    return ScanResponse(
        **result,
        features_received=len(request.features),
        scan_time_ms=elapsed
    )


@router.get("/features")
def get_feature_names():
    """Return list of expected feature names."""
    return {
        "count": len(feature_names),
        "features": feature_names
    }