import pickle
import numpy as np
import os
# Known legitimate domains whitelist
# In production this would be a large reputation database
LEGITIMATE_DOMAINS = {
    'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'youtube.com', 'wikipedia.org', 'stackoverflow.com', 'reddit.com',
    'netflix.com', 'spotify.com', 'dropbox.com', 'slack.com',
    'zoom.us', 'adobe.com', 'salesforce.com', 'cloudflare.com',
    'anthropic.com', 'openai.com', 'huggingface.co', 'kaggle.com'
}
# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "xgboost_v1.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "models", "feature_names.pkl")

# Load model and feature names at startup
print(f"Loading model from {MODEL_PATH}...")

with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

with open(FEATURES_PATH, 'rb') as f:
    feature_names = pickle.load(f)

print(f"Model loaded. Expects {len(feature_names)} features.")

def predict(features: dict, url: str = None) -> dict:
    """
    Takes a dict of URL features and returns prediction.
    """
    import tldextract

    # Check whitelist first
    if url:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if domain in LEGITIMATE_DOMAINS:
            return {
                "is_phishing": False,
                "confidence": 0.99,
                "risk_score": 0.01,
                "risk_percentage": 1.0,
                "label": "legitimate",
                "note": "trusted domain"
            }

    # Build feature vector in correct order
    feature_vector = []
    for name in feature_names:
        value = features.get(name, 0)
        feature_vector.append(float(value))

    X = np.array([feature_vector])

    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]
    confidence = float(probabilities[prediction])
    risk_score = float(probabilities[1])

    return {
        "is_phishing": prediction == 1,
        "confidence": round(confidence, 4),
        "risk_score": round(risk_score, 4),
        "risk_percentage": round(risk_score * 100, 1),
        "label": "phishing" if prediction == 1 else "legitimate"
    }