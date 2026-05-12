import pickle
import numpy as np
import os

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


def predict(features: dict) -> dict:
    """
    Takes a dict of URL features and returns prediction.
    """
    # Build feature vector in correct order
    # Missing features default to 0
    feature_vector = []
    for name in feature_names:
        value = features.get(name, 0)
        feature_vector.append(float(value))

    X = np.array([feature_vector])

    # Predict
    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]

    confidence = float(probabilities[prediction])
    risk_score = float(probabilities[1])  # probability of being phishing

    return {
        "is_phishing": prediction == 1,
        "confidence": round(confidence, 4),
        "risk_score": round(risk_score, 4),
        "risk_percentage": round(risk_score * 100, 1),
        "label": "phishing" if prediction == 1 else "legitimate"
    }