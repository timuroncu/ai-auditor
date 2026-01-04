import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

_LOCAL = {"ready": False}

def enabled() -> bool:
    """Check if local ML agent is enabled via environment variable"""
    return os.getenv("LOCAL_ML_ENABLED", "false").lower() in ("1", "true", "yes", "y")

def load_once():
    if _LOCAL.get("ready"):
        return

    model_path = os.getenv("LOCAL_ML_MODEL_PATH", "").strip()
    if not model_path:
        raise RuntimeError("LOCAL_ML_MODEL_PATH is missing in .env")

    # Two thresholds for voting logic:
    # - skip_threshold: below this = likely safe (skip AI analysis)
    # - force_ai_threshold: above this = likely vulnerable (force AI confirmation)
    skip_threshold = float(os.getenv("LOCAL_ML_SKIP_THRESHOLD", "0.20"))
    force_ai_threshold = float(os.getenv("LOCAL_ML_FORCE_AI_THRESHOLD", "0.70"))
    threshold = float(os.getenv("LOCAL_ML_THRESHOLD", "0.5"))  # default voting threshold

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.to(device)
    model.eval()

    _LOCAL.update({
        "ready": True,
        "model_path": model_path,
        "threshold": threshold,
        "skip_threshold": skip_threshold,
        "force_ai_threshold": force_ai_threshold,
        "device": device,
        "tokenizer": tokenizer,
        "model": model,
    })

def predict(code_text: str):
    load_once()
    tok = _LOCAL["tokenizer"]
    mdl = _LOCAL["model"]
    device = _LOCAL["device"]
    thr = _LOCAL["threshold"]

    inputs = tok(str(code_text), truncation=True, max_length=512, return_tensors="pt").to(device)
    with torch.no_grad():
        logits = mdl(**inputs).logits
        probs = torch.softmax(logits, dim=1)
        p_vuln = float(probs[0, 1].item())
        pred = 1 if p_vuln >= thr else 0

    return pred, p_vuln, thr, device

def vote(code_context: str) -> dict:
    """
    Vote on whether code is vulnerable using local ML model.
    
    Returns dict with:
    - vote: True if vulnerable, False if safe
    - p_vuln: probability score (0.0 to 1.0)
    - skip_ai: True if confidence is high enough to skip OpenAI analysis
    - force_ai: True if score is high enough to force AI confirmation
    """
    pred, p_vuln, thr, device = predict(code_context)
    skip_thr = _LOCAL.get("skip_threshold", 0.20)
    force_thr = _LOCAL.get("force_ai_threshold", 0.70)
    
    return {
        "agent": "LocalML-CodeBERT-Phase2",
        "vote": bool(pred),
        "p_vuln": p_vuln,
        "threshold": thr,
        "skip_threshold": skip_thr,
        "force_ai_threshold": force_thr,
        "skip_ai": p_vuln < skip_thr,  # Very low probability = skip expensive AI
        "force_ai": p_vuln >= force_thr,  # High probability = definitely check with AI
        "device": device
    }