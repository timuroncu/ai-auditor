import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

_LOCAL = {"ready": False}

def enabled() -> bool:
    return os.getenv("ENABLE_LOCAL_ML", "false").lower() in ("1", "true", "yes", "y")

def load_once():
    if _LOCAL.get("ready"):
        return

    model_path = os.getenv("LOCAL_MODEL_PATH", "").strip()
    if not model_path:
        raise RuntimeError("LOCAL_MODEL_PATH is missing in .env")

    threshold = float(os.getenv("LOCAL_MODEL_THRESHOLD", "0.5"))

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.to(device)
    model.eval()

    _LOCAL.update({
        "ready": True,
        "model_path": model_path,
        "threshold": threshold,
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
    pred, p_vuln, thr, device = predict(code_context)
    return {
        "agent": "LocalML-CodeBERT-Phase2",
        "vote": bool(pred),
        "p_vuln": p_vuln,
        "threshold": thr,
        "device": device
    }
