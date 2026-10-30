"""Flag poisoned tool descriptions with the trained classifier. Requires scanner/requirements.txt."""

import json
from pathlib import Path


class Scanner:
    def __init__(self, run_dir: Path, device: str = "cpu"):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.device = device
        self.threshold = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))["threshold"]
        self.tokenizer = AutoTokenizer.from_pretrained(run_dir / "model")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            run_dir / "model", dtype=torch.float32
        ).to(device)
        self.model.eval()

    def score(self, text: str) -> float:
        encoded = self.tokenizer(text, truncation=True, max_length=256, return_tensors="pt").to(self.device)
        with self.torch.no_grad():
            logits = self.model(**encoded).logits
        return float(self.torch.softmax(logits, dim=-1)[0, 1])

    def flags(self, text: str) -> bool:
        return self.score(text) >= self.threshold
