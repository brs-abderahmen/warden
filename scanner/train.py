"""Fine-tune a small text classifier to flag poisoned tool descriptions.

Picks the threshold on validation data, then reports held-out test results by attack family.
Usage: python scanner/train.py <dataset.jsonl> <output_dir>
"""

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL = "microsoft/deberta-v3-small"
MAX_LENGTH = 256
BATCH_SIZE = 16
EPOCHS = 2
LEARNING_RATE = 3e-5
TARGET_FALSE_POSITIVE_RATE = 0.01
SEED = 13


def batches(rows, tokenizer, device, shuffle=False):
    order = list(range(len(rows)))
    if shuffle:
        random.shuffle(order)
    for start in range(0, len(order), BATCH_SIZE):
        chosen = [rows[index] for index in order[start : start + BATCH_SIZE]]
        encoded = tokenizer(
            [row["text"] for row in chosen],
            truncation=True,
            max_length=MAX_LENGTH,
            padding=True,
            return_tensors="pt",
        ).to(device)
        labels = torch.tensor([row["label"] for row in chosen], device=device)
        yield encoded, labels


def predict(model, rows, tokenizer, device) -> np.ndarray:
    model.eval()
    scores = []
    with torch.no_grad():
        for encoded, _ in batches(rows, tokenizer, device):
            logits = model(**encoded).logits
            scores.append(torch.softmax(logits, dim=-1)[:, 1].cpu().numpy())
    return np.concatenate(scores)


def threshold_for(scores: np.ndarray, labels: np.ndarray) -> float:
    """Lowest threshold that keeps false alarms at the target rate on benign validation data."""
    return float(np.quantile(scores[labels == 0], 1 - TARGET_FALSE_POSITIVE_RATE))


def report(scores: np.ndarray, labels: np.ndarray, rows: list[dict], threshold: float) -> dict:
    predicted = (scores >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predicted, average="binary", zero_division=0
    )
    benign = labels == 0
    by_family = defaultdict(list)
    for row, flagged in zip(rows, predicted):
        if row["label"] == 1:
            by_family[row["family"]].append(int(flagged))
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "auc": float(roc_auc_score(labels, scores)),
        "false_positive_rate": float(predicted[benign].mean()),
        "recall_by_family": {name: float(np.mean(hits)) for name, hits in sorted(by_family.items())},
        "count": len(rows),
    }


def main() -> None:
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    rows = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
    splits = {name: [row for row in rows if row["split"] == name] for name in ("train", "val", "test")}
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL, num_labels=2, dtype=torch.float32
    ).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE)

    for epoch in range(EPOCHS):
        model.train()
        for step, (encoded, labels) in enumerate(batches(splits["train"], tokenizer, device, shuffle=True)):
            loss = model(**encoded, labels=labels).loss
            if not torch.isfinite(loss):
                raise RuntimeError(f"loss became {loss.item()} at epoch {epoch} step {step}")
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            optimizer.zero_grad()
            if step % 100 == 0:
                print(f"epoch {epoch} step {step} loss {loss.item():.4f}", flush=True)

    val_scores = predict(model, splits["val"], tokenizer, device)
    val_labels = np.array([row["label"] for row in splits["val"]])
    threshold = threshold_for(val_scores, val_labels)

    test_scores = predict(model, splits["test"], tokenizer, device)
    test_labels = np.array([row["label"] for row in splits["test"]])
    results = {
        "model": MODEL,
        "threshold": threshold,
        "val": report(val_scores, val_labels, splits["val"], threshold),
        "test": report(test_scores, test_labels, splits["test"], threshold),
    }
    (output_dir / "metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    model.save_pretrained(output_dir / "model")
    tokenizer.save_pretrained(output_dir / "model")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
