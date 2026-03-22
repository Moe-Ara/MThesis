import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from intelligence.core.utils import extract_json
from intelligence.scorers.classifier_config import default_severity_for_class, severity_to_class

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _parse_completion(raw: str) -> Dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        parsed = extract_json(raw)
        return parsed or {}


def _load_training_data(path: Path) -> Tuple[List[str], List[str], List[float]]:
    prompts: List[str] = []
    labels: List[str] = []
    severities: List[float] = []

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            prompt = record.get("prompt") or ""
            completion = _parse_completion(record.get("completion", ""))
            severity = completion.get("severity")
            if not prompt or severity is None:
                continue
            label = severity_to_class(severity)
            prompts.append(prompt)
            labels.append(label)
            severities.append(float(severity))

    if not prompts:
        raise ValueError("No training data found. Check the JSONL input format.")

    return prompts, labels, severities


def _class_severity_means(labels: List[str], severities: List[float]) -> Dict[str, float]:
    buckets: Dict[str, List[float]] = {}
    for label, sev in zip(labels, severities):
        buckets.setdefault(label, []).append(sev)

    result: Dict[str, float] = {}
    for label, values in buckets.items():
        result[label] = float(np.mean(values))

    for label in set(labels):
        if label not in result:
            result[label] = float(default_severity_for_class(label))

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a classifier-based scorer model.")
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("intelligence/training/data/real_scorer_train.jsonl"),
        help="JSONL scorer training data.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("intelligence/models/scorer_classifier"),
        help="Output directory for model.joblib and meta.json.",
    )
    parser.add_argument("--max-features", type=int, default=12000)
    parser.add_argument("--min-df", type=int, default=2)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not args.data.exists():
        raise FileNotFoundError(f"Training data not found: {args.data}")

    np.random.seed(args.seed)

    prompts, labels, severities = _load_training_data(args.data)
    train_x, val_x, train_y, val_y, train_sev, val_sev = train_test_split(
        prompts,
        labels,
        severities,
        test_size=args.test_size,
        stratify=labels,
        random_state=args.seed,
    )

    pipeline = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    max_features=args.max_features,
                    min_df=args.min_df,
                    ngram_range=(1, 2),
                    lowercase=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=1000,
                    n_jobs=-1,
                    class_weight="balanced",
                    solver="lbfgs",
                    random_state=args.seed,
                ),
            ),
        ]
    )

    logger.info("Training classifier scorer...")
    pipeline.fit(train_x, train_y)

    preds = pipeline.predict(val_x)
    acc = accuracy_score(val_y, preds)
    logger.info("Validation accuracy: %.4f", acc)
    logger.info("Validation report:\n%s", classification_report(val_y, preds))

    class_to_severity = _class_severity_means(train_y + val_y, train_sev + val_sev)

    args.output.mkdir(parents=True, exist_ok=True)
    model_path = args.output / "model.joblib"
    meta_path = args.output / "meta.json"

    joblib.dump(pipeline, model_path)
    meta = {
        "trainedAt": datetime.now(tz=timezone.utc).isoformat(),
        "dataPath": str(args.data),
        "numExamples": len(prompts),
        "class_to_severity": class_to_severity,
        "validationAccuracy": acc,
    }
    with meta_path.open("w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2)

    logger.info("Saved model to %s", model_path)
    logger.info("Saved metadata to %s", meta_path)


if __name__ == "__main__":
    main()
