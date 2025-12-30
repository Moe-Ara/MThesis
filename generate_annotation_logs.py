import argparse
import csv
import json
from pathlib import Path


def parse_json_value(value: str):
    value = value.strip()
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def load_dataset(path: Path):
    rows = {}
    with path.open("r", encoding="utf-8", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            rows[row["id"]] = row
    return rows


def build_log(row: dict):
    raw_log = row.get("full_log", "")
    truncated = raw_log[:1024]
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "rule": parse_json_value(row["rule"]),
        "agent": parse_json_value(row["agent"]),
        "location": row.get("location", ""),
        "full_log": truncated,
    }


def main():
    parser = argparse.ArgumentParser(description="Dump annotated dataset rows into JSON files.")
    parser.add_argument("--dataset", type=Path, default=Path("data/dataset.csv"))
    parser.add_argument("--annotations", type=Path, default=Path("training_annotations.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/annotation_logs"))

    args = parser.parse_args()
    annotations = json.loads(args.annotations.read_text(encoding="utf-8"))
    dataset_rows = load_dataset(args.dataset)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for entry in annotations:
        dataset_id = entry["dataset_id"]
        row = dataset_rows.get(dataset_id)
        if not row:
            raise KeyError(f"No row for dataset_id {dataset_id}.")
        log = build_log(row)
        path = args.output_dir / f"{dataset_id}.json"
        path.write_text(json.dumps([log], indent=2), encoding="utf-8")
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
