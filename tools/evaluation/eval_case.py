"""Evaluate named case findings against a labeled, process-identity corpus.

The labels must be established independently of the rules. This reports
false alarms and misses; it does not convert scores into probabilities.
"""

import argparse
import json
from pathlib import Path


def evaluate(findings, labels):
    flagged = {f["subject"] for f in findings["findings"] if f["origin"] == "behavior"}
    seen = set()
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    rows = []
    for label in labels["labels"]:
        subject = label["subject"]
        if subject in seen:
            raise ValueError(f"duplicate label: {subject}")
        seen.add(subject)
        positive = bool(label["suspicious"])
        predicted = subject in flagged
        result = "tp" if positive and predicted else "fn" if positive else "fp" if predicted else "tn"
        counts[result] += 1
        rows.append({"subject": subject, "scenario": label.get("scenario", ""), "result": result})
    unlabelled = sorted(flagged - seen)
    if unlabelled:
        raise ValueError(f"unlabelled flagged subjects: {unlabelled}")
    return {"counts": counts, "scenarios": rows,
            "precision": counts["tp"] / (counts["tp"] + counts["fp"])
            if counts["tp"] + counts["fp"] else None,
            "recall": counts["tp"] / (counts["tp"] + counts["fn"])
            if counts["tp"] + counts["fn"] else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(json.loads(args.findings.read_text(encoding="utf-8-sig")),
                      json.loads(args.labels.read_text(encoding="utf-8-sig")))
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
