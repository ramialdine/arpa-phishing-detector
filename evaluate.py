#!/usr/bin/env python3
"""
evaluate.py — Run the detector against the test dataset and report metrics.

Evaluates false positives, false negatives, and score distribution across
the benign / malicious / comparison label groups.

Usage:
    python evaluate.py
    python evaluate.py --dataset data/test_dataset.csv
    python evaluate.py --csv results.csv   # save results to CSV
"""

import argparse
import csv
import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))

from detector import analyze_url, analyze_hostname


# ---------------------------------------------------------------------------
# Verdict ordering for comparison
# ---------------------------------------------------------------------------
VERDICT_ORDER = {"low": 0, "medium": 1, "high": 2}
VERDICT_COLORS = {
    "low":    "\033[92m",   # green
    "medium": "\033[93m",   # yellow
    "high":   "\033[91m",   # red
    "reset":  "\033[0m",
}


def load_dataset(path: str) -> list[dict]:
    """Load test dataset CSV, skipping comment lines."""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(
            (line for line in f if not line.strip().startswith("#"))
        )
        for row in reader:
            if row.get("input", "").strip():
                rows.append(row)
    return rows


def run_evaluation(dataset: list[dict], verbose: bool = True) -> list[dict]:
    """Run detector against each sample, return annotated results."""
    results = []

    for row in dataset:
        inp = row["input"].strip()
        inp_type = row.get("type", "url").strip()
        expected = row.get("expected_verdict", "low").strip()
        label = row.get("label", "unknown").strip()
        is_email = row.get("is_email_delivered", "False").strip().lower() == "true"

        if inp_type == "url":
            result = analyze_url(inp, is_email_delivered=is_email, run_dns=False)
        else:
            result = analyze_hostname(inp, is_email_delivered=is_email, run_dns=False)

        got = result.verdict
        match = got == expected

        # Determine FP/FN/TP/TN relative to "high" being the positive class
        # Positive = expected high | Negative = expected low or medium
        is_positive_expected = expected == "high"
        is_positive_got = got == "high"

        if is_positive_expected and is_positive_got:
            outcome = "TP"
        elif is_positive_expected and not is_positive_got:
            outcome = "FN"
        elif not is_positive_expected and is_positive_got:
            outcome = "FP"
        else:
            outcome = "TN"

        results.append({
            "input": inp,
            "type": inp_type,
            "label": label,
            "expected": expected,
            "got": got,
            "score": result.score,
            "match": match,
            "outcome": outcome,
            "signals": ", ".join(s.name for s in result.triggered_signals),
            "notes": row.get("notes", ""),
        })

    return results


def print_report(results: list[dict]):
    """Print a formatted evaluation report to stdout."""
    width = 80
    
    print("\n" + "═" * width)
    print("  .arpa PHISHING DETECTOR — EVALUATION REPORT")
    print("═" * width)

    # Per-sample table
    print(f"\n{'INPUT':<55} {'EXP':<8} {'GOT':<8} {'SCORE':>5}  {'OUT'}")
    print("─" * width)

    for r in results:
        inp_display = r["input"][:52] + "..." if len(r["input"]) > 55 else r["input"]
        c = VERDICT_COLORS.get(r["got"], "")
        reset = VERDICT_COLORS["reset"]
        match_sym = "✓" if r["match"] else "✗"
        outcome_display = r["outcome"]

        print(
            f"{inp_display:<55} {r['expected']:<8} "
            f"{c}{r['got']:<8}{reset} {r['score']:>5}  "
            f"{match_sym} {outcome_display}"
        )

    # Aggregate metrics
    total = len(results)
    correct = sum(1 for r in results if r["match"])
    tp = sum(1 for r in results if r["outcome"] == "TP")
    tn = sum(1 for r in results if r["outcome"] == "TN")
    fp = sum(1 for r in results if r["outcome"] == "FP")
    fn = sum(1 for r in results if r["outcome"] == "FN")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = correct / total if total > 0 else 0

    print("\n" + "─" * width)
    print(f"  TOTAL SAMPLES : {total}")
    print(f"  CORRECT       : {correct}/{total} ({accuracy:.0%})")
    print(f"  TRUE POSITIVE : {tp}   (malicious correctly flagged HIGH)")
    print(f"  TRUE NEGATIVE : {tn}   (benign correctly not flagged HIGH)")
    print(f"  FALSE POSITIVE: {fp}   (benign incorrectly flagged HIGH)")
    print(f"  FALSE NEGATIVE: {fn}   (malicious missed / scored too low)")
    print()
    print(f"  PRECISION     : {precision:.2%}")
    print(f"  RECALL        : {recall:.2%}")
    print(f"  F1 SCORE      : {f1:.2%}")

    # Score distribution by label group
    print("\n  SCORE DISTRIBUTION BY LABEL GROUP:")
    by_label = defaultdict(list)
    for r in results:
        by_label[r["label"]].append(r["score"])
    
    for lbl, scores in sorted(by_label.items()):
        avg = sum(scores) / len(scores)
        mn  = min(scores)
        mx  = max(scores)
        print(f"    {lbl:<20} n={len(scores):>2}  avg={avg:>5.1f}  min={mn:>3}  max={mx:>3}")

    # FP/FN details
    fps = [r for r in results if r["outcome"] == "FP"]
    fns = [r for r in results if r["outcome"] == "FN"]

    if fps:
        print("\n  FALSE POSITIVES (benign flagged as high risk):")
        for r in fps:
            print(f"    → [{r['score']:>3}] {r['input'][:65]}")
            print(f"        Signals: {r['signals']}")

    if fns:
        print("\n  FALSE NEGATIVES (malicious scored too low):")
        for r in fns:
            print(f"    → [{r['score']:>3}] {r['input'][:65]}")
            print(f"        Signals: {r['signals']}")

    if not fps and not fns:
        print("\n  ✅ No false positives or false negatives detected.")

    print("═" * width + "\n")


def save_csv(results: list[dict], path: str):
    """Write results to a CSV file."""
    fieldnames = ["input", "type", "label", "expected", "got", "score", "match", "outcome", "signals", "notes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"  📊 Results saved to: {path}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate .arpa phishing detector against test dataset.")
    parser.add_argument("--dataset", default=os.path.join(os.path.dirname(__file__), "test_dataset.csv"), help="Path to test dataset CSV")
    parser.add_argument("--csv", metavar="OUTPUT_CSV", help="Save results to CSV file")
    args = parser.parse_args()

    print(f"\n  Loading dataset: {args.dataset}")
    dataset = load_dataset(args.dataset)
    print(f"  Loaded {len(dataset)} samples.")

    results = run_evaluation(dataset)
    print_report(results)

    if args.csv:
        save_csv(results, args.csv)


if __name__ == "__main__":
    main()
