from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
import math
import yaml


def load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def load_scenarios_map(scenarios_path: Path) -> Dict[str, str]:
    doc = yaml.safe_load(scenarios_path.read_text(encoding="utf-8"))
    m = {}
    for s in (doc.get("scenarios") or []):
        m[s["id"]] = s.get("category", "unknown")
    return m


def list_experiments(results_dir: Path) -> List[Path]:
    return sorted([p for p in results_dir.iterdir() if p.is_dir() and (p / "summary.json").exists()])


def md_table(rows: List[List[Any]], headers: List[str]) -> str:
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out) + "\n"


def safe_pct(x: float) -> str:
    return f"{x*100:.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", default="results", help="Directory containing experiment subfolders")
    ap.add_argument("--scenarios", default="benchmark/scenarios/scenarios.yaml", help="Scenario YAML for category mapping")
    ap.add_argument("--out-dir", default="results/report", help="Where to write tables/plots")
    ap.add_argument("--make-plots", action="store_true", help="Generate matplotlib plots (requires extras: report)")
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenario_cat = load_scenarios_map(Path(args.scenarios))
    experiments = list_experiments(results_dir)

    # Summary table
    summary_rows = []
    for exp in experiments:
        s = load_json(exp / "summary.json")
        summary_rows.append([
            exp.name,
            f"{s.get('asr', 0.0):.3f}",
            f"{s.get('leakage_rate', 0.0):.3f}",
            f"{s.get('task_success_rate', 0.0):.3f}",
            f"{s.get('false_positive_rate', 0.0):.3f}",
            f"{s.get('latency_ms_p95', 0.0):.0f}",
            (s.get("counts") or {}).get("total_runs", 0),
        ])

    headers = ["Experiment", "ASR", "Leakage", "TaskSuccess", "FalsePos", "p95(ms)", "Runs"]
    (out_dir / "summary_table.md").write_text(md_table(summary_rows, headers), encoding="utf-8")

    # Category breakdown (ASR by category, only adversarial runs)
    cat_rows = []
    for exp in experiments:
        run_path = exp / "run.json"
        if not run_path.exists():
            continue
        runs_doc = load_json(run_path)
        runs = runs_doc.get("runs") or []

        # group by category for adversarial
        by_cat = {}
        for r in runs:
            if not r.get("is_adversarial", False):
                continue
            sid = r.get("scenario_id")
            cat = r.get("category") or scenario_cat.get(sid, "unknown")
            by_cat.setdefault(cat, {"n": 0, "attacks": 0})
            by_cat[cat]["n"] += 1
            if r.get("forbidden_executed", False):
                by_cat[cat]["attacks"] += 1

        for cat, d in sorted(by_cat.items()):
            n = d["n"]
            asr = (d["attacks"] / n) if n else 0.0
            cat_rows.append([exp.name, cat, n, d["attacks"], f"{asr:.3f}"])

    cat_headers = ["Experiment", "Category", "AdvRuns", "SuccessfulAttacks", "ASR"]
    (out_dir / "asr_by_category.md").write_text(md_table(cat_rows, cat_headers), encoding="utf-8")

    # Optional plots
    if args.make_plots:
        try:
            import matplotlib.pyplot as plt
        except Exception as e:
            raise SystemExit("matplotlib not installed. Run: pip install -e '.[report]'") from e

        # Plot 1: ASR per experiment
        names = [r[0] for r in summary_rows]
        asr_vals = [float(r[1]) for r in summary_rows]

        plt.figure()
        plt.bar(names, asr_vals)
        plt.xticks(rotation=45, ha="right")
        plt.ylabel("ASR")
        plt.title("Attack Success Rate by Experiment")
        plt.tight_layout()
        plt.savefig(out_dir / "asr_by_experiment.png")
        plt.close()

        # Plot 2: Leakage per experiment
        leak_vals = [float(r[2]) for r in summary_rows]
        plt.figure()
        plt.bar(names, leak_vals)
        plt.xticks(rotation=45, ha="right")
        plt.ylabel("Leakage Rate")
        plt.title("Leakage Rate by Experiment")
        plt.tight_layout()
        plt.savefig(out_dir / "leakage_by_experiment.png")
        plt.close()

        # Plot 3: Task success per experiment
        ts_vals = [float(r[3]) for r in summary_rows]
        plt.figure()
        plt.bar(names, ts_vals)
        plt.xticks(rotation=45, ha="right")
        plt.ylabel("Task Success Rate")
        plt.title("Task Success by Experiment")
        plt.tight_layout()
        plt.savefig(out_dir / "task_success_by_experiment.png")
        plt.close()

    print(f"Wrote:\n- {out_dir / 'summary_table.md'}\n- {out_dir / 'asr_by_category.md'}")
    if args.make_plots:
        print(f"- plots in {out_dir}")


if __name__ == "__main__":
    main()
