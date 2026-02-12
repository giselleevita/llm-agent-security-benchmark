from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import yaml


def load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def load_scenarios_map(scenarios_path: Path) -> Dict[str, str]:
    doc = yaml.safe_load(scenarios_path.read_text(encoding="utf-8"))
    return {s["id"]: s.get("category", "unknown") for s in (doc.get("scenarios") or [])}


def list_experiments(results_dir: Path) -> List[Path]:
    return sorted([p for p in results_dir.iterdir() if p.is_dir() and (p / "summary.json").exists()])


def md_table(rows: List[List[Any]], headers: List[str]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(x) for x in row) + " |")
    return "\n".join(out) + "\n"


def _comparison_rows(comparison: Dict[str, Any]) -> List[List[Any]]:
    rows: List[List[Any]] = []
    baselines = comparison.get("baselines") or {}
    for name in sorted(baselines.keys()):
        s = baselines[name]
        rows.append(
            [
                name,
                f"{s.get('asr', 0.0):.3f}",
                f"{s.get('leakage_rate', 0.0):.3f}",
                f"{s.get('task_success_rate', 0.0):.3f}",
                f"{s.get('false_positive_rate', 0.0):.3f}",
                f"{s.get('latency_ms_p95', 0.0):.0f}",
                (s.get("counts") or {}).get("total_runs", 0),
            ]
        )
    return rows


def _build_context(results_dir: Path, scenarios_path: Path) -> Dict[str, Any]:
    scenario_cat = load_scenarios_map(scenarios_path)

    comparison_path = results_dir / "summary_comparison.json"
    summary_path = results_dir / "summary.json"

    if comparison_path.exists():
        comparison = load_json(comparison_path)
        rows = _comparison_rows(comparison)
        threat_breakdown = ((comparison.get("threat_breakdown") or {}).get("B3") or {})
        threat_rows = [
            [
                threat,
                f"{m.get('asr', 0.0):.3f}",
                f"{m.get('leakage_rate', 0.0):.3f}",
                f"{m.get('task_success_rate', 0.0):.3f}",
            ]
            for threat, m in sorted(threat_breakdown.items())
        ]
        meta = comparison.get("meta", {})
        return {
            "summary_rows": rows,
            "threat_rows": threat_rows,
            "meta": meta,
            "source": "comparison",
        }

    # Fallback: experiment directory mode
    experiments = list_experiments(results_dir)
    rows: List[List[Any]] = []
    threat_rows: List[List[Any]] = []

    for exp in experiments:
        s = load_json(exp / "summary.json")
        rows.append(
            [
                exp.name,
                f"{s.get('asr', 0.0):.3f}",
                f"{s.get('leakage_rate', 0.0):.3f}",
                f"{s.get('task_success_rate', 0.0):.3f}",
                f"{s.get('false_positive_rate', 0.0):.3f}",
                f"{s.get('latency_ms_p95', 0.0):.0f}",
                (s.get("counts") or {}).get("total_runs", 0),
            ]
        )

        exp_run = exp / "run.json"
        if exp_run.exists():
            runs = (load_json(exp_run).get("runs") or [])
            by_cat: Dict[str, Dict[str, int]] = {}
            for record in runs:
                if not record.get("is_adversarial", False):
                    continue
                sid = record.get("scenario_id")
                cat = record.get("category") or scenario_cat.get(sid, "unknown")
                by_cat.setdefault(cat, {"n": 0, "attacks": 0})
                by_cat[cat]["n"] += 1
                if record.get("forbidden_executed", False):
                    by_cat[cat]["attacks"] += 1
            for cat, d in sorted(by_cat.items()):
                n = d["n"]
                asr = d["attacks"] / n if n else 0.0
                threat_rows.append([cat, f"{asr:.3f}", "n/a", "n/a"])

    meta = load_json(summary_path).get("meta", {}) if summary_path.exists() else {}
    return {"summary_rows": rows, "threat_rows": threat_rows, "meta": meta, "source": "experiments"}


def _plot(summary_rows: List[List[Any]], out_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover
        raise SystemExit("matplotlib not installed. Run: pip install -e '.[report]'") from exc

    names = [row[0] for row in summary_rows]
    asr = [float(row[1]) for row in summary_rows]
    leakage = [float(row[2]) for row in summary_rows]
    task_success = [float(row[3]) for row in summary_rows]
    false_pos = [float(row[4]) for row in summary_rows]
    p95 = [float(row[5]) for row in summary_rows]

    plots = [
        ("asr_comparison.png", "ASR by baseline/experiment", "ASR", asr),
        ("leakage_comparison.png", "Leakage by baseline/experiment", "Leakage", leakage),
        ("false_positive_comparison.png", "False Positive Rate", "False Positives", false_pos),
        ("p95_latency_comparison.png", "P95 Latency (ms)", "Latency (ms)", p95),
        ("task_success_comparison.png", "Task Success Rate", "Task Success", task_success),
    ]

    for filename, title, ylabel, values in plots:
        plt.figure(figsize=(7, 4))
        plt.bar(names, values)
        plt.title(title)
        plt.ylabel(ylabel)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(out_dir / filename)
        plt.close()


def _render_html(out_dir: Path, context: Dict[str, Any]) -> None:
    template_path = Path("scripts/templates/report.html.j2")
    charts = [
        "asr_comparison.png",
        "leakage_comparison.png",
        "false_positive_comparison.png",
        "p95_latency_comparison.png",
        "task_success_comparison.png",
    ]

    headers = ["Experiment", "ASR", "Leakage", "TaskSuccess", "FalsePos", "p95(ms)", "Runs"]
    threat_headers = ["Threat/Category", "ASR", "Leakage", "TaskSuccess"]

    try:
        from jinja2 import Template
    except Exception:  # pragma: no cover
        html = "<html><body><h1>Report</h1><p>Install Jinja2 for full templating.</p></body></html>"
        (out_dir / "index.html").write_text(html, encoding="utf-8")
        return

    template = Template(template_path.read_text(encoding="utf-8"))
    html = template.render(
        title="LLM Agent Security Benchmark Report",
        headers=headers,
        rows=context["summary_rows"],
        threat_headers=threat_headers,
        threat_rows=context["threat_rows"],
        meta=context.get("meta", {}),
        charts=charts,
    )
    (out_dir / "index.html").write_text(html, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--scenarios", default="benchmark/scenarios/scenarios.yaml")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--run-id", default="latest")
    parser.add_argument("--make-plots", action="store_true")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = results_dir / args.run_id / "report"
    out_dir.mkdir(parents=True, exist_ok=True)

    context = _build_context(results_dir, Path(args.scenarios))

    headers = ["Experiment", "ASR", "Leakage", "TaskSuccess", "FalsePos", "p95(ms)", "Runs"]
    (out_dir / "summary_table.md").write_text(
        md_table(context["summary_rows"], headers), encoding="utf-8"
    )

    threat_headers = ["Threat/Category", "ASR", "Leakage", "TaskSuccess"]
    (out_dir / "asr_by_category.md").write_text(
        md_table(context["threat_rows"], threat_headers), encoding="utf-8"
    )

    if args.make_plots:
        _plot(context["summary_rows"], out_dir)
    _render_html(out_dir, context)

    print(f"Wrote:\n- {out_dir / 'summary_table.md'}\n- {out_dir / 'asr_by_category.md'}")
    if args.make_plots:
        print(f"- plots in {out_dir}")
    print(f"- {out_dir / 'index.html'}")


if __name__ == "__main__":
    main()
