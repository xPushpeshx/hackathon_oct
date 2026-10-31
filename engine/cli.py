from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from engine.pipeline import run_scan


def cmd_scan(args: argparse.Namespace) -> int:
    payload = run_scan(
        args.target,
        args.profile,
        use_gcb=not args.no_gcb,
        mode=args.mode,
    )
    target_id = payload["target"]["target_id"]

    report_dir = Path("reports") / args.target
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Target: {target_id}")
    print(f"Discovered routes: {len(payload['routes'])}")
    print(f"Semgrep status: {payload['semgrep']['status']}")
    print(f"Static findings: {len(payload['findings'])}")
    print(f"ZAP status: {payload['zap']['status']}")
    print(f"Completed ZAP tasks: {sum(task['status'] == 'completed' for task in payload['tasks'])}")
    print(f"Untested ZAP tasks: {len(payload['zap']['untested_tasks'])}")
    if payload["semgrep"]["error"]:
        print(f"Semgrep: {payload['semgrep']['error']}")
    if payload["zap"]["error"]:
        print(f"ZAP: {payload['zap']['error']}")
    print(f"Report written to {report_path}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    print(f"Evaluation is not implemented yet (requested target: {args.target}).")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SAST/DAST correlation engine MVP")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run the scan pipeline for one target")
    scan_parser.add_argument("--target", required=True)
    scan_parser.add_argument("--profile", default="config/scan_profile.yaml")
    scan_parser.add_argument("--mode", choices=["default", "baseline", "planner"], default="default", help="Scan mode for ZAP execution")
    scan_parser.add_argument("--no-gcb", action="store_true", help="Skip GraphCodeBERT scoring and plan tasks without the model")
    scan_parser.set_defaults(func=cmd_scan)

    eval_parser = subparsers.add_parser("eval", help="Evaluation output for a target")
    eval_parser.add_argument("--target", required=True)
    eval_parser.set_defaults(func=cmd_eval)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
