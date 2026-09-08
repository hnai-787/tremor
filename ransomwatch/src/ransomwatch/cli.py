"""ransomwatch: a passive host-based ransomware behavioral-detection engine.

    ransomwatch analyze trace.jsonl [--json] [--config path.yaml]
    ransomwatch monitor ~/Documents [--json] [--canary path ...]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from .config import load_config
from .detector import Alert, DetectionEngine
from .renderers import render_json, render_text
from .sources.replay import iter_replay_events


def _emit(alert: Alert, *, as_json: bool) -> None:
    print(render_json(alert) if as_json else render_text(alert))


def cmd_analyze(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    engine = DetectionEngine(config)

    event_count = 0
    last_timestamp = 0.0
    severity_counts: Counter[str] = Counter()
    alert_count = 0

    for event in iter_replay_events(args.log):
        event_count += 1
        last_timestamp = event.timestamp
        for alert in engine.observe(event):
            alert_count += 1
            if alert.severity:
                severity_counts[alert.severity] += 1
            _emit(alert, as_json=args.json)

    for alert in engine.flush(last_timestamp):
        alert_count += 1
        _emit(alert, as_json=args.json)

    if not args.json:
        print(
            f"\n{event_count} event(s) analyzed, {alert_count} alert(s) "
            f"({dict(severity_counts)})"
        )
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    from .sources.watchdog_source import run_live

    config = load_config(args.config)
    if args.canary:
        import dataclasses

        config = dataclasses.replace(config, canary_paths=tuple(args.canary))
    engine = DetectionEngine(config)

    def on_event(event) -> None:
        for alert in engine.observe(event):
            _emit(alert, as_json=args.json)

    try:
        run_live(args.path, on_event, sample_bytes=config.sample_bytes)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ransomwatch", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="emit newline-delimited JSON")
    common.add_argument("--config", default=None, help="path to a detection config YAML file")

    analyze = sub.add_parser(
        "analyze", parents=[common], help="analyze an offline JSONL event log"
    )
    analyze.add_argument("log", help="path to a .jsonl filesystem-event log")
    analyze.set_defaults(func=cmd_analyze)

    monitor = sub.add_parser(
        "monitor", parents=[common], help="monitor a live directory (requires the 'live' extra)"
    )
    monitor.add_argument("path", help="directory to watch recursively")
    monitor.add_argument(
        "--canary",
        action="append",
        default=[],
        help="a decoy file path that has no ordinary reason to change (repeatable)",
    )
    monitor.set_defaults(func=cmd_monitor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
