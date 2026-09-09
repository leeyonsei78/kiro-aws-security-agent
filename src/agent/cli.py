"""로컬 실행용 CLI.

예)
  python -m agent.cli --lookback-minutes 120 --min-severity HIGH
  python -m agent.cli --event event.json   # 저장된 EventBridge 이벤트로 실시간 경로 테스트
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import load_config
from .core import run_event, run_poll
from .models import Severity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWS Security Monitoring Agent (local runner)")
    parser.add_argument("--lookback-minutes", type=int, help="폴링 조회 윈도우(분)")
    parser.add_argument("--min-severity", help="INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL")
    parser.add_argument("--collectors", help="쉼표구분 (예: guardduty,securityhub)")
    parser.add_argument("--event", help="EventBridge 이벤트 JSON 파일 경로(실시간 경로 테스트)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    cfg = load_config()
    if args.lookback_minutes is not None:
        cfg.lookback_minutes = args.lookback_minutes
    if args.min_severity:
        cfg.min_severity = Severity.from_name(args.min_severity)
    if args.collectors:
        cfg.collectors = [c.strip() for c in args.collectors.split(",") if c.strip()]

    if args.event:
        with open(args.event, "r", encoding="utf-8") as fh:
            event = json.load(fh)
        result = run_event(event, cfg)
    else:
        result = run_poll(cfg)

    print(json.dumps({k: v for k, v in result.items() if k != "findings"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
