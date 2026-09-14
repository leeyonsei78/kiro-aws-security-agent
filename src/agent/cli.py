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
from .core import compliance_report, run_event, run_poll
from .models import Severity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWS Security Monitoring Agent (local runner)")
    parser.add_argument("--lookback-minutes", type=int, help="폴링 조회 윈도우(분)")
    parser.add_argument("--min-severity", help="INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL")
    parser.add_argument("--collectors", help="쉼표구분 (예: guardduty,securityhub)")
    parser.add_argument("--event", help="EventBridge 이벤트 JSON 파일 경로(실시간 경로 테스트)")
    parser.add_argument("--compliance-report", action="store_true",
                        help="컴플라이언스 점검 후 점수/리포트 출력(AWS 자격증명 필요)")
    parser.add_argument("--academy", action="store_true",
                        help="화이트해커(블루팀) 양성 프로그램: 학습 모듈 목록/상세 출력")
    parser.add_argument("--module", help="특정 학습 모듈 상세(예: M01)")
    parser.add_argument("--list-labs", action="store_true", help="실습 랩 목록 출력")
    parser.add_argument("--lab", help="특정 실습 랩의 실행 계획 출력(예: LAB-SG-OPEN). 명령은 자동 실행하지 않음")
    parser.add_argument("--playbook", action="store_true",
                        help="컴플라이언스 점검 위반 각각에 대한 대응 플레이북(단계별 가이드) 출력. 명령은 자동 실행하지 않음")
    parser.add_argument("--json", action="store_true", help="리포트를 JSON으로 출력")
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

    # --- 화이트해커(블루팀) 양성 프로그램 (AWS 자격증명 불필요) ---
    if args.academy or args.module or args.list_labs or args.lab:
        from .academy import labs_summary, modules_summary, plan_lab
        from .academy.format import (
            format_lab_plan,
            format_labs_list,
            format_module_detail,
            format_modules_list,
        )

        if args.json:
            if args.lab:
                print(json.dumps(plan_lab(args.lab), ensure_ascii=False, indent=2))
            elif args.list_labs:
                print(json.dumps(labs_summary(), ensure_ascii=False, indent=2))
            else:
                print(json.dumps(modules_summary(), ensure_ascii=False, indent=2))
            return 0

        if args.module:
            print(format_module_detail(args.module))
        elif args.lab:
            print(format_lab_plan(args.lab))
        elif args.list_labs:
            print(format_labs_list())
        else:
            print(format_modules_list())
        return 0

    # --- 대응 플레이북: 컴플라이언스 위반별 단계별 대응 가이드 (AWS 자격증명 필요) ---
    if args.playbook:
        from datetime import timezone, datetime as _dt

        from .playbook import build_playbooks, format_playbooks_text
        from .registry import build_collector

        collector = build_collector("compliance", cfg)
        findings = []
        if collector:
            try:
                findings = list(collector.collect(since=_dt.now(timezone.utc)))
            except Exception as e:  # noqa: BLE001
                print(f"컴플라이언스 점검 실패(자격증명/권한 확인 필요): {e}", file=sys.stderr)
                return 1
        playbooks = build_playbooks(findings)
        if args.json:
            print(json.dumps(playbooks, ensure_ascii=False, indent=2))
        else:
            print(format_playbooks_text(playbooks))
        return 0

    if args.compliance_report:
        from .compliance.report import format_report_text

        report = compliance_report(cfg)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(format_report_text(report))
        return 0

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
