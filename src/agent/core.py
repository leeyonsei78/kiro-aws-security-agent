"""오케스트레이션: 수집 -> 정규화(collector 내부) -> 필터 -> 알림.

폴링 모드와 실시간 이벤트 모드 두 진입점을 제공한다.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import copy

from .config import Config
from .models import SecurityFinding, utcnow
from .registry import (
    EVENT_TYPE_TO_COLLECTOR,
    build_collector,
    build_collectors,
    build_notifiers,
    build_remediators,
)

logger = logging.getLogger(__name__)


def _filter(findings: list[SecurityFinding], cfg: Config) -> list[SecurityFinding]:
    """심각도 임계값 필터 + dedup_key 기준 중복 제거."""
    seen: set[str] = set()
    result: list[SecurityFinding] = []
    for f in findings:
        if f.severity < cfg.min_severity:
            continue
        if f.dedup_key in seen:
            continue
        seen.add(f.dedup_key)
        result.append(f)
    return result


def _remediate(findings: list[SecurityFinding], cfg: Config) -> list[dict]:
    """대응 가능한 finding에 대해 remediator 실행. 결과(감사 로그)를 반환.

    알림 이후 단계. 실패는 격리하며, 결과는 항상 감사 로그로 남긴다.
    """
    remediators = build_remediators(cfg)
    if not remediators:
        return []
    results: list[dict] = []
    for f in findings:
        for r in remediators:
            if not r.can_handle(f):
                continue
            try:
                result = r.remediate(f)
            except Exception:  # noqa: BLE001 - 한 대응 실패가 전체를 막지 않도록
                logger.exception("remediator '%s' 실행 실패 (finding=%s)", r.name, f.id)
                continue
            results.append(result.to_dict())
    return results


def _dispatch(findings: list[SecurityFinding], cfg: Config) -> dict:
    notifiers = build_notifiers(cfg)
    for n in notifiers:
        try:
            n.notify(findings)
        except Exception:  # noqa: BLE001 - 한 채널 실패가 전체를 막지 않도록
            logger.exception("notifier '%s' 전송 실패", n.name)

    remediations = _remediate(findings, cfg)

    return {
        "matched": len(findings),
        "notifiers": [n.name for n in notifiers],
        "remediations": remediations,
        "findings": [f.to_dict() for f in findings],
    }


def run_poll(cfg: Config) -> dict:
    """스케줄 폴링: lookback 윈도우 동안 갱신된 finding 수집 후 알림."""
    since = utcnow() - timedelta(minutes=cfg.lookback_minutes)
    collected: list[SecurityFinding] = []
    for collector in build_collectors(cfg):
        try:
            collected.extend(list(collector.collect(since)))
        except Exception:  # noqa: BLE001
            logger.exception("collector '%s' 수집 실패", collector.name)
    logger.info("수집 %d건 (since=%s)", len(collected), since.isoformat())

    matched = _filter(collected, cfg)
    return _dispatch(matched, cfg)


def run_event(event: dict, cfg: Config) -> dict:
    """실시간: EventBridge 이벤트 하나를 알맞은 collector로 파싱 후 알림."""
    detail_type = event.get("detail-type", "")
    collector_name = EVENT_TYPE_TO_COLLECTOR.get(detail_type)
    if not collector_name:
        logger.info("처리 대상 아님: detail-type=%r", detail_type)
        return {"matched": 0, "skipped": True, "detail_type": detail_type}

    collector = build_collector(collector_name, cfg)
    if not collector:
        return {"matched": 0, "skipped": True, "reason": "collector 없음"}

    findings = list(collector.parse_event(event))
    matched = _filter(findings, cfg)
    return _dispatch(matched, cfg)


def run_firewall(payload: dict, cfg: Config) -> dict:
    """써드파티 방화벽 수신: webhook/syslog payload를 firewall_syslog collector로 처리.

    payload 예: {"firewall_lines": [...], "vendor": "fortinet"} 또는 {"firewall_raw": "..."}
    """
    collector = build_collector("firewall_syslog", cfg)
    if not collector:
        return {"matched": 0, "skipped": True, "reason": "firewall collector 없음"}

    findings = list(collector.parse_event(payload))
    matched = _filter(findings, cfg)
    return _dispatch(matched, cfg)


def preview_parse(*, event: dict | None = None, firewall_payload: dict | None = None,
                  cfg: Config) -> dict:
    """알림/대응 없이 파싱→정규화→필터만 수행해 결과를 반환(웹 검증 UI 전용).

    event: EventBridge 스타일 이벤트(detail-type 기반 라우팅).
    firewall_payload: {"firewall_lines"/"firewall_raw", "vendor"}.
    반환: 모든 정규화 finding, 필터 통과 finding, dedup/필터로 걸러진 수.
    """
    collected: list[SecurityFinding] = []

    if firewall_payload is not None:
        collector = build_collector("firewall_syslog", cfg)
        if collector:
            collected.extend(list(collector.parse_event(firewall_payload)))
    elif event is not None:
        detail_type = event.get("detail-type", "")
        collector_name = EVENT_TYPE_TO_COLLECTOR.get(detail_type)
        if not collector_name:
            return {
                "ok": False,
                "reason": f"지원하지 않는 detail-type: {detail_type!r}",
                "supported": sorted(EVENT_TYPE_TO_COLLECTOR.keys()),
            }
        collector = build_collector(collector_name, cfg)
        if collector:
            collected.extend(list(collector.parse_event(event)))

    matched = _filter(collected, cfg)
    return {
        "ok": True,
        "total": len(collected),
        "matched": len(matched),
        "filtered_out": len(collected) - len(matched),
        "min_severity": cfg.min_severity.name,
        "all_findings": [f.to_dict() for f in collected],
        "matched_findings": [f.to_dict() for f in matched],
    }


def _parse_to_findings(event: dict | None, firewall_payload: dict | None,
                       cfg: Config) -> tuple[list[SecurityFinding], dict | None]:
    """이벤트/방화벽 payload를 정규화 finding 목록으로. 실패 시 (빈목록, 에러dict)."""
    collected: list[SecurityFinding] = []
    if firewall_payload is not None:
        collector = build_collector("firewall_syslog", cfg)
        if collector:
            collected.extend(list(collector.parse_event(firewall_payload)))
    elif event is not None:
        detail_type = event.get("detail-type", "")
        collector_name = EVENT_TYPE_TO_COLLECTOR.get(detail_type)
        if not collector_name:
            return [], {
                "ok": False,
                "reason": f"지원하지 않는 detail-type: {detail_type!r}",
                "supported": sorted(EVENT_TYPE_TO_COLLECTOR.keys()),
            }
        collector = build_collector(collector_name, cfg)
        if collector:
            collected.extend(list(collector.parse_event(event)))
    return collected, None


def preview_pipeline(*, event: dict | None = None, firewall_payload: dict | None = None,
                     cfg: Config) -> dict:
    """전체 파이프라인 미리보기(웹 UI 전용): 파싱→정규화→필터→알림포맷→대응 dry-run.

    실제 알림 전송이나 AWS 변경은 하지 않는다:
      - notifier는 render()로 "보낼 메시지"만 문자열로 생성
      - remediator는 강제 dry-run으로 "수행할 액션 계획"만 산출
    """
    collected, err = _parse_to_findings(event, firewall_payload, cfg)
    if err:
        return err

    matched = _filter(collected, cfg)

    # 1) 알림 미리보기 (전송 없음)
    notifications = []
    for n in build_notifiers(cfg):
        notifications.append({
            "notifier": n.name,
            "label": getattr(n, "channel_label", n.name),
            "message": n.render(matched),
        })

    # 2) 자동 대응 미리보기 (강제 dry-run — 실제 AWS 변경 없음)
    preview_cfg = copy.copy(cfg)
    preview_cfg.remediation_enabled = True
    preview_cfg.remediation_dry_run = True
    remediators = build_remediators(preview_cfg)
    remediations = []
    for f in matched:
        for r in remediators:
            try:
                if not r.can_handle(f):
                    continue
                result = r.remediate(f)  # dry-run이라 _plan만 실행
            except Exception as e:  # noqa: BLE001 - 미리보기이므로 오류도 표시
                remediations.append({
                    "remediator": r.name, "finding_id": f.id,
                    "status": "ERROR", "message": str(e), "actions": [],
                })
                continue
            remediations.append(result.to_dict())

    return {
        "ok": True,
        "total": len(collected),
        "matched": len(matched),
        "filtered_out": len(collected) - len(matched),
        "min_severity": cfg.min_severity.name,
        "all_findings": [f.to_dict() for f in collected],
        "matched_findings": [f.to_dict() for f in matched],
        "notifications": notifications,
        "remediations": remediations,
    }



def compliance_report(cfg: Config) -> dict:
    """compliance collector로 계정을 점검한 뒤 점수/리포트 요약을 반환.

    실제 AWS를 점검(collect)하므로 자격증명이 필요하다. 알림/대응은 하지 않는다.
    """
    from .compliance.report import build_report

    collector = build_collector("compliance", cfg)
    findings: list[SecurityFinding] = []
    if collector:
        try:
            findings = list(collector.collect(since=utcnow()))
        except Exception:  # noqa: BLE001
            logger.exception("compliance 점검 실패")
    return build_report(findings)
