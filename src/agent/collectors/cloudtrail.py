"""CloudTrail 이상 활동 collector.

Security Hub에 항상 집계되지 않는 "위험 관리 이벤트(management event)"를 직접 감지한다.
lookup_events(EventName별)로 지정된 위험 API 호출을 조회 후 정규화한다.

폴링: 위험 EventName 목록을 순회하며 lookup_events(StartTime=since)
실시간: EventBridge로 전달된 CloudTrail 이벤트(detail)를 parse_event로 정규화

주의: lookup_events는 LookupAttributes를 1개만 허용하므로 EventName마다 개별 조회한다.
      루트 사용자 활동은 EventName으로 못 거르므로 별도 조회 후 userIdentity로 필터.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Iterable

from ..models import Resource, SecurityFinding, Severity, parse_ts as _parse_ts
from .base import BaseCollector

logger = logging.getLogger(__name__)


# 위험 관리 이벤트 -> (심각도, 사유)
RISKY_EVENTS: dict[str, tuple[Severity, str]] = {
    # 감사/방어 기능 무력화
    "StopLogging": (Severity.CRITICAL, "CloudTrail 로깅 중지"),
    "DeleteTrail": (Severity.CRITICAL, "CloudTrail 삭제"),
    "UpdateTrail": (Severity.HIGH, "CloudTrail 설정 변경"),
    "DeleteFlowLogs": (Severity.HIGH, "VPC Flow Logs 삭제"),
    "DisableSecurityHub": (Severity.CRITICAL, "Security Hub 비활성화"),
    "DeleteDetector": (Severity.CRITICAL, "GuardDuty detector 삭제"),
    "StopMonitoringMembers": (Severity.HIGH, "GuardDuty 멤버 모니터링 중지"),
    # 자격증명/권한 변경
    "CreateAccessKey": (Severity.MEDIUM, "액세스 키 생성"),
    "CreateUser": (Severity.MEDIUM, "IAM 사용자 생성"),
    "AttachUserPolicy": (Severity.HIGH, "IAM 사용자에 정책 연결"),
    "PutUserPolicy": (Severity.HIGH, "IAM 인라인 정책 추가"),
    "CreateLoginProfile": (Severity.HIGH, "콘솔 로그인 프로파일 생성"),
    "DeactivateMFADevice": (Severity.HIGH, "MFA 디바이스 비활성화"),
    # 데이터/키 파괴
    "DeleteBucketPolicy": (Severity.HIGH, "S3 버킷 정책 삭제"),
    "PutBucketPolicy": (Severity.MEDIUM, "S3 버킷 정책 변경"),
    "ScheduleKeyDeletion": (Severity.HIGH, "KMS 키 삭제 예약"),
    "DisableKey": (Severity.HIGH, "KMS 키 비활성화"),
    # 네트워크 노출
    "AuthorizeSecurityGroupIngress": (Severity.MEDIUM, "SG 인바운드 규칙 추가"),
}

# 루트 사용자로 수행되면 그 자체로 위험한 것으로 간주(EventName 무관)
ROOT_ACTIVITY_SEVERITY = Severity.HIGH


class CloudTrailCollector(BaseCollector):
    name = "cloudtrail"

    def __init__(self, region: str | None = None, session: Any = None,
                 risky_events: dict[str, tuple[Severity, str]] | None = None) -> None:
        super().__init__(region=region, session=session)
        self.risky_events = risky_events or RISKY_EVENTS

    def _client(self):
        return self._make_client("cloudtrail")

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        client = self._client()
        for event_name, (severity, reason) in self.risky_events.items():
            paginator = client.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=since,
            )
            for page in pages:
                for ev in page.get("Events", []):
                    finding = self._normalize(ev, severity, reason)
                    if finding:
                        yield finding

    def parse_event(self, event: dict[str, Any]) -> Iterable[SecurityFinding]:
        # EventBridge CloudTrail 이벤트: detail이 곧 CloudTrail 레코드
        detail = event.get("detail")
        if not detail:
            return
        event_name = detail.get("eventName", "")
        entry = self.risky_events.get(event_name)
        if entry:
            severity, reason = entry
        elif self._is_root(detail):
            severity, reason = ROOT_ACTIVITY_SEVERITY, "루트 사용자 활동"
        else:
            return  # 관심 대상 아님
        f = self._normalize_record(detail, severity, reason)
        if f:
            yield f

    # --- 내부: lookup_events 항목 정규화 --------------------------------
    def _normalize(self, ev: dict[str, Any], severity: Severity, reason: str) -> SecurityFinding | None:
        # lookup_events 항목의 CloudTrailEvent는 JSON 문자열
        raw_record: dict[str, Any] = {}
        ct = ev.get("CloudTrailEvent")
        if ct:
            try:
                raw_record = json.loads(ct)
            except (ValueError, TypeError):
                raw_record = {}

        # 루트 사용자면 심각도 상향(관심 이벤트가 아니어도 root면 강조)
        if self._is_root(raw_record) and severity < ROOT_ACTIVITY_SEVERITY:
            severity = ROOT_ACTIVITY_SEVERITY
            reason = f"{reason} (루트 사용자)"

        return self._build(
            event_id=ev.get("EventId", ""),
            event_name=ev.get("EventName", raw_record.get("eventName", "")),
            username=ev.get("Username", ""),
            event_time=ev.get("EventTime"),
            severity=severity,
            reason=reason,
            record=raw_record,
            resources_hint=ev.get("Resources", []),
        )

    def _normalize_record(self, record: dict[str, Any], severity: Severity, reason: str) -> SecurityFinding | None:
        if self._is_root(record) and severity < ROOT_ACTIVITY_SEVERITY:
            severity = ROOT_ACTIVITY_SEVERITY
            reason = f"{reason} (루트 사용자)"
        return self._build(
            event_id=record.get("eventID", ""),
            event_name=record.get("eventName", ""),
            username=(record.get("userIdentity", {}) or {}).get("userName", ""),
            event_time=record.get("eventTime"),
            severity=severity,
            reason=reason,
            record=record,
            resources_hint=[],
        )

    def _build(self, event_id, event_name, username, event_time, severity, reason,
               record, resources_hint) -> SecurityFinding:
        identity = record.get("userIdentity", {}) or {}
        actor = username or identity.get("arn", "") or identity.get("type", "unknown")
        account_id = identity.get("accountId", record.get("recipientAccountId", ""))
        source_ip = record.get("sourceIPAddress", "")
        region = record.get("awsRegion", self.region or "")

        resources: list[Resource] = []
        for r in resources_hint or []:
            resources.append(Resource(
                type=r.get("ResourceType", "Unknown"),
                id=r.get("ResourceName", ""),
                region=region,
            ))
        if not resources:
            resources.append(Resource(type="AwsIamIdentity", id=actor, region=region))

        return SecurityFinding(
            id=event_id or f"ct:{event_name}:{event_time}",
            source=self.name,
            title=f"위험 API 호출: {event_name} ({reason})",
            description=(
                f"{reason}. eventName={event_name}, 주체={actor}, "
                f"sourceIP={source_ip or '-'}, region={region or '-'}."
            ),
            severity=severity,
            finding_type=f"SuspiciousActivity:CloudTrail/{event_name}",
            account_id=account_id or "",
            region=region,
            resources=resources,
            created_at=_parse_ts(event_time),
            updated_at=_parse_ts(event_time),
            remediation=(
                "해당 호출이 승인된 변경인지 확인하세요. 미승인 시 관련 자격증명을 비활성화하고, "
                "변경된 설정(로깅/정책/키)을 원복하세요."
            ),
            raw=record or {"EventName": event_name, "Username": username},
        )

    def _is_root(self, record: dict[str, Any]) -> bool:
        identity = record.get("userIdentity", {}) or {}
        return identity.get("type") == "Root"

