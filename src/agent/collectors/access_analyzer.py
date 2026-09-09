"""IAM Access Analyzer collector.

외부(계정/조직 밖)에서 접근 가능한 리소스 finding을 수집한다.
Security Hub에 항상 집계되지 않는 "외부 공유" 신호를 직접 확보하는 것이 목적.

폴링: list_analyzers -> (각 analyzer) list_findings(status=ACTIVE) -> 정규화
실시간: EventBridge "Access Analyzer Finding" 이벤트 지원(parse_event)

심각도 정책(휴리스틱):
  - isPublic=True  -> HIGH (인터넷 공개)
  - 그 외 외부 공유 -> MEDIUM
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterable

from ..models import Resource, SecurityFinding, Severity, parse_ts as _parse_ts
from .base import BaseCollector

logger = logging.getLogger(__name__)


class AccessAnalyzerCollector(BaseCollector):
    name = "access_analyzer"

    def _client(self):
        return self._make_client("accessanalyzer")

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        client = self._client()
        analyzers = client.list_analyzers().get("analyzers", [])
        if not analyzers:
            logger.info("access_analyzer: 활성 analyzer 없음")
            return
        for analyzer in analyzers:
            arn = analyzer.get("arn")
            if not arn:
                continue
            paginator = client.get_paginator("list_findings")
            filt = {"status": {"eq": ["ACTIVE"]}}
            for page in paginator.paginate(analyzerArn=arn, filter=filt):
                for raw in page.get("findings", []):
                    yield self._normalize(raw)

    def parse_event(self, event: dict[str, Any]) -> Iterable[SecurityFinding]:
        detail = event.get("detail")
        if not detail:
            return
        # EventBridge Access Analyzer 이벤트는 detail에 finding 필드를 담는다.
        yield self._normalize(detail)

    def _normalize(self, raw: dict[str, Any]) -> SecurityFinding:
        is_public = bool(raw.get("isPublic", False))
        severity = Severity.HIGH if is_public else Severity.MEDIUM

        resource_type = raw.get("resourceType", "Unknown")
        resource_arn = raw.get("resource", "")
        actions = raw.get("action", []) or []
        principal = raw.get("principal", {}) or {}

        exposure = "인터넷 공개(Public)" if is_public else "외부 주체와 공유"
        title = f"{resource_type} 외부 접근 노출 - {exposure}"
        desc_parts = [f"리소스 {resource_arn} 가 {exposure} 상태입니다."]
        if actions:
            desc_parts.append(f"허용 액션: {', '.join(actions[:8])}")
        if principal:
            desc_parts.append(f"주체: {principal}")

        return SecurityFinding(
            id=raw.get("id", ""),
            source=self.name,
            title=title,
            description=" ".join(desc_parts),
            severity=severity,
            finding_type=f"ExternalAccess:{resource_type}/{'Public' if is_public else 'CrossAccount'}",
            account_id=(principal.get("AWS", "") if isinstance(principal, dict) else ""),
            region=self.region or "",
            resources=[
                Resource(
                    type=resource_type,
                    id=resource_arn,
                    region=self.region or "",
                    details={
                        "isPublic": is_public,
                        "action": actions,
                        "principal": principal,
                        "condition": raw.get("condition", {}),
                    },
                )
            ],
            created_at=_parse_ts(raw.get("createdAt")),
            updated_at=_parse_ts(raw.get("updatedAt") or raw.get("analyzedAt")),
            remediation=(
                "리소스 정책/ACL에서 외부 주체 또는 퍼블릭 접근 권한을 제거하거나, "
                "필요한 경우 Access Analyzer 아카이브 규칙으로 예외 처리하세요."
            ),
            raw=raw,
        )
