"""AWS Security Hub collector.

폴링: get_findings(Filters: UpdatedAt DateRange, RecordState=ACTIVE)
실시간: EventBridge "Security Hub Findings - Imported" 이벤트를 정규화

Security Hub는 GuardDuty/Inspector/Macie 등 여러 소스를 ASFF로 집계하므로
단일 collector로도 다수 소스를 커버한다.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from ..models import Resource, SecurityFinding, Severity, parse_ts as _parse_ts
from .base import BaseCollector

logger = logging.getLogger(__name__)


class SecurityHubCollector(BaseCollector):
    name = "securityhub"

    def _client(self):
        return self._make_client("securityhub")

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        client = self._client()
        start = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        filters = {
            "UpdatedAt": [{"Start": start, "End": end}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        }
        try:
            paginator = client.get_paginator("get_findings")
            for page in paginator.paginate(Filters=filters, SortCriteria=[{"Field": "UpdatedAt", "SortOrder": "desc"}]):
                for raw in page.get("Findings", []):
                    yield self._normalize(raw)
        except client.exceptions.InvalidAccessException:
            logger.warning("securityhub: 이 리전에서 Security Hub가 활성화되지 않음")
            return

    def parse_event(self, event: dict[str, Any]) -> Iterable[SecurityFinding]:
        # detail.findings: ASFF finding 배열
        detail = event.get("detail", {}) or {}
        for raw in detail.get("findings", []):
            yield self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> SecurityFinding:
        severity_obj = raw.get("Severity", {}) or {}
        # ASFF: Normalized(0~100) 또는 Label 제공. Label 우선, 없으면 Normalized/10.
        label = severity_obj.get("Label")
        if label:
            sev = Severity.from_name(label)
            score = severity_obj.get("Normalized", 0) / 10.0
        else:
            score = severity_obj.get("Normalized", 0) / 10.0
            sev = Severity.from_score(score)

        resources: list[Resource] = []
        for r in raw.get("Resources", []) or []:
            resources.append(
                Resource(
                    type=r.get("Type", "Unknown"),
                    id=r.get("Id", ""),
                    region=r.get("Region", ""),
                    partition=r.get("Partition", "aws"),
                    details=r.get("Details", {}) or {},
                )
            )

        remediation = ""
        rem = raw.get("Remediation", {}) or {}
        rec = rem.get("Recommendation", {}) or {}
        if rec:
            remediation = rec.get("Text", "")
            if rec.get("Url"):
                remediation = f"{remediation} ({rec['Url']})".strip()

        return SecurityFinding(
            id=raw.get("Id", ""),
            source=self.name,
            title=raw.get("Title", "Security Hub Finding"),
            description=raw.get("Description", ""),
            severity=sev,
            severity_score=score or None,
            finding_type=(raw.get("Types") or [""])[0],
            account_id=raw.get("AwsAccountId", ""),
            region=raw.get("Region", ""),
            resources=resources,
            created_at=_parse_ts(raw.get("CreatedAt")),
            updated_at=_parse_ts(raw.get("UpdatedAt")),
            remediation=remediation,
            raw=raw,
        )
