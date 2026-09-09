"""Amazon GuardDuty collector.

폴링: list_detectors -> list_findings(updatedAt 필터) -> get_findings
실시간: EventBridge "GuardDuty Finding" 이벤트를 parse_event로 정규화
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterable

from ..models import Resource, SecurityFinding, Severity, parse_ts as _parse_ts
from .base import BaseCollector

logger = logging.getLogger(__name__)


class GuardDutyCollector(BaseCollector):
    name = "guardduty"

    def _client(self):
        return self._make_client("guardduty")

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        client = self._client()
        detector_ids = client.list_detectors().get("DetectorIds", [])
        if not detector_ids:
            logger.info("guardduty: 활성 detector 없음")
            return

        # updatedAt(epoch millis) >= since 인 미확인(archived=false) finding만
        since_ms = int(since.timestamp() * 1000)
        criteria = {
            "Criterion": {
                "updatedAt": {"GreaterThanOrEqual": since_ms},
                "service.archived": {"Eq": ["false"]},
            }
        }

        for detector_id in detector_ids:
            finding_ids = self._list_all_finding_ids(client, detector_id, criteria)
            for batch in _chunks(finding_ids, 50):  # get_findings는 최대 50개
                resp = client.get_findings(DetectorId=detector_id, FindingIds=batch)
                for raw in resp.get("Findings", []):
                    yield self._normalize(raw)

    def _list_all_finding_ids(self, client, detector_id: str, criteria: dict) -> list[str]:
        ids: list[str] = []
        paginator = client.get_paginator("list_findings")
        for page in paginator.paginate(DetectorId=detector_id, FindingCriteria=criteria):
            ids.extend(page.get("FindingIds", []))
        return ids

    def parse_event(self, event: dict[str, Any]) -> Iterable[SecurityFinding]:
        # EventBridge: detail-type == "GuardDuty Finding", detail == finding 본문
        detail = event.get("detail")
        if not detail:
            return
        yield self._normalize(detail)

    def _normalize(self, raw: dict[str, Any]) -> SecurityFinding:
        # GuardDuty severity는 0.1~8.9 float. Security Hub 정규화 점수는 0~10.
        gd_sev = float(raw.get("Severity", 0) or 0)
        resources: list[Resource] = []
        res = raw.get("Resource", {}) or {}
        res_type = res.get("ResourceType", "Unknown")
        # 대표 리소스 id 추출(타입별로 위치가 다름)
        res_id = (
            (res.get("InstanceDetails") or {}).get("InstanceId")
            or (res.get("AccessKeyDetails") or {}).get("AccessKeyId")
            or _first_s3_bucket_name(res)
            or ""
        )
        resources.append(
            Resource(type=res_type, id=res_id or "", region=raw.get("Region", ""), details=res)
        )

        return SecurityFinding(
            id=raw.get("Id", ""),
            source=self.name,
            title=raw.get("Title", raw.get("Type", "GuardDuty Finding")),
            description=raw.get("Description", ""),
            severity=Severity.from_score(gd_sev),
            severity_score=gd_sev,
            finding_type=raw.get("Type", ""),
            account_id=raw.get("AccountId", ""),
            region=raw.get("Region", ""),
            resources=resources,
            created_at=_parse_ts(raw.get("CreatedAt")),
            updated_at=_parse_ts(raw.get("UpdatedAt")),
            raw=raw,
        )


def _first_s3_bucket_name(res: dict[str, Any]) -> str:
    buckets = res.get("S3BucketDetails") or []
    if buckets and isinstance(buckets, list):
        return buckets[0].get("Name", "")
    return ""


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]
