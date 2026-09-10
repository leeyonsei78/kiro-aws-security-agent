"""CloudTrail 관련 컴플라이언스 체크."""

from __future__ import annotations

from typing import Any

from ..models import Severity
from .base import BaseComplianceCheck, CheckViolation


class CloudTrailEnabledCheck(BaseComplianceCheck):
    code = "CA-20"
    title = "다중 리전 CloudTrail 미구성"
    severity = Severity.HIGH
    service = "cloudtrail"
    category = "감사/로깅"
    remediation = "모든 리전을 포함하는(IsMultiRegionTrail=true) CloudTrail을 최소 1개 구성하고 로깅을 활성화하세요."
    standards = ("KISA CII(감사/로깅)", "CIS AWS 3.1")

    def run(self, client: Any) -> list[CheckViolation]:
        trails = client.describe_trails().get("trailList", [])
        # 다중 리전 trail이 하나라도 있으면 통과
        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        if not multi_region:
            return [CheckViolation(
                resource_id="account",
                detail="다중 리전 CloudTrail이 구성되지 않음",
                evidence={"trailCount": len(trails)},
            )]

        # 다중 리전 trail 중 실제 로깅이 켜진 것이 있는지 확인
        for t in multi_region:
            name = t.get("Name") or t.get("TrailARN", "")
            try:
                status = client.get_trail_status(Name=name)
                if status.get("IsLogging"):
                    return []  # 정상: 로깅 중인 다중 리전 trail 존재
            except Exception:  # noqa: BLE001
                continue
        return [CheckViolation(
            resource_id="account",
            detail="다중 리전 CloudTrail은 있으나 로깅이 비활성 상태",
        )]
