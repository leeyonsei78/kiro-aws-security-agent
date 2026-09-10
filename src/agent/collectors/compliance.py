"""컴플라이언스 점검 collector.

계정 구성을 점검 규칙(compliance/checks_*)으로 평가해 위반을 SecurityFinding으로 산출한다.
Security Hub/GuardDuty가 실시간으로 못 잡는 "구성 하드닝" 관점을 규칙 기반으로 커버한다.

점검 항목 체계는 KISA 기반 KESE-KIT(MIT)의 클라우드 점검 코드 방식을 참고했고,
점검 로직은 boto3로 새로 구현했다.

폴링 전용(구성 스캔). since는 무시한다.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Iterable

from ..compliance.base import BaseComplianceCheck, CheckViolation
from ..compliance.registry import all_checks
from ..models import Resource, SecurityFinding, utcnow
from .base import BaseCollector

logger = logging.getLogger(__name__)


class ComplianceCollector(BaseCollector):
    name = "compliance"

    def __init__(self, region=None, session=None, checks: list[BaseComplianceCheck] | None = None):
        super().__init__(region=region, session=session)
        self._checks = checks if checks is not None else all_checks()

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        # 서비스별 client를 한 번씩만 생성해 재사용
        clients: dict[str, object] = {}
        for check in self._checks:
            try:
                client = clients.get(check.service)
                if client is None:
                    client = self._make_client(check.service)
                    clients[check.service] = client
                violations = check.run(client)
            except Exception:  # noqa: BLE001 - 한 체크 실패가 전체를 막지 않도록
                logger.exception("compliance check '%s' 실행 실패", check.code)
                continue
            for v in violations:
                yield self._to_finding(check, v)

    def _to_finding(self, check: BaseComplianceCheck, v: CheckViolation) -> SecurityFinding:
        std = f" [{', '.join(check.standards)}]" if check.standards else ""
        return SecurityFinding(
            id=f"compliance:{check.code}:{v.resource_id or 'account'}",
            source=self.name,
            title=f"[{check.code}] {check.title}",
            description=f"{v.detail}{std}",
            severity=check.severity,
            finding_type=check.finding_type,
            region=self.region or "",
            resources=[Resource(
                type=v.resource_type,
                id=v.resource_id,
                region=self.region or "",
                details=v.evidence,
            )],
            created_at=utcnow(),
            updated_at=utcnow(),
            remediation=check.remediation,
            raw={
                "code": check.code,
                "category": check.category,
                "standards": list(check.standards),
                "evidence": v.evidence,
            },
        )
