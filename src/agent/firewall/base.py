"""방화벽 벤더 파서 인터페이스.

각 벤더는 raw 로그 라인(문자열)을 SecurityFinding으로 변환한다.
새 벤더 추가 = BaseFirewallParser 상속 + registry 등록.
"""

from __future__ import annotations

import abc
from typing import Any

from ..models import SecurityFinding, Severity


class BaseFirewallParser(abc.ABC):
    #: registry/설정에서 쓰는 고유 벤더 이름 (예: "fortinet")
    vendor: str = "base"

    @abc.abstractmethod
    def matches(self, line: str) -> bool:
        """이 파서가 처리할 수 있는 로그 라인인지 판별(벤더 자동 감지용)."""
        raise NotImplementedError

    @abc.abstractmethod
    def parse(self, line: str) -> SecurityFinding | None:
        """raw 로그 라인을 정규화. 관심 대상이 아니면 None."""
        raise NotImplementedError

    # 공통 헬퍼 ------------------------------------------------------------
    def _finding(
        self,
        *,
        event_id: str,
        title: str,
        severity: Severity,
        finding_type: str,
        description: str,
        src_ip: str = "",
        dst_ip: str = "",
        action: str = "",
        raw_fields: dict[str, Any] | None = None,
    ) -> SecurityFinding:
        from ..models import Resource, utcnow

        resources = []
        if src_ip:
            resources.append(Resource(type="RemoteIp", id=src_ip, details={"role": "source"}))
        if dst_ip:
            resources.append(Resource(type="RemoteIp", id=dst_ip, details={"role": "destination"}))

        desc = description
        if action:
            desc = f"{desc} (action={action})"

        return SecurityFinding(
            id=event_id,
            source=f"firewall/{self.vendor}",
            title=title,
            description=desc,
            severity=severity,
            finding_type=finding_type,
            resources=resources,
            created_at=utcnow(),
            updated_at=utcnow(),
            remediation=(
                "방화벽 정책과 위협 상세를 확인하고, 필요 시 소스 IP 차단(NACL/WAF IPSet) 및 "
                "영향 자원 점검을 수행하세요."
            ),
            raw=raw_fields or {"description": description[:500]},
        )
