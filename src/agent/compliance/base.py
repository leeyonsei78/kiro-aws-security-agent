"""컴플라이언스 체크 인터페이스.

새 점검 항목을 추가하려면 BaseComplianceCheck를 상속하고 registry에 등록한다.
각 체크는 고유 코드(예: CA-01), 제목, 심각도, 점검 서비스, run()을 제공한다.
run()은 위반이 있으면 CheckViolation 목록을, 없으면 빈 목록을 반환한다.

설계 참고: KISA 기반 KESE-KIT의 클라우드 점검 항목 코드 체계(CA-nn).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ..models import Severity


@dataclass
class CheckViolation:
    """단일 위반 사실. collector가 이를 SecurityFinding으로 정규화한다."""

    resource_id: str = ""          # 위반 리소스 식별자(버킷명, 사용자명 등)
    resource_type: str = "AwsAccount"
    detail: str = ""               # 위반 상세 설명
    evidence: dict[str, Any] = field(default_factory=dict)


class BaseComplianceCheck(abc.ABC):
    """모든 컴플라이언스 체크의 베이스.

    Attributes:
        code: 점검 항목 코드 (예: "CA-01").
        title: 짧은 제목.
        severity: 위반 시 심각도.
        service: 점검에 사용하는 boto3 서비스명 (client 생성용).
        remediation: 권고 조치.
        standards: 참조 표준/근거 (예: ["KISA CII", "CIS AWS"]).
    """

    code: str = "CA-00"
    title: str = "base check"
    severity: Severity = Severity.MEDIUM
    service: str = ""
    remediation: str = ""
    standards: tuple[str, ...] = ()

    @abc.abstractmethod
    def run(self, client: Any) -> list[CheckViolation]:
        """주어진 boto3 client로 점검 수행. 위반 목록 반환(없으면 빈 목록)."""
        raise NotImplementedError

    @property
    def finding_type(self) -> str:
        return f"Compliance:AWS/{self.code}"
