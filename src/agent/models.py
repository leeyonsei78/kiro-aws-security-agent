"""Unified security finding data model.

모든 Collector는 소스별 raw finding을 이 공통 스키마로 정규화한다.
새 소스를 추가하더라도 하위(필터/알림) 로직은 이 모델만 알면 된다.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """정렬/비교가 쉽도록 정수 기반 심각도.

    IntEnum이라 MIN_SEVERITY 필터링 시 `finding.severity >= threshold` 로 비교 가능.
    """

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            return cls.INFORMATIONAL

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """AWS(GuardDuty/Security Hub)의 0~10 점수 → 심각도 구간 매핑.

        Security Hub Normalized severity 기준을 참고한 구간.
        """
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 1.0:
            return cls.LOW
        return cls.INFORMATIONAL


@dataclass
class Resource:
    """finding이 가리키는 AWS 리소스."""

    type: str = "Unknown"
    id: str = ""
    region: str = ""
    partition: str = "aws"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityFinding:
    """소스 독립적인 통합 보안 finding.

    Attributes:
        id: 소스 내에서의 고유 식별자.
        source: 어떤 collector가 생성했는지 (예: "guardduty", "securityhub").
        title: 짧은 제목.
        description: 상세 설명.
        severity: 통합 심각도.
        severity_score: 원본 점수(0~10), 있으면 보존.
        finding_type: 소스별 유형 문자열 (예: GuardDuty type).
        account_id: AWS 계정 ID.
        region: 발생 리전.
        resources: 관련 리소스 목록.
        created_at / updated_at: 타임스탬프.
        raw: 원본 finding(디버깅/추적용).
        remediation: 권고 조치 텍스트(있는 경우).
    """

    id: str
    source: str
    title: str
    severity: Severity
    description: str = ""
    severity_score: float | None = None
    finding_type: str = ""
    account_id: str = ""
    region: str = ""
    resources: list[Resource] = field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    remediation: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        """동일 finding 중복 알림을 막기 위한 키."""
        return f"{self.source}:{self.id}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["created_at"] = self.created_at.isoformat() if self.created_at else None
        d["updated_at"] = self.updated_at.isoformat() if self.updated_at else None
        # raw는 크고 노이즈가 많아 직렬화 기본 출력에서 제외
        d.pop("raw", None)
        return d


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: Any) -> datetime | None:
    """ISO8601 문자열 또는 datetime을 datetime으로 파싱. 실패 시 None.

    - 이미 datetime이면 그대로 반환.
    - 'Z' 접미사(UTC)를 '+00:00'으로 정규화.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
