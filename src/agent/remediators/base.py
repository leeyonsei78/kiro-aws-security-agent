"""Remediator 인터페이스 및 결과 모델.

설계 원칙 (안전 최우선):
  1. dry-run 기본값 True — 실제 변경은 명시적으로 켜야 한다.
  2. finding-type 화이트리스트 — 허용된 finding_type만 대응한다.
  3. 감사 로깅 — 모든 시도/성공/실패/스킵을 RemediationResult로 남긴다.
  4. 멱등/롤백 지향 — 가능한 되돌릴 수 있는 액션을 우선한다.

각 구현체는 `can_handle`(대응 가능 여부)와 `_apply`(실제/모의 액션)를 제공한다.
공통 흐름(화이트리스트 검사, dry-run 분기, 감사 로깅)은 `remediate`에서 처리한다.
"""

from __future__ import annotations

import abc
import enum
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

from ..models import SecurityFinding, utcnow

logger = logging.getLogger(__name__)


class RemediationStatus(str, enum.Enum):
    DRY_RUN = "DRY_RUN"        # dry-run 모드에서 계획만 산출
    APPLIED = "APPLIED"        # 실제 액션 수행 성공
    SKIPPED = "SKIPPED"        # 화이트리스트/조건 불충족으로 건너뜀
    FAILED = "FAILED"          # 액션 시도 중 오류
    NO_ACTION = "NO_ACTION"    # 대응 가능하나 이미 조치됨/변경 불필요


@dataclass
class RemediationAction:
    """수행(또는 계획)한 단일 액션의 서술."""

    description: str
    api: str = ""                       # 호출한(또는 호출할) AWS API
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationResult:
    """감사 로깅을 위한 대응 결과."""

    remediator: str
    finding_id: str
    finding_type: str
    status: RemediationStatus
    actions: list[RemediationAction] = field(default_factory=list)
    message: str = ""
    dry_run: bool = True
    timestamp: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["timestamp"] = self.timestamp.isoformat()
        return d


class BaseRemediator(abc.ABC):
    """모든 remediator의 베이스.

    Attributes:
        name: registry/설정에서 쓰는 고유 이름.
        supported_types: 이 remediator가 처리할 수 있는 finding_type 접두사 목록.
            (정확 일치가 아닌 startswith 매칭 — GuardDuty type이 계층적이기 때문)
    """

    name: str = "base"
    supported_types: tuple[str, ...] = ()

    def __init__(
        self,
        dry_run: bool = True,
        allowed_types: list[str] | None = None,
        region: str | None = None,
        session: Any = None,
    ) -> None:
        self.dry_run = dry_run
        # 설정으로 좁힌 화이트리스트. None이면 supported_types 전체 허용.
        self.allowed_types = allowed_types
        self.region = region
        self._session = session

    def _make_client(self, service: str, region: str | None = None):
        """boto3 클라이언트 생성(공통). region 미지정 시 self.region 사용."""
        from ..aws import make_client

        return make_client(service, region if region is not None else self.region, self._session)

    # --- 하위 구현이 제공 -------------------------------------------------
    def can_handle(self, finding: SecurityFinding) -> bool:
        """finding_type이 지원 목록에 매칭되는지(접두사)."""
        return any(finding.finding_type.startswith(t) for t in self.supported_types)

    @abc.abstractmethod
    def _plan(self, finding: SecurityFinding) -> list[RemediationAction]:
        """수행할 액션 계획을 산출(호출 없이). dry-run/실제 공통으로 사용."""
        raise NotImplementedError

    @abc.abstractmethod
    def _apply(self, finding: SecurityFinding, actions: list[RemediationAction]) -> None:
        """계획된 액션을 실제로 AWS에 적용(실행 모드에서만 호출)."""
        raise NotImplementedError

    # --- 공통 오케스트레이션 ---------------------------------------------
    def _type_allowed(self, finding: SecurityFinding) -> bool:
        if self.allowed_types is None:
            return True
        return any(finding.finding_type.startswith(t) for t in self.allowed_types)

    def remediate(self, finding: SecurityFinding) -> RemediationResult:
        base = dict(
            remediator=self.name,
            finding_id=finding.id,
            finding_type=finding.finding_type,
            dry_run=self.dry_run,
        )

        # 화이트리스트 강제
        if not self._type_allowed(finding):
            return RemediationResult(
                status=RemediationStatus.SKIPPED,
                message=f"finding_type '{finding.finding_type}' 화이트리스트 제외",
                **base,
            )

        try:
            actions = self._plan(finding)
        except Exception as e:  # noqa: BLE001
            logger.exception("remediator '%s' 계획 실패", self.name)
            return RemediationResult(
                status=RemediationStatus.FAILED, message=f"plan error: {e}", **base
            )

        if not actions:
            return RemediationResult(
                status=RemediationStatus.NO_ACTION, message="수행할 액션 없음", **base
            )

        if self.dry_run:
            result = RemediationResult(
                status=RemediationStatus.DRY_RUN,
                actions=actions,
                message="dry-run: 실제 변경 없음",
                **base,
            )
            logger.info("[REMEDIATION-AUDIT] %s", result.to_dict())
            return result

        try:
            self._apply(finding, actions)
            result = RemediationResult(
                status=RemediationStatus.APPLIED, actions=actions, message="적용 완료", **base
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("remediator '%s' 적용 실패", self.name)
            result = RemediationResult(
                status=RemediationStatus.FAILED, actions=actions, message=f"apply error: {e}", **base
            )

        logger.info("[REMEDIATION-AUDIT] %s", result.to_dict())
        return result
