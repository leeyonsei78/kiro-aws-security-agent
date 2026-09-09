"""Collector 인터페이스.

새 보안 소스를 추가하려면 이 클래스를 상속하고 registry에 등록하면 된다.
코어(core.py)는 개별 소스를 몰라도 이 인터페이스로만 상호작용한다.
"""

from __future__ import annotations

import abc
from datetime import datetime
from typing import Any, Iterable

from ..models import SecurityFinding


class BaseCollector(abc.ABC):
    """모든 collector의 베이스 클래스.

    구현체는 `name`과 `collect` / `parse_event`를 제공한다.
    """

    #: registry/설정에서 사용하는 고유 이름 (예: "guardduty")
    name: str = "base"

    def __init__(self, region: str | None = None, session: Any = None) -> None:
        self.region = region
        self._session = session

    def _make_client(self, service: str, region: str | None = None):
        """boto3 클라이언트 생성(공통). region 미지정 시 self.region 사용."""
        from ..aws import make_client

        return make_client(service, region if region is not None else self.region, self._session)

    # --- 폴링 모드 ---------------------------------------------------------
    @abc.abstractmethod
    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        """`since` 이후 갱신된 finding을 정규화된 형태로 반환(폴링)."""
        raise NotImplementedError

    # --- 실시간 이벤트 모드 -------------------------------------------------
    def parse_event(self, event: dict[str, Any]) -> Iterable[SecurityFinding]:
        """EventBridge 등에서 전달된 단일 이벤트를 finding으로 변환.

        기본 구현은 미지원(빈 목록). 실시간을 지원하는 소스에서 override.
        """
        return []
