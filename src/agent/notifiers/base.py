"""Notifier 인터페이스.

새 알림 채널(PagerDuty, Teams 등)을 추가하려면 이 클래스를 상속하고
registry에 등록하면 된다.
"""

from __future__ import annotations

import abc

from ..models import SecurityFinding, Severity

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFORMATIONAL: "⚪",
}


class BaseNotifier(abc.ABC):
    #: registry/설정에서 사용하는 고유 이름 (예: "slack")
    name: str = "base"

    @abc.abstractmethod
    def notify(self, findings: list[SecurityFinding]) -> None:
        """finding 목록을 채널로 전송."""
        raise NotImplementedError

    # 공통 포맷 헬퍼 -------------------------------------------------------
    @staticmethod
    def summarize(findings: list[SecurityFinding]) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
        parts = [f"{k}={v}" for k, v in sorted(counts.items())]
        return f"{len(findings)}건 " + ", ".join(parts)

    @staticmethod
    def format_line(f: SecurityFinding) -> str:
        emoji = SEVERITY_EMOJI.get(f.severity, "")
        res = f.resources[0].id if f.resources and f.resources[0].id else "-"
        return (
            f"{emoji} [{f.severity.name}] {f.title} "
            f"(source={f.source}, account={f.account_id or '-'}, "
            f"region={f.region or '-'}, resource={res})"
        )
