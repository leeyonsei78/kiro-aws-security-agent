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

    #: 사람이 읽기 좋은 채널 설명(웹 미리보기 표시용)
    channel_label: str = "알림"

    @abc.abstractmethod
    def notify(self, findings: list[SecurityFinding]) -> None:
        """finding 목록을 채널로 전송."""
        raise NotImplementedError

    def render(self, findings: list[SecurityFinding]) -> str:
        """실제 전송 없이 이 채널로 보낼 메시지를 텍스트로 미리보기(웹 UI 전용).

        기본 구현은 요약 + 각 finding 한 줄. 채널별로 포맷이 다르면 override.
        """
        if not findings:
            return "(전송할 finding 없음)"
        lines = [self.summarize(findings), ""]
        for f in sorted(findings, key=lambda x: x.severity, reverse=True):
            lines.append(self.format_line(f))
        return "\n".join(lines)

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
