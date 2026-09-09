"""Stdout notifier - 로컬 테스트/디버깅용 기본 채널."""

from __future__ import annotations

import logging

from ..models import SecurityFinding
from .base import BaseNotifier

logger = logging.getLogger(__name__)


class StdoutNotifier(BaseNotifier):
    name = "stdout"

    def notify(self, findings: list[SecurityFinding]) -> None:
        if not findings:
            print("[security-agent] 새 finding 없음")
            return
        print(f"[security-agent] {self.summarize(findings)}")
        for f in sorted(findings, key=lambda x: x.severity, reverse=True):
            print("  " + self.format_line(f))
