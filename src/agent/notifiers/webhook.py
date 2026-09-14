"""범용 Webhook notifier (구조화된 JSON POST).

Slack/Email이 '사람이 읽는' 알림이라면, 이 notifier는 임의의 HTTP 엔드포인트로
**구조화된 JSON**을 그대로 보낸다. n8n·Zapier·자체 수신 서버 등에서 이 JSON을
받아 Jira 티켓 생성, Notion 기록, 재알림 등 후속 자동화를 코드 수정 없이 붙일 수 있다.

외부 SDK 없이 표준 라이브러리(urllib)만 사용 → Lambda 의존성 최소화.
(설계 참고: ai-security-suite의 n8n Push 연동 아이디어를 이 프로젝트의
notifier 플러그인 구조로 새로 구현.)

payload 형식:
{
  "source": "aws-security-agent",
  "summary": "2건 MEDIUM=2",
  "count": 2,
  "severity_counts": {"MEDIUM": 2},
  "max_severity": "MEDIUM",
  "findings": [ {<SecurityFinding.to_dict()>}, ... ]
}
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from ..models import SecurityFinding
from .base import BaseNotifier

logger = logging.getLogger(__name__)

# 페이로드 비대화를 막기 위해 상세 finding은 상위 심각도 일부만 포함(요약 수치는 전체 반영).
_MAX_FINDINGS = 50


class WebhookNotifier(BaseNotifier):
    name = "webhook"
    channel_label = "Webhook (구조화 JSON)"

    def __init__(self, webhook_url: str, source: str = "aws-security-agent",
                 timeout: int = 10) -> None:
        self.webhook_url = webhook_url
        self.source = source
        self.timeout = timeout

    # --- payload 구성 -----------------------------------------------------
    def _severity_counts(self, findings: list[SecurityFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
        return counts

    def build_payload(self, findings: list[SecurityFinding]) -> dict:
        ordered = sorted(findings, key=lambda x: x.severity, reverse=True)
        max_sev = ordered[0].severity.name if ordered else None
        return {
            "source": self.source,
            "summary": self.summarize(findings),
            "count": len(findings),
            "severity_counts": self._severity_counts(findings),
            "max_severity": max_sev,
            "findings": [f.to_dict() for f in ordered[:_MAX_FINDINGS]],
        }

    def render(self, findings: list[SecurityFinding]) -> str:
        """실제 전송 없이 보낼 JSON을 미리보기(웹 UI 전용)."""
        if not findings:
            return "(전송할 finding 없음)"
        return json.dumps(self.build_payload(findings), ensure_ascii=False, indent=2)

    # --- 전송 -------------------------------------------------------------
    def notify(self, findings: list[SecurityFinding]) -> None:
        if not findings:
            return
        if not self.webhook_url:
            logger.warning("webhook: WEBHOOK_URL 미설정, 전송 생략")
            return
        self._post(self.build_payload(findings))

    def _post(self, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url, data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status >= 300:
                    logger.error("webhook: 전송 실패 status=%s", resp.status)
        except urllib.error.URLError as e:
            logger.error("webhook: 전송 예외 %s", e)
