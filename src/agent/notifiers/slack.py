"""Slack notifier (Incoming Webhook).

외부 SDK 없이 표준 라이브러리(urllib)만 사용 -> Lambda 의존성 최소화.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error

from ..models import SecurityFinding
from .base import BaseNotifier, SEVERITY_EMOJI

logger = logging.getLogger(__name__)


class SlackNotifier(BaseNotifier):
    name = "slack"

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    def notify(self, findings: list[SecurityFinding]) -> None:
        if not findings:
            return
        if not self.webhook_url:
            logger.warning("slack: SLACK_WEBHOOK_URL 미설정, 전송 생략")
            return

        blocks = self._build_blocks(findings)
        payload = {
            "text": f"AWS 보안 알림: {self.summarize(findings)}",
            "blocks": blocks,
        }
        self._post(payload)

    def _build_blocks(self, findings: list[SecurityFinding]) -> list[dict]:
        blocks: list[dict] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🛡️ AWS 보안 finding 감지"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*요약:* {self.summarize(findings)}"},
            },
            {"type": "divider"},
        ]
        # Slack 블록 수 제한 고려: 상위 심각도 최대 20건만 상세 표기
        top = sorted(findings, key=lambda x: x.severity, reverse=True)[:20]
        for f in top:
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            res = f.resources[0].id if f.resources and f.resources[0].id else "-"
            text = (
                f"{emoji} *[{f.severity.name}] {f.title}*\n"
                f"> source: `{f.source}` | account: `{f.account_id or '-'}` | "
                f"region: `{f.region or '-'}`\n"
                f"> resource: `{res}`"
            )
            if f.description:
                desc = f.description[:280]
                text += f"\n> {desc}"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
        if len(findings) > len(top):
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"...외 {len(findings) - len(top)}건 더 있음"}
                    ],
                }
            )
        return blocks

    def _post(self, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status >= 300:
                    logger.error("slack: 전송 실패 status=%s", resp.status)
        except urllib.error.URLError as e:
            logger.error("slack: 전송 예외 %s", e)
