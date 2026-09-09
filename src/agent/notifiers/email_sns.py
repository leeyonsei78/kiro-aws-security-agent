"""Email notifier via Amazon SNS.

SNS 토픽에 이메일 구독을 붙이면 이메일로 수신된다.
(SES 직접 발송 방식으로 교체 가능하도록 인터페이스 동일 유지)
"""

from __future__ import annotations

import logging

from ..aws import make_client
from ..models import SecurityFinding
from .base import BaseNotifier

logger = logging.getLogger(__name__)


class EmailSnsNotifier(BaseNotifier):
    name = "email_sns"
    channel_label = "Email (SNS)"

    def __init__(self, topic_arn: str, region: str | None = None, session=None) -> None:
        self.topic_arn = topic_arn
        self.region = region
        self._session = session

    def _client(self):
        return make_client("sns", self.region, self._session)

    def _subject(self, findings: list[SecurityFinding]) -> str:
        return f"[AWS 보안] {self.summarize(findings)}"[:100]  # SNS Subject 100자 제한

    def render(self, findings: list[SecurityFinding]) -> str:
        """실제 이메일 본문을 텍스트로 미리보기(전송하지 않음)."""
        if not findings:
            return "(전송할 finding 없음)"
        lines = [f"제목: {self._subject(findings)}", "",
                 f"AWS 보안 finding 감지 - {self.summarize(findings)}", ""]
        for f in sorted(findings, key=lambda x: x.severity, reverse=True):
            lines.append(self.format_line(f))
            if f.remediation:
                lines.append(f"    권고: {f.remediation}")
        return "\n".join(lines)

    def notify(self, findings: list[SecurityFinding]) -> None:
        if not findings:
            return
        if not self.topic_arn:
            logger.warning("email_sns: SNS_TOPIC_ARN 미설정, 전송 생략")
            return

        # render()와 동일 포맷이되, 제목 라인은 SNS Subject로 분리
        lines = [f"AWS 보안 finding 감지 - {self.summarize(findings)}", ""]
        for f in sorted(findings, key=lambda x: x.severity, reverse=True):
            lines.append(self.format_line(f))
            if f.remediation:
                lines.append(f"    권고: {f.remediation}")
        body = "\n".join(lines)

        self._client().publish(TopicArn=self.topic_arn, Subject=self._subject(findings), Message=body)
