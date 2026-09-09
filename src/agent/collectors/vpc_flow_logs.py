"""VPC Flow Logs 이상 트래픽 탐지 collector.

Security Hub에 없는 네트워크 원본 신호를 CloudWatch Logs Insights로 직접 집계한다.
탐지: 특정 소스 IP가 짧은 시간에 많은 REJECT를 유발(스캔/브루트포스 징후) 또는
      민감 포트로의 대량 접근 시도.

전제: VPC Flow Logs가 CloudWatch Logs 로그그룹에 적재되어 있어야 하고,
      로그그룹 이름을 FLOWLOGS_LOG_GROUP(설정)으로 지정해야 한다.

폴링: start_query -> (완료까지 폴링) get_query_results -> 정규화
실시간: 미지원(집계성 쿼리라 폴링에 적합)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Iterable

from ..models import Resource, SecurityFinding, Severity, utcnow
from .base import BaseCollector

logger = logging.getLogger(__name__)

# REJECT 집계 쿼리: 소스 IP별 reject 횟수와 대상 포트 수집
_REJECT_QUERY = """
fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter action = "REJECT"
| stats count(*) as rejectCount, count_distinct(dstPort) as distinctPorts by srcAddr
| sort rejectCount desc
| limit 50
"""


class VpcFlowLogsCollector(BaseCollector):
    name = "vpc_flow_logs"

    def __init__(
        self,
        region: str | None = None,
        session: Any = None,
        log_group: str = "",
        reject_threshold: int = 100,
        distinct_ports_threshold: int = 20,
        query_timeout_sec: int = 60,
    ) -> None:
        super().__init__(region=region, session=session)
        self.log_group = log_group
        self.reject_threshold = reject_threshold
        self.distinct_ports_threshold = distinct_ports_threshold
        self.query_timeout_sec = query_timeout_sec

    def _client(self):
        return self._make_client("logs")

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        if not self.log_group:
            logger.info("vpc_flow_logs: FLOWLOGS_LOG_GROUP 미설정, 건너뜀")
            return
        client = self._client()
        rows = self._run_query(client, since)
        for row in rows:
            finding = self._evaluate_row(row)
            if finding:
                yield finding

    def _run_query(self, client, since: datetime) -> list[dict[str, str]]:
        start = int(since.timestamp())
        end = int(datetime.now(timezone.utc).timestamp())
        resp = client.start_query(
            logGroupName=self.log_group,
            startTime=start,
            endTime=end,
            queryString=_REJECT_QUERY,
        )
        query_id = resp["queryId"]

        # 완료까지 폴링
        deadline = time.time() + self.query_timeout_sec
        while time.time() < deadline:
            result = client.get_query_results(queryId=query_id)
            status = result.get("status")
            if status == "Complete":
                return [self._row_to_dict(r) for r in result.get("results", [])]
            if status in ("Failed", "Cancelled", "Timeout"):
                logger.warning("vpc_flow_logs: 쿼리 상태 %s", status)
                return []
            time.sleep(1)
        logger.warning("vpc_flow_logs: 쿼리 타임아웃(%ss)", self.query_timeout_sec)
        # 타임아웃 시 진행 중 쿼리 정리(best-effort)
        try:
            client.stop_query(queryId=query_id)
        except Exception:  # noqa: BLE001
            pass
        return []

    def _row_to_dict(self, row: list[dict[str, str]]) -> dict[str, str]:
        # Insights 결과 행은 [{"field": "srcAddr", "value": "1.2.3.4"}, ...]
        return {cell.get("field", ""): cell.get("value", "") for cell in row}

    def _evaluate_row(self, row: dict[str, str]) -> SecurityFinding | None:
        src = row.get("srcAddr", "")
        if not src:
            return None
        reject_count = _to_int(row.get("rejectCount"))
        distinct_ports = _to_int(row.get("distinctPorts"))

        # 임계값 미만이면 finding 아님
        if reject_count < self.reject_threshold and distinct_ports < self.distinct_ports_threshold:
            return None

        # 심각도: 포트 스캔(다수 포트) 또는 대량 reject 강도에 따라
        if distinct_ports >= self.distinct_ports_threshold and reject_count >= self.reject_threshold:
            severity = Severity.HIGH
            pattern = "포트 스캔 + 대량 거부"
        elif distinct_ports >= self.distinct_ports_threshold:
            severity = Severity.MEDIUM
            pattern = "포트 스캔 의심(다수 포트 접근)"
        else:
            severity = Severity.MEDIUM
            pattern = "대량 연결 거부(브루트포스/스캔 의심)"

        return SecurityFinding(
            id=f"flowlogs:{src}",
            source=self.name,
            title=f"VPC Flow Logs 이상 트래픽: {src} ({pattern})",
            description=(
                f"소스 {src} 가 REJECT {reject_count}회, 고유 대상 포트 {distinct_ports}개를 "
                f"기록했습니다. {pattern}."
            ),
            severity=severity,
            finding_type=f"NetworkAnomaly:VpcFlowLogs/{'PortScan' if distinct_ports >= self.distinct_ports_threshold else 'RejectFlood'}",
            region=self.region or "",
            resources=[
                Resource(
                    type="RemoteIp",
                    id=src,
                    region=self.region or "",
                    details={"rejectCount": reject_count, "distinctPorts": distinct_ports},
                )
            ],
            created_at=utcnow(),
            updated_at=utcnow(),
            remediation=(
                "소스 IP가 정상 트래픽인지 확인하고, 악성으로 판단되면 NACL/WAF IPSet에 차단 추가를 검토하세요."
            ),
            raw={"srcAddr": src, "rejectCount": reject_count, "distinctPorts": distinct_ports},
        )


def _to_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
