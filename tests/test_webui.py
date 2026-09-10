"""웹 검증 UI 백엔드 검증.

라이브 서버 대신 preview_parse(핸들러가 호출하는 핵심)와 HTML/메타를 직접 검증.
boto3 미설치 환경이라 stub 경로 필요(firewall/event 파싱 경로만 사용).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import preview_parse
from agent.models import Severity
from agent.webui.page import INDEX_HTML


FORTINET = ('devname="FGT60F" logid="0419016384" type="utm" subtype="ips" level="alert" '
            'srcip=203.0.113.5 dstip=10.0.0.7 action="dropped" attack="Backdoor"')
CHECKPOINT = ('product="SmartDefense" action="Drop" src=203.0.113.11 dst=10.0.0.30 '
              'attack="Port Scan" severity="High"')

GUARDDUTY_EVENT = {
    "source": "aws.guardduty", "detail-type": "GuardDuty Finding",
    "detail": {"Id": "gd-1", "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
               "Title": "SSH brute force", "Severity": 8.0, "AccountId": "111122223333",
               "Region": "ap-northeast-2",
               "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-0abc"}}},
}


def test_preview_firewall_multi():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.MEDIUM)
    result = preview_parse(firewall_payload={"firewall_raw": FORTINET + "\n" + CHECKPOINT}, cfg=cfg)
    assert result["ok"] is True
    assert result["total"] == 2
    assert result["matched"] == 2  # CRITICAL + HIGH
    print("OK preview firewall multi:", result["total"], result["matched"])


def test_preview_firewall_filter():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.CRITICAL)
    result = preview_parse(firewall_payload={"firewall_raw": FORTINET + "\n" + CHECKPOINT}, cfg=cfg)
    # fortinet(CRITICAL)만 통과, checkpoint(HIGH) 제외
    assert result["matched"] == 1
    assert result["filtered_out"] == 1
    print("OK preview firewall filter:", result["matched"], result["filtered_out"])


def test_preview_firewall_forced_vendor():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.LOW)
    result = preview_parse(firewall_payload={"firewall_raw": FORTINET, "vendor": "fortinet"}, cfg=cfg)
    assert result["total"] == 1
    assert result["all_findings"][0]["source"] == "firewall/fortinet"
    print("OK preview firewall forced vendor")


def test_preview_event_guardduty():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.MEDIUM)
    result = preview_parse(event=GUARDDUTY_EVENT, cfg=cfg)
    assert result["ok"] is True
    assert result["matched"] == 1
    assert result["matched_findings"][0]["severity"] == "HIGH"
    print("OK preview event guardduty")


def test_preview_event_unsupported():
    cfg = Config(collectors=[], notifiers=["stdout"])
    result = preview_parse(event={"detail-type": "Scheduled Event"}, cfg=cfg)
    assert result["ok"] is False
    assert "supported" in result
    print("OK preview event unsupported ->", result["reason"])


def test_index_html_served():
    # HTML에 핵심 요소가 포함되는지(렌더 가능성 기초 확인)
    assert "<!DOCTYPE html>" in INDEX_HTML
    assert "/api/firewall" in INDEX_HTML
    assert "/api/event" in INDEX_HTML
    assert "/api/pipeline" in INDEX_HTML       # 전체 파이프라인 모드
    assert "전체 파이프라인" in INDEX_HTML       # 모드 토글
    assert "알림 미리보기" in INDEX_HTML         # 알림 결과 섹션
    assert "자동 대응" in INDEX_HTML             # 대응 결과 섹션
    assert "컴플라이언스 점검 항목" in INDEX_HTML  # 컴플라이언스 탭
    assert "showChecks" in INDEX_HTML            # 항목 목록 함수
    assert "showReport" in INDEX_HTML            # 리포트 함수
    assert "/api/compliance-report" in INDEX_HTML  # 리포트 엔드포인트
    assert "analyze()" in INDEX_HTML
    print("OK index html contains endpoints, pipeline mode, compliance tab/report & result sections")


def test_meta_includes_compliance_checks():
    # 서버 meta에 컴플라이언스 항목이 포함되는지(항목 카탈로그 노출)
    from agent.compliance.registry import all_checks
    checks = all_checks()
    assert len(checks) >= 6
    codes = {c.code for c in checks}
    assert {"CA-01", "CA-10", "CA-20"} <= codes
    print("OK compliance checks available:", sorted(codes))


if __name__ == "__main__":
    test_preview_firewall_multi()
    test_preview_firewall_filter()
    test_preview_firewall_forced_vendor()
    test_preview_event_guardduty()
    test_preview_event_unsupported()
    test_index_html_served()
    test_meta_includes_compliance_checks()
    print("\nALL WEBUI TESTS PASSED")
