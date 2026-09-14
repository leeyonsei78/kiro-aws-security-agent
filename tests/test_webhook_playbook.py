"""webhook notifier + 대응 플레이북 단위 테스트.

표준 라이브러리만 사용(boto3 불필요). tests/_stubs 없이도 동작.
"""

import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.models import Resource, SecurityFinding, Severity
from agent.notifiers.webhook import WebhookNotifier
from agent.playbook import (
    _categorize,
    _is_blockable_external_ip,
    build_playbook,
    build_playbooks,
    format_playbooks_text,
)
from agent.registry import build_notifiers, capabilities


def _finding(**kw):
    base = dict(id="x", source="compliance", title="t", severity=Severity.MEDIUM)
    base.update(kw)
    return SecurityFinding(**base)


# --- webhook notifier ------------------------------------------------------
def test_webhook_payload_shape():
    fs = [
        _finding(id="CA-10", finding_type="Compliance:AWS/CA-10", severity=Severity.MEDIUM,
                 created_at=datetime.now(timezone.utc)),
        _finding(id="gd", source="guardduty", title="brute", severity=Severity.HIGH,
                 finding_type="UnauthorizedAccess:EC2/SSHBruteForce",
                 resources=[Resource(type="Instance", id="i-0abc")]),
    ]
    n = WebhookNotifier(webhook_url="http://x", source="test-agent")
    p = n.build_payload(fs)
    assert p["source"] == "test-agent"
    assert p["count"] == 2
    assert p["max_severity"] == "HIGH"          # HIGH 우선 정렬
    assert p["severity_counts"] == {"MEDIUM": 1, "HIGH": 1}
    assert p["findings"][0]["severity"] == "HIGH"
    assert "raw" not in p["findings"][0]         # raw 제외
    print("OK webhook payload shape")


def test_webhook_actual_post():
    received = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            received["body"] = json.loads(self.rfile.read(n))
            received["ct"] = self.headers.get("Content-Type")
            self.send_response(200)
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), H)  # 임의 포트
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        n = WebhookNotifier(webhook_url=f"http://127.0.0.1:{port}/hook")
        n.notify([_finding(id="CA-30", finding_type="Compliance:AWS/CA-30")])
    finally:
        import time
        time.sleep(0.2)
        srv.shutdown()
    assert received["ct"] == "application/json"
    assert received["body"]["count"] == 1
    print("OK webhook actual POST")


def test_webhook_empty_and_missing_url():
    # finding 없으면 아무 일도 안 함(예외 없이 통과)
    WebhookNotifier(webhook_url="http://x").notify([])
    # URL 없으면 전송 생략(예외 없이 통과)
    WebhookNotifier(webhook_url="").notify([_finding()])
    print("OK webhook empty/missing url")


def test_webhook_registered():
    cfg = Config(collectors=[], notifiers=[], slack_webhook_url="", sns_topic_arn="",
                 webhook_url="http://x")
    assert cfg.resolved_notifiers() == ["webhook"]
    built = [type(x).__name__ for x in build_notifiers(cfg)]
    assert built == ["WebhookNotifier"]
    assert any(x["name"] == "webhook" for x in capabilities()["notifiers"])
    print("OK webhook registered + auto-enabled")


# --- 대응 플레이북 ---------------------------------------------------------
def test_categorize():
    cases = {
        "Compliance:AWS/CA-30": "network_exposure",
        "Compliance:AWS/CA-10": "account_hardening",
        "Compliance:AWS/CA-01": "data_exposure",
        "Compliance:AWS/CA-20": "logging_integrity",
        "Compliance:AWS/ZT-02": "credential_exposure",
        "Compliance:AWS/SC-01": "supply_chain",
        "UnauthorizedAccess:EC2/SSHBruteForce": "brute_force",
        "Backdoor:EC2/C&CActivity.B": "malware_c2",
    }
    for ft, expect in cases.items():
        got = _categorize(_finding(finding_type=ft))
        assert got == expect, f"{ft} -> {got} (expect {expect})"
    # 미상 유형은 generic
    assert _categorize(_finding(finding_type="Nope", source="other")) == "generic"
    print("OK categorize", len(cases), "cases + generic")


def test_private_ip_guard():
    assert _is_blockable_external_ip("8.8.8.8") is True
    for bad in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", None, "not-an-ip"):
        assert _is_blockable_external_ip(bad) is False, bad
    print("OK private/invalid IP guard")


def test_playbook_public_ip_substitution():
    gd = _finding(
        id="gd", source="guardduty", title="brute", severity=Severity.HIGH,
        finding_type="UnauthorizedAccess:EC2/SSHBruteForce",
        raw={"Service": {"Action": {"NetworkConnectionAction": {
            "RemoteIpDetails": {"IpAddressV4": "45.83.66.10"}}}}},
    )
    pb = build_playbook(gd)
    assert pb["category"] == "brute_force"
    assert pb["attacker_ip"] == "45.83.66.10"
    cmds = [c for s in pb["steps"] for c in s["commands"]]
    assert any("45.83.66.10" in c for c in cmds), "공인 IP가 차단 명령에 치환돼야 함"
    # 4단계 구조
    assert [s["phase"] for s in pb["steps"]] == ["즉시조치", "조사", "봉쇄", "복구/재발방지"]
    print("OK playbook public IP substitution")


def test_playbook_private_ip_not_suggested():
    gd = _finding(
        id="gd2", source="guardduty", severity=Severity.HIGH,
        finding_type="UnauthorizedAccess:EC2/SSHBruteForce",
        raw={"Service": {"Action": {"NetworkConnectionAction": {
            "RemoteIpDetails": {"IpAddressV4": "10.0.0.9"}}}}},
    )
    pb = build_playbook(gd)
    assert pb["attacker_ip"] is None, "사설 IP는 차단 제안 대상이 아니어야 함"
    print("OK playbook private IP not suggested")


def test_playbook_text_and_list():
    fs = [
        _finding(id="CA-30", finding_type="Compliance:AWS/CA-30", remediation="규칙 제거"),
        _finding(id="gd", source="guardduty", severity=Severity.HIGH,
                 finding_type="UnauthorizedAccess:EC2/SSHBruteForce"),
    ]
    pbs = build_playbooks(fs)
    assert pbs[0]["severity"] == "HIGH"  # 심각도 높은 순
    text = format_playbooks_text(pbs)
    assert "대응 플레이북 2건" in text
    assert "참고용" in text  # safety 문구
    print("OK playbook text + list ordering")


if __name__ == "__main__":
    test_webhook_payload_shape()
    test_webhook_actual_post()
    test_webhook_empty_and_missing_url()
    test_webhook_registered()
    test_categorize()
    test_private_ip_guard()
    test_playbook_public_ip_substitution()
    test_playbook_private_ip_not_suggested()
    test_playbook_text_and_list()
    print("\n모든 테스트 통과")
