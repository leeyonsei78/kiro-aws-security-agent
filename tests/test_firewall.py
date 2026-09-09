"""써드파티 방화벽 수신 확장 검증: 벤더 파서, 자동 감지, 수신 collector, HTTP handler.

순수 파싱/라우팅 로직이라 boto3 불필요(단, import 체인 때문에 stub 경로 사용).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import run_firewall
from agent.models import Severity
from agent.firewall.registry import detect_parser, get_parser, available_vendors
from agent.firewall.fortinet import FortinetParser
from agent.firewall.paloalto import PaloAltoParser
from agent.firewall.checkpoint import CheckPointParser
from agent.firewall.cef import CefParser
from agent.handler import _is_http_event, _parse_firewall_payload


# --- 샘플 로그 라인 ---------------------------------------------------------
FORTINET = (
    'devname="FGT60F" logid="0419016384" type="utm" subtype="ips" level="alert" '
    'srcip=203.0.113.5 dstip=10.0.0.7 action="dropped" attack="Backdoor.Double.Door"'
)
PALOALTO_THREAT = (
    "1,2026/09/09 00:00:00,001901000001,THREAT,vulnerability,2049,2026/09/09 00:00:00,"
    "203.0.113.9,10.0.0.20,0.0.0.0,0.0.0.0,rule1,,,web-browsing,vsys1,trust,untrust,"
    "ethernet1/1,ethernet1/2,log-fwd,2026/09/09 00:00:00,12345,1,80,443,0,0,0x0,tcp,"
    "reset-both,\"evil.com/x\",SQL-Injection(9999),any,high,client-to-server"
)
CHECKPOINT = (
    'product="SmartDefense" action="Drop" src=203.0.113.11 dst=10.0.0.30 proto=tcp '
    'service=445 attack="Port Scan" severity="High"'
)
CEF = (
    "CEF:0|Palo Alto Networks|PAN-OS|10.1|spyware|Spyware Detected|8|"
    "src=203.0.113.20 dst=10.0.0.40 act=blocked"
)


# --- 벤더 파서 --------------------------------------------------------------
def test_fortinet_parse():
    f = FortinetParser().parse(FORTINET)
    assert f is not None
    assert f.severity == Severity.CRITICAL  # level=alert
    assert f.source == "firewall/fortinet"
    assert f.finding_type == "Firewall:Fortinet/ips/Threat"
    assert f.resources[0].id == "203.0.113.5"
    print("OK fortinet:", f.finding_type, f.severity.name)


def test_paloalto_parse():
    f = PaloAltoParser().parse(PALOALTO_THREAT)
    assert f is not None
    assert f.finding_type.startswith("Firewall:PaloAlto/THREAT")
    assert f.severity == Severity.HIGH  # 'high' 토큰
    # src/dst IP 추출
    ids = [r.id for r in f.resources]
    assert "203.0.113.9" in ids
    print("OK paloalto:", f.finding_type, f.severity.name)


def test_checkpoint_parse():
    f = CheckPointParser().parse(CHECKPOINT)
    assert f is not None
    assert f.severity == Severity.HIGH
    assert f.finding_type == "Firewall:CheckPoint/SmartDefense/Threat"
    assert f.resources[0].id == "203.0.113.11"
    print("OK checkpoint:", f.finding_type, f.severity.name)


def test_cef_parse():
    f = CefParser().parse(CEF)
    assert f is not None
    assert f.severity == Severity.HIGH  # CEF severity 8 -> HIGH
    assert f.finding_type.startswith("Firewall:CEF/")
    assert f.resources[0].id == "203.0.113.20"
    print("OK cef:", f.finding_type, f.severity.name)


# --- 자동 감지 --------------------------------------------------------------
def test_detect_parser():
    assert detect_parser(FORTINET).vendor == "fortinet"
    assert detect_parser(PALOALTO_THREAT).vendor == "paloalto"
    assert detect_parser(CHECKPOINT).vendor == "checkpoint"
    assert detect_parser(CEF).vendor == "cef"
    assert detect_parser("random noise line") is None
    print("OK auto-detect all vendors")


def test_kv_injection_safe():
    # 따옴표 안의 공백 분리 토큰이 별도 필드로 새지 않아야 함
    from agent.firewall.util import parse_kv
    d = parse_kv('action="drop x=y z=w" srcip=1.2.3.4')
    assert d["action"] == "drop x=y z=w"
    assert d["srcip"] == "1.2.3.4"
    assert "x" not in d and "z" not in d
    print("OK kv quoted-injection safe")


# --- 수신 collector + core ---------------------------------------------------
def test_run_firewall_mixed_lines():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.MEDIUM)
    payload = {"firewall_lines": [FORTINET, CHECKPOINT, CEF, "junk"]}
    result = run_firewall(payload, cfg)
    # fortinet(CRITICAL), checkpoint(HIGH), cef(HIGH) 통과, junk 스킵
    assert result["matched"] == 3
    print("OK run_firewall mixed:", result["matched"])


def test_run_firewall_forced_vendor():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.LOW)
    result = run_firewall({"firewall_raw": FORTINET, "vendor": "fortinet"}, cfg)
    assert result["matched"] == 1
    print("OK run_firewall forced vendor")


def test_run_firewall_severity_filter():
    # min_severity=CRITICAL이면 fortinet(CRITICAL)만 통과
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.CRITICAL)
    payload = {"firewall_lines": [FORTINET, CHECKPOINT, CEF]}
    result = run_firewall(payload, cfg)
    assert result["matched"] == 1
    print("OK run_firewall severity filter -> 1")


# --- HTTP handler 경로 ------------------------------------------------------
def test_is_http_event():
    assert _is_http_event({"httpMethod": "POST", "body": "x"}) is True
    assert _is_http_event({"requestContext": {"http": {"method": "POST"}}}) is True
    assert _is_http_event({"detail-type": "GuardDuty Finding"}) is False
    print("OK http event detection")


def test_parse_firewall_payload_json():
    event = {"httpMethod": "POST", "body": json.dumps({"firewall_lines": [FORTINET]})}
    payload = _parse_firewall_payload(event)
    assert payload["firewall_lines"] == [FORTINET]
    print("OK parse http json body")


def test_parse_firewall_payload_text_with_vendor_qs():
    event = {"httpMethod": "POST", "body": FORTINET,
             "queryStringParameters": {"vendor": "fortinet"}}
    payload = _parse_firewall_payload(event)
    assert payload["vendor"] == "fortinet"
    assert payload["firewall_raw"] == FORTINET
    print("OK parse http text body + vendor querystring")


def test_parse_firewall_payload_base64():
    import base64
    event = {"httpMethod": "POST", "isBase64Encoded": True,
             "body": base64.b64encode(FORTINET.encode()).decode()}
    payload = _parse_firewall_payload(event)
    assert payload["firewall_raw"] == FORTINET
    print("OK parse http base64 body")


if __name__ == "__main__":
    test_fortinet_parse()
    test_paloalto_parse()
    test_checkpoint_parse()
    test_cef_parse()
    test_detect_parser()
    test_kv_injection_safe()
    test_run_firewall_mixed_lines()
    test_run_firewall_forced_vendor()
    test_run_firewall_severity_filter()
    test_is_http_event()
    test_parse_firewall_payload_json()
    test_parse_firewall_payload_text_with_vendor_qs()
    test_parse_firewall_payload_base64()
    print("\nALL FIREWALL TESTS PASSED")
