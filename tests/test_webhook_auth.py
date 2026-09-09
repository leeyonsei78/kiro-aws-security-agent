"""방화벽 webhook 인증 검증.

API 키/IP 허용목록 조합, API Gateway v1·v2 이벤트 형식, handler 통합(401/403/200)을 검증.
boto3 미설치 환경이라 stub 경로 필요(handler가 registry를 import).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.webhook_auth import authorize, extract_api_key, extract_source_ip
from agent import handler as H


# --- 이벤트 헬퍼 (v2 = HTTP API, v1 = REST API) ---
def ev_v2(api_key=None, source_ip="203.0.113.5", body="raw log"):
    headers = {}
    if api_key is not None:
        headers["X-Api-Key"] = api_key
    return {
        "requestContext": {"http": {"method": "POST", "sourceIp": source_ip}},
        "headers": headers,
        "body": body,
    }


def ev_v1(api_key=None, source_ip="203.0.113.5", body="raw log"):
    headers = {}
    if api_key is not None:
        headers["x-api-key"] = api_key  # 소문자 헤더도 처리돼야 함
    return {
        "httpMethod": "POST",
        "requestContext": {"identity": {"sourceIp": source_ip}},
        "headers": headers,
        "body": body,
    }


# --- 추출 유틸 ---
def test_extract_api_key_case_insensitive():
    assert extract_api_key({"headers": {"X-Api-Key": "k1"}}) == "k1"
    assert extract_api_key({"headers": {"x-api-key": "k2"}}) == "k2"
    assert extract_api_key({"headers": {}}) == ""
    print("OK extract api key (case-insensitive)")


def test_extract_source_ip_v1_v2_xff():
    assert extract_source_ip(ev_v2(source_ip="1.2.3.4")) == "1.2.3.4"
    assert extract_source_ip(ev_v1(source_ip="5.6.7.8")) == "5.6.7.8"
    assert extract_source_ip({"headers": {"X-Forwarded-For": "9.9.9.9, 10.0.0.1"}}) == "9.9.9.9"
    print("OK extract source ip (v1/v2/xff)")


# --- 인증 미설정: 통과(경고) ---
def test_auth_disabled_passes():
    cfg = Config(collectors=[], notifiers=["stdout"])  # 키/IP 미설정
    assert cfg.firewall_auth_configured is False
    assert authorize(ev_v2(), cfg).ok is True
    print("OK auth disabled -> pass")


# --- API 키 검사 ---
def test_api_key_valid():
    cfg = Config(collectors=[], notifiers=["stdout"], firewall_api_key="secret123")
    assert authorize(ev_v2(api_key="secret123"), cfg).ok is True
    print("OK api key valid")


def test_api_key_invalid():
    cfg = Config(collectors=[], notifiers=["stdout"], firewall_api_key="secret123")
    r = authorize(ev_v2(api_key="wrong"), cfg)
    assert r.ok is False and r.status == 401
    print("OK api key invalid -> 401")


def test_api_key_missing():
    cfg = Config(collectors=[], notifiers=["stdout"], firewall_api_key="secret123")
    r = authorize(ev_v2(api_key=None), cfg)
    assert r.ok is False and r.status == 401
    print("OK api key missing -> 401")


# --- IP 허용목록 ---
def test_ip_allow_exact():
    cfg = Config(collectors=[], notifiers=["stdout"], firewall_allowed_ips=["203.0.113.5"])
    assert authorize(ev_v2(source_ip="203.0.113.5"), cfg).ok is True
    print("OK ip exact allow")


def test_ip_allow_cidr():
    cfg = Config(collectors=[], notifiers=["stdout"], firewall_allowed_ips=["203.0.113.0/24"])
    assert authorize(ev_v2(source_ip="203.0.113.77"), cfg).ok is True
    print("OK ip cidr allow")


def test_ip_deny():
    cfg = Config(collectors=[], notifiers=["stdout"], firewall_allowed_ips=["10.0.0.0/8"])
    r = authorize(ev_v2(source_ip="203.0.113.5"), cfg)
    assert r.ok is False and r.status == 403
    print("OK ip deny -> 403")


# --- 키 + IP 동시 (둘 다 통과해야 ok) ---
def test_key_and_ip_both_required():
    cfg = Config(collectors=[], notifiers=["stdout"],
                 firewall_api_key="k", firewall_allowed_ips=["203.0.113.0/24"])
    assert authorize(ev_v2(api_key="k", source_ip="203.0.113.5"), cfg).ok is True
    # 키는 맞지만 IP 거부
    assert authorize(ev_v2(api_key="k", source_ip="8.8.8.8"), cfg).status == 403
    # IP는 맞지만 키 틀림
    assert authorize(ev_v2(api_key="x", source_ip="203.0.113.5"), cfg).status == 401
    print("OK key+ip both required")


# --- handler 통합 (환경변수로 설정 주입) ---
def _with_env(env, fn):
    old = {k: os.environ.get(k) for k in env}
    os.environ.update({k: v for k, v in env.items()})
    try:
        return fn()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_handler_rejects_bad_key():
    def run():
        return H.lambda_handler(ev_v2(api_key="wrong", body="devname=x type=utm subtype=ips level=alert srcip=1.2.3.4 attack=X"))
    resp = _with_env({"FIREWALL_API_KEY": "secret123"}, run)
    assert resp["statusCode"] == 401
    assert "error" in json.loads(resp["body"])
    print("OK handler rejects bad key -> 401")


def test_handler_accepts_good_key():
    def run():
        return H.lambda_handler(ev_v2(api_key="secret123", body='devname=x logid=1 type=utm subtype=ips level=alert srcip=1.2.3.4 attack=Backdoor'))
    resp = _with_env({"FIREWALL_API_KEY": "secret123", "NOTIFIERS": "stdout"}, run)
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["matched"] == 1
    print("OK handler accepts good key -> 200, matched=1")


if __name__ == "__main__":
    test_extract_api_key_case_insensitive()
    test_extract_source_ip_v1_v2_xff()
    test_auth_disabled_passes()
    test_api_key_valid()
    test_api_key_invalid()
    test_api_key_missing()
    test_ip_allow_exact()
    test_ip_allow_cidr()
    test_ip_deny()
    test_key_and_ip_both_required()
    test_handler_rejects_bad_key()
    test_handler_accepts_good_key()
    print("\nALL WEBHOOK AUTH TESTS PASSED")
