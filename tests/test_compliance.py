"""컴플라이언스 체크 규칙 + collector 정규화 단위 테스트.

각 체크의 run()을 가짜 client(fake)로 검증한다(boto3 불필요).
collector는 페이크 체크를 주입해 정규화를 검증한다.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.compliance.base import BaseComplianceCheck, CheckViolation
from agent.compliance.checks_s3 import S3PublicAccessBlockCheck, S3EncryptionCheck
from agent.compliance.checks_iam import (
    IamPasswordPolicyCheck, IamRootAccessKeyCheck, IamUserMfaCheck,
)
from agent.compliance.checks_cloudtrail import CloudTrailEnabledCheck
from agent.compliance.registry import all_checks, checks_by_code
from agent.collectors.compliance import ComplianceCollector
from agent.models import Severity


# --- 가짜 client 헬퍼: 필요한 메서드만 람다/속성으로 흉내 ---
class Fake:
    def __init__(self, **methods):
        self._m = methods
        # 페이지네이터가 필요한 경우
    def __getattr__(self, name):
        if name in self._m:
            return self._m[name]
        raise AttributeError(name)

    def get_paginator(self, op):
        pages = self._m.get(f"__pages__{op}", [])
        class _P:
            def paginate(self_inner, **kw):
                return iter(pages)
        return _P()


def _boom(*a, **k):
    raise RuntimeError("NoSuchEntity")


# --- S3 CA-01 퍼블릭 액세스 ---
def test_s3_pab_violation_when_missing():
    c = S3PublicAccessBlockCheck()
    client = Fake(
        list_buckets=lambda: {"Buckets": [{"Name": "b1"}]},
        get_public_access_block=_boom,  # 미설정 → 위반
    )
    v = c.run(client)
    assert len(v) == 1 and v[0].resource_id == "b1"
    print("OK CA-01 위반 감지(PAB 미설정)")


def test_s3_pab_ok_when_all_true():
    c = S3PublicAccessBlockCheck()
    full = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    client = Fake(
        list_buckets=lambda: {"Buckets": [{"Name": "b1"}]},
        get_public_access_block=lambda Bucket: {"PublicAccessBlockConfiguration": full},
    )
    assert c.run(client) == []
    print("OK CA-01 통과(PAB 완전 설정)")


def test_s3_encryption_violation():
    c = S3EncryptionCheck()
    client = Fake(
        list_buckets=lambda: {"Buckets": [{"Name": "b1"}]},
        get_bucket_encryption=_boom,  # 미설정 → 위반
    )
    assert len(c.run(client)) == 1
    print("OK CA-02 위반 감지(암호화 미설정)")


# --- IAM ---
def test_iam_password_policy_weak():
    c = IamPasswordPolicyCheck()
    client = Fake(get_account_password_policy=lambda: {"PasswordPolicy": {
        "MinimumPasswordLength": 8, "RequireSymbols": False,
        "RequireNumbers": True, "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True}})
    v = c.run(client)
    assert len(v) == 1 and "최소 길이" in v[0].detail
    print("OK CA-10 약한 비밀번호 정책 감지")


def test_iam_password_policy_none():
    c = IamPasswordPolicyCheck()
    client = Fake(get_account_password_policy=_boom)  # 정책 없음
    assert len(c.run(client)) == 1
    print("OK CA-10 정책 부재 감지")


def test_iam_root_access_key():
    c = IamRootAccessKeyCheck()
    client = Fake(get_account_summary=lambda: {"SummaryMap": {"AccountAccessKeysPresent": 1}})
    v = c.run(client)
    assert len(v) == 1 and v[0].resource_id == "root"
    assert c.severity == Severity.CRITICAL
    # 없으면 통과
    client2 = Fake(get_account_summary=lambda: {"SummaryMap": {"AccountAccessKeysPresent": 0}})
    assert c.run(client2) == []
    print("OK CA-11 루트 액세스 키 감지")


def test_iam_user_mfa():
    c = IamUserMfaCheck()
    users_page = {"Users": [{"UserName": "console-user"}, {"UserName": "svc-user"}]}
    def get_login_profile(UserName):
        if UserName == "console-user":
            return {"LoginProfile": {}}
        raise RuntimeError("NoSuchEntity")  # svc-user는 콘솔 접근 없음
    client = Fake(**{
        "__pages__list_users": [users_page],
        "get_login_profile": get_login_profile,
        "list_mfa_devices": lambda UserName: {"MFADevices": []},  # 콘솔 사용자 MFA 없음
    })
    v = c.run(client)
    # console-user만 위반(svc-user는 콘솔 접근 없어 제외)
    assert len(v) == 1 and v[0].resource_id == "console-user"
    print("OK CA-12 콘솔 사용자 MFA 미설정 감지")


# --- CloudTrail ---
def test_cloudtrail_no_multiregion():
    c = CloudTrailEnabledCheck()
    client = Fake(describe_trails=lambda: {"trailList": [{"Name": "t", "IsMultiRegionTrail": False}]})
    assert len(c.run(client)) == 1
    print("OK CA-20 다중리전 미구성 감지")


def test_cloudtrail_ok():
    c = CloudTrailEnabledCheck()
    client = Fake(
        describe_trails=lambda: {"trailList": [{"Name": "t", "IsMultiRegionTrail": True}]},
        get_trail_status=lambda Name: {"IsLogging": True},
    )
    assert c.run(client) == []
    print("OK CA-20 통과(로깅 중 다중리전 trail)")


def test_cloudtrail_multiregion_but_not_logging():
    c = CloudTrailEnabledCheck()
    client = Fake(
        describe_trails=lambda: {"trailList": [{"Name": "t", "IsMultiRegionTrail": True}]},
        get_trail_status=lambda Name: {"IsLogging": False},
    )
    assert len(c.run(client)) == 1
    print("OK CA-20 로깅 비활성 감지")


# --- registry ---
def test_registry_codes_unique():
    codes = [c.code for c in all_checks()]
    assert len(codes) == len(set(codes)), "체크 코드 중복"
    assert "CA-01" in checks_by_code()
    print("OK registry 체크 코드 유니크:", codes)


# --- collector 정규화 (페이크 체크 주입) ---
class _FakeCheck(BaseComplianceCheck):
    code = "CA-99"
    title = "테스트 체크"
    severity = Severity.HIGH
    service = "s3"
    remediation = "고치세요"
    standards = ("KISA CII",)
    def run(self, client):
        return [CheckViolation(resource_id="b1", resource_type="AwsS3Bucket", detail="위반 상세")]


def test_collector_normalizes_violation(monkeypatch):
    col = ComplianceCollector(region="ap-northeast-2", checks=[_FakeCheck()])
    # _make_client가 boto3를 부르지 않도록 패치
    monkeypatch.setattr(col, "_make_client", lambda svc, region=None: object())
    findings = list(col.collect(since=None))
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "compliance"
    assert f.finding_type == "Compliance:AWS/CA-99"
    assert f.severity == Severity.HIGH
    assert f.title.startswith("[CA-99]")
    assert f.resources[0].id == "b1"
    assert "KISA CII" in f.description
    assert f.remediation == "고치세요"
    print("OK collector 정규화:", f.finding_type, f.severity.name)


def test_collector_isolates_check_error(monkeypatch):
    class Boom(_FakeCheck):
        code = "CA-98"
        def run(self, client):
            raise RuntimeError("check 폭발")
    col = ComplianceCollector(region="x", checks=[Boom(), _FakeCheck()])
    monkeypatch.setattr(col, "_make_client", lambda svc, region=None: object())
    findings = list(col.collect(since=None))
    # 하나가 터져도 나머지는 정상 산출
    assert len(findings) == 1 and findings[0].finding_type == "Compliance:AWS/CA-99"
    print("OK collector 체크 오류 격리")


if __name__ == "__main__":
    import types
    # 간이 monkeypatch (pytest 없이 직접 실행 지원)
    class MP:
        def setattr(self, obj, name, val): setattr(obj, name, val)
    test_s3_pab_violation_when_missing()
    test_s3_pab_ok_when_all_true()
    test_s3_encryption_violation()
    test_iam_password_policy_weak()
    test_iam_password_policy_none()
    test_iam_root_access_key()
    test_iam_user_mfa()
    test_cloudtrail_no_multiregion()
    test_cloudtrail_ok()
    test_cloudtrail_multiregion_but_not_logging()
    test_registry_codes_unique()
    test_collector_normalizes_violation(MP())
    test_collector_isolates_check_error(MP())
    print("\nALL COMPLIANCE TESTS PASSED")
