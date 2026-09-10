"""SW 공급망(SC) + 제로트러스트(ZT) 컴플라이언스 규칙 단위 테스트.

가짜 client로 run()을 검증한다(boto3 불필요).
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.compliance.checks_supplychain import (
    EcrScanOnPushCheck, EcrTagImmutabilityCheck, LambdaDeprecatedRuntimeCheck,
    DEPRECATED_LAMBDA_RUNTIMES,
)
from agent.compliance.checks_zerotrust import (
    IamWildcardAdminPolicyCheck, IamStaleAccessKeyCheck,
)
from agent.compliance.registry import all_checks


class Fake:
    def __init__(self, **methods):
        self._m = methods
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


# --- SC: ECR ---
def test_ecr_scan_on_push_violation():
    c = EcrScanOnPushCheck()
    page = {"repositories": [
        {"repositoryName": "app", "imageScanningConfiguration": {"scanOnPush": False}},
        {"repositoryName": "safe", "imageScanningConfiguration": {"scanOnPush": True}},
    ]}
    v = c.run(Fake(**{"__pages__describe_repositories": [page]}))
    assert len(v) == 1 and v[0].resource_id == "app"
    print("OK SC-01 ECR scanOnPush 감지")


def test_ecr_tag_immutability_violation():
    c = EcrTagImmutabilityCheck()
    page = {"repositories": [
        {"repositoryName": "mut", "imageTagMutability": "MUTABLE"},
        {"repositoryName": "imm", "imageTagMutability": "IMMUTABLE"},
    ]}
    v = c.run(Fake(**{"__pages__describe_repositories": [page]}))
    assert len(v) == 1 and v[0].resource_id == "mut"
    print("OK SC-02 ECR 태그 불변성 감지")


# --- SC: Lambda ---
def test_lambda_deprecated_runtime():
    c = LambdaDeprecatedRuntimeCheck()
    page = {"Functions": [
        {"FunctionName": "old", "Runtime": "python3.8"},   # EOL
        {"FunctionName": "new", "Runtime": "python3.12"},  # 지원
        {"FunctionName": "img", "Runtime": None},          # 컨테이너 이미지(런타임 없음)
    ]}
    v = c.run(Fake(**{"__pages__list_functions": [page]}))
    assert len(v) == 1 and v[0].resource_id == "old"
    assert "python3.8" in DEPRECATED_LAMBDA_RUNTIMES
    print("OK SC-10 Lambda EOL 런타임 감지")


# --- ZT: 와일드카드 관리자 정책 ---
def test_zt_wildcard_admin_policy():
    c = IamWildcardAdminPolicyCheck()
    policies_page = {"Policies": [
        {"PolicyName": "admin", "Arn": "arn:aws:iam::1:policy/admin", "DefaultVersionId": "v1"},
        {"PolicyName": "scoped", "Arn": "arn:aws:iam::1:policy/scoped", "DefaultVersionId": "v1"},
    ]}
    docs = {
        "arn:aws:iam::1:policy/admin": {"PolicyVersion": {"Document": {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}},
        "arn:aws:iam::1:policy/scoped": {"PolicyVersion": {"Document": {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}}},
    }
    c_client = Fake(**{
        "__pages__list_policies": [policies_page],
        "get_policy_version": lambda PolicyArn, VersionId: docs[PolicyArn],
    })
    v = c.run(c_client)
    assert len(v) == 1 and v[0].resource_id == "admin"
    print("OK ZT-01 와일드카드 관리자 정책 감지")


def test_zt_wildcard_admin_ignores_conditioned():
    # Condition이 붙은 Allow:*:*는 완전 무제한이 아니므로 제외
    c = IamWildcardAdminPolicyCheck()
    page = {"Policies": [{"PolicyName": "cond", "Arn": "arn:aws:iam::1:policy/cond", "DefaultVersionId": "v1"}]}
    doc = {"PolicyVersion": {"Document": {"Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]}}}
    v = c.run(Fake(**{"__pages__list_policies": [page], "get_policy_version": lambda **kw: doc}))
    assert v == []
    print("OK ZT-01 Condition 있는 정책 제외")


# --- ZT: 오래된 액세스 키 ---
def test_zt_stale_access_key():
    c = IamStaleAccessKeyCheck()
    old_date = datetime.now(timezone.utc) - timedelta(days=200)
    new_date = datetime.now(timezone.utc) - timedelta(days=10)
    users_page = {"Users": [{"UserName": "u1"}, {"UserName": "u2"}]}
    def list_access_keys(UserName):
        if UserName == "u1":
            return {"AccessKeyMetadata": [{"Status": "Active", "CreateDate": old_date, "AccessKeyId": "AKIA1111"}]}
        return {"AccessKeyMetadata": [{"Status": "Active", "CreateDate": new_date, "AccessKeyId": "AKIA2222"}]}
    v = c.run(Fake(**{"__pages__list_users": [users_page], "list_access_keys": list_access_keys}))
    assert len(v) == 1 and v[0].resource_id == "u1"
    assert v[0].evidence["ageDays"] >= 90
    print("OK ZT-02 오래된 액세스 키 감지")


def test_zt_stale_key_ignores_inactive():
    c = IamStaleAccessKeyCheck()
    old_date = datetime.now(timezone.utc) - timedelta(days=300)
    users_page = {"Users": [{"UserName": "u1"}]}
    keys = {"AccessKeyMetadata": [{"Status": "Inactive", "CreateDate": old_date, "AccessKeyId": "AKIA"}]}
    v = c.run(Fake(**{"__pages__list_users": [users_page], "list_access_keys": lambda UserName: keys}))
    assert v == []
    print("OK ZT-02 비활성 키 제외")


# --- registry ---
def test_registry_has_new_categories():
    cats = {c.category for c in all_checks()}
    assert "공급망 보안" in cats and "제로트러스트" in cats
    codes = {c.code for c in all_checks()}
    assert {"SC-01", "SC-02", "SC-10", "ZT-01", "ZT-02"} <= codes
    assert len(codes) == len(all_checks())  # 코드 중복 없음
    print("OK registry 신규 카테고리/코드:", sorted(cats))


if __name__ == "__main__":
    test_ecr_scan_on_push_violation()
    test_ecr_tag_immutability_violation()
    test_lambda_deprecated_runtime()
    test_zt_wildcard_admin_policy()
    test_zt_wildcard_admin_ignores_conditioned()
    test_zt_stale_access_key()
    test_zt_stale_key_ignores_inactive()
    test_registry_has_new_categories()
    print("\nALL SUPPLYCHAIN/ZEROTRUST TESTS PASSED")
