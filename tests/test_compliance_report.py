"""추가 컴플라이언스 규칙(EC2/RDS/IAM) + 점수/리포트 요약 테스트.

가짜 client로 규칙을 검증하고, build_report/demo_report의 점수·집계를 검증한다.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.compliance.checks_ec2 import EbsEncryptionByDefaultCheck, DefaultSgOpenCheck
from agent.compliance.checks_rds import RdsPublicAccessCheck, RdsEncryptionCheck
from agent.compliance.checks_iam import IamMultipleActiveKeysCheck
from agent.compliance.registry import all_checks
from agent.compliance.report import build_report, demo_report, format_report_text
from agent.models import SecurityFinding, Severity, Resource


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


# --- EC2 ---
def test_ebs_encryption_default_off():
    c = EbsEncryptionByDefaultCheck()
    assert len(c.run(Fake(get_ebs_encryption_by_default=lambda: {"EbsEncryptionByDefault": False}))) == 1
    assert c.run(Fake(get_ebs_encryption_by_default=lambda: {"EbsEncryptionByDefault": True})) == []
    print("OK CA-03 EBS 기본암호화 감지")


def test_default_sg_open():
    c = DefaultSgOpenCheck()
    page = {"SecurityGroups": [{"GroupId": "sg-def", "VpcId": "vpc-1",
            "IpPermissions": [{"IpProtocol": "-1"}], "IpPermissionsEgress": []}]}
    v = c.run(Fake(**{"__pages__describe_security_groups": [page]}))
    assert len(v) == 1 and v[0].resource_id == "sg-def"
    # 규칙 없으면 통과
    page2 = {"SecurityGroups": [{"GroupId": "sg-def", "IpPermissions": [], "IpPermissionsEgress": []}]}
    assert c.run(Fake(**{"__pages__describe_security_groups": [page2]})) == []
    print("OK CA-30 기본 SG 개방 감지")


# --- RDS ---
def test_rds_public_access():
    c = RdsPublicAccessCheck()
    page = {"DBInstances": [{"DBInstanceIdentifier": "db1", "PubliclyAccessible": True},
                            {"DBInstanceIdentifier": "db2", "PubliclyAccessible": False}]}
    v = c.run(Fake(**{"__pages__describe_db_instances": [page]}))
    assert len(v) == 1 and v[0].resource_id == "db1"
    print("OK CA-40 RDS 퍼블릭 감지")


def test_rds_encryption():
    c = RdsEncryptionCheck()
    page = {"DBInstances": [{"DBInstanceIdentifier": "db1", "StorageEncrypted": False}]}
    v = c.run(Fake(**{"__pages__describe_db_instances": [page]}))
    assert len(v) == 1
    print("OK CA-41 RDS 암호화 감지")


# --- IAM 다중 활성 키 ---
def test_iam_multiple_active_keys():
    c = IamMultipleActiveKeysCheck()
    users_page = {"Users": [{"UserName": "u1"}]}
    keys = {"AccessKeyMetadata": [{"Status": "Active"}, {"Status": "Active"}]}
    v = c.run(Fake(**{"__pages__list_users": [users_page], "list_access_keys": lambda UserName: keys}))
    assert len(v) == 1 and v[0].resource_id == "u1"
    # 활성 1개면 통과
    keys1 = {"AccessKeyMetadata": [{"Status": "Active"}, {"Status": "Inactive"}]}
    v2 = c.run(Fake(**{"__pages__list_users": [users_page], "list_access_keys": lambda UserName: keys1}))
    assert v2 == []
    print("OK CA-13 다중 활성 키 감지")


# --- registry: 카테고리/코드 ---
def test_registry_has_categories():
    checks = all_checks()
    assert len(checks) >= 11
    cats = {c.category for c in checks}
    assert {"데이터 보호", "계정 관리", "네트워크", "감사/로깅"} <= cats
    # 모든 체크가 category를 가짐
    assert all(c.category for c in checks)
    print("OK registry 카테고리:", sorted(cats))


# --- 리포트 점수 ---
def _finding(code, category, sev):
    return SecurityFinding(
        id=f"compliance:{code}:x", source="compliance", title=f"[{code}] t",
        severity=sev, finding_type=f"Compliance:AWS/{code}",
        resources=[Resource(type="AwsAccount", id="x")],
        raw={"code": code, "category": category},
    )


def test_report_score_no_violations():
    r = build_report([])
    assert r["score"] == 100 and r["grade"] == "A" and r["total_violations"] == 0
    print("OK 리포트 위반 없음 → 100점 A")


def test_report_score_partial():
    # HIGH 1(15) + MEDIUM 1(5) = 20 감점 → 80점 B
    findings = [_finding("CA-01", "데이터 보호", Severity.HIGH),
                _finding("CA-02", "데이터 보호", Severity.MEDIUM)]
    r = build_report(findings)
    assert r["score"] == 80 and r["grade"] == "B"
    assert r["by_category"]["데이터 보호"]["violations"] == 2
    assert r["by_severity"]["HIGH"] == 1 and r["by_severity"]["MEDIUM"] == 1
    print("OK 리포트 부분 위반 → 80점 B")


def test_report_ignores_non_compliance():
    # source가 compliance가 아니면 리포트에서 제외
    other = SecurityFinding(id="gd-1", source="guardduty", title="x", severity=Severity.CRITICAL)
    r = build_report([other])
    assert r["total_violations"] == 0 and r["score"] == 100
    print("OK 리포트는 compliance source만 집계")


def test_report_floor_zero():
    # CRITICAL 3개 = 120 감점 → 하한 0
    findings = [_finding(f"CA-1{i}", "계정 관리", Severity.CRITICAL) for i in range(3)]
    r = build_report(findings)
    assert r["score"] == 0 and r["grade"] == "F"
    print("OK 리포트 점수 하한 0")


def test_demo_report():
    r = demo_report()
    assert r["total_violations"] == len(all_checks())
    assert r["score"] == 0  # 모든 체크 위반 가정 → 0점
    txt = format_report_text(r)
    assert "AWS 컴플라이언스 리포트" in txt and "등급" in txt
    print("OK demo_report:", r["score"], r["grade"], r["total_violations"])


if __name__ == "__main__":
    test_ebs_encryption_default_off()
    test_default_sg_open()
    test_rds_public_access()
    test_rds_encryption()
    test_iam_multiple_active_keys()
    test_registry_has_categories()
    test_report_score_no_violations()
    test_report_score_partial()
    test_report_ignores_non_compliance()
    test_report_floor_zero()
    test_demo_report()
    print("\nALL COMPLIANCE REPORT TESTS PASSED")
