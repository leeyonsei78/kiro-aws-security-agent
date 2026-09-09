"""추가 확장 3종 검증: S3 public block, WAF IPSet block, Access Analyzer collector.

boto3 실제 호출(_apply/collect의 AWS 부분)은 network 제한으로 미실행.
_plan/dry-run/정규화/화이트리스트 로직을 검증한다.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import _remediate
from agent.models import SecurityFinding, Severity, Resource
from agent.remediators.base import RemediationStatus
from agent.remediators.s3_public_block import S3PublicBlockRemediator
from agent.remediators.waf_ipset_block import WafIpSetBlockRemediator
from agent.collectors.access_analyzer import AccessAnalyzerCollector


# --- S3 public block --------------------------------------------------------
def _s3_public_finding() -> SecurityFinding:
    return SecurityFinding(
        id="sh-s3-1", source="securityhub", title="S3 bucket is public",
        severity=Severity.CRITICAL,
        finding_type="Effects/Data Exposure/Public S3 bucket",
        resources=[Resource(type="AwsS3Bucket", id="arn:aws:s3:::my-secret-bucket", region="ap-northeast-2")],
    )


def test_s3_plan_dry_run():
    r = S3PublicBlockRemediator(dry_run=True)
    f = _s3_public_finding()
    assert r.can_handle(f)
    result = r.remediate(f)
    assert result.status == RemediationStatus.DRY_RUN
    a = result.actions[0]
    assert a.api == "s3:PutPublicAccessBlock"
    assert a.params["Bucket"] == "my-secret-bucket"
    assert a.params["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"] is True
    print("OK s3 plan:", a.params["Bucket"])


def test_s3_skip_non_s3():
    r = S3PublicBlockRemediator(dry_run=True)
    f = SecurityFinding(
        id="x", source="securityhub", title="not s3", severity=Severity.HIGH,
        finding_type="Effects/Data Exposure/Other",
        resources=[Resource(type="AwsEc2Instance", id="i-1")],
    )
    assert r.can_handle(f) is False
    print("OK s3 ignores non-bucket resource")


def test_s3_arn_with_key():
    r = S3PublicBlockRemediator(dry_run=True)
    f = _s3_public_finding()
    f.resources = [Resource(type="AwsS3Bucket", id="arn:aws:s3:::bucket-x/some/key")]
    result = r.remediate(f)
    assert result.actions[0].params["Bucket"] == "bucket-x"
    print("OK s3 arn-with-key -> bucket name")


# --- WAF IPSet block --------------------------------------------------------
def _gd_ip_finding() -> SecurityFinding:
    return SecurityFinding(
        id="gd-2", source="guardduty", title="malicious caller",
        severity=Severity.HIGH,
        finding_type="UnauthorizedAccess:EC2/MaliciousIPCaller",
        raw={"Service": {"Action": {"AwsApiCallAction": {"RemoteIpDetails": {"IpAddressV4": "198.51.100.7"}}}}},
    )


def test_waf_plan_dry_run():
    r = WafIpSetBlockRemediator(ipset_name="blocklist", ipset_id="abc-123", scope="REGIONAL", dry_run=True)
    f = _gd_ip_finding()
    assert r.can_handle(f)
    result = r.remediate(f)
    assert result.status == RemediationStatus.DRY_RUN
    a = result.actions[0]
    assert a.api == "wafv2:UpdateIPSet"
    assert a.params["AddAddress"] == "198.51.100.7/32"
    assert a.params["Scope"] == "REGIONAL"
    print("OK waf plan:", a.params["AddAddress"])


def test_waf_no_ipset_configured():
    # IPSet 미설정이면 can_handle=False (안전)
    r = WafIpSetBlockRemediator(ipset_name="", ipset_id="", dry_run=True)
    assert r.can_handle(_gd_ip_finding()) is False
    print("OK waf skips when IPSet not configured")


# --- Access Analyzer collector ---------------------------------------------
def test_access_analyzer_normalize_public():
    c = AccessAnalyzerCollector(region="ap-northeast-2")
    raw = {
        "id": "aa-1", "resourceType": "AWS::S3::Bucket",
        "resource": "arn:aws:s3:::exposed-bucket",
        "isPublic": True, "status": "ACTIVE",
        "action": ["s3:GetObject"], "principal": {"AWS": "*"},
        "createdAt": "2026-09-09T00:00:00Z",
    }
    f = list(c.parse_event({"detail": raw}))[0]
    assert f.severity == Severity.HIGH  # public -> HIGH
    assert "ExternalAccess:AWS::S3::Bucket/Public" == f.finding_type
    assert f.resources[0].id == "arn:aws:s3:::exposed-bucket"
    print("OK access-analyzer public normalize:", f.finding_type)


def test_access_analyzer_normalize_crossaccount():
    c = AccessAnalyzerCollector(region="ap-northeast-2")
    raw = {
        "id": "aa-2", "resourceType": "AWS::IAM::Role",
        "resource": "arn:aws:iam::111122223333:role/shared",
        "isPublic": False, "status": "ACTIVE",
        "principal": {"AWS": "444455556666"},
    }
    f = list(c.parse_event({"detail": raw}))[0]
    assert f.severity == Severity.MEDIUM  # non-public -> MEDIUM
    assert f.finding_type.endswith("/CrossAccount")
    print("OK access-analyzer crossaccount normalize:", f.finding_type)


# --- core 통합 (여러 remediator 동시) --------------------------------------
def test_core_multiple_remediators():
    cfg = Config(
        collectors=[], notifiers=["stdout"],
        remediation_enabled=True, remediation_dry_run=True,
        remediators=["s3_public_block", "waf_ipset_block"],
        waf_ipset_name="blocklist", waf_ipset_id="abc-123",
    )
    findings = [_s3_public_finding(), _gd_ip_finding()]
    results = _remediate(findings, cfg)
    # s3 finding -> s3_public_block, gd ip finding -> waf_ipset_block
    remediators_fired = {r["remediator"] for r in results}
    assert "s3_public_block" in remediators_fired
    assert "waf_ipset_block" in remediators_fired
    assert all(r["status"] == "DRY_RUN" for r in results)
    print("OK core multiple remediators:", remediators_fired)


if __name__ == "__main__":
    test_s3_plan_dry_run()
    test_s3_skip_non_s3()
    test_s3_arn_with_key()
    test_waf_plan_dry_run()
    test_waf_no_ipset_configured()
    test_access_analyzer_normalize_public()
    test_access_analyzer_normalize_crossaccount()
    test_core_multiple_remediators()
    print("\nALL EXTENSION TESTS PASSED")
