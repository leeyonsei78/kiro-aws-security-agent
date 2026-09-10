"""moto 기반 컴플라이언스 collector 통합 테스트.

실제 boto3 호출 경로를 moto 가상 AWS로 검증한다:
  - S3 퍼블릭 액세스/암호화 (CA-01, CA-02)
  - IAM 루트키/비밀번호정책 (CA-10, CA-11)
  - CloudTrail 다중리전 (CA-20)

moto가 특정 API를 미지원하면 해당 assertion을 건너뛴다(코드 결함 아님).
"""

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from agent.collectors.compliance import ComplianceCollector
from agent.compliance.checks_s3 import S3PublicAccessBlockCheck, S3EncryptionCheck
from agent.compliance.checks_iam import IamRootAccessKeyCheck, IamPasswordPolicyCheck
from agent.compliance.checks_cloudtrail import CloudTrailEnabledCheck

REGION = "us-east-1"


def _codes(findings):
    return {f.raw["code"] for f in findings}


@mock_aws
def test_s3_checks_detect_unprotected_bucket():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="plain-bucket")  # PAB/암호화 없음

    col = ComplianceCollector(region=REGION, checks=[S3PublicAccessBlockCheck(), S3EncryptionCheck()])
    findings = list(col.collect(since=None))
    codes = _codes(findings)
    # moto 기본 버킷은 PAB 미설정 → CA-01, 암호화 미설정 → CA-02
    assert "CA-01" in codes or "CA-02" in codes
    print("OK moto S3 compliance:", sorted(codes))


@mock_aws
def test_s3_pab_ok_after_block():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="safe-bucket")
    s3.put_public_access_block(
        Bucket="safe-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
    )
    col = ComplianceCollector(region=REGION, checks=[S3PublicAccessBlockCheck()])
    findings = [f for f in col.collect(since=None) if f.resources[0].id == "safe-bucket"]
    assert findings == []  # PAB 설정됨 → 위반 없음
    print("OK moto S3 PAB 설정 후 통과")


@mock_aws
def test_iam_root_key_absent_by_default():
    # moto 새 계정은 루트 액세스 키 없음 → 위반 없어야
    col = ComplianceCollector(region=REGION, checks=[IamRootAccessKeyCheck()])
    try:
        findings = list(col.collect(since=None))
    except ClientError as e:
        if "NotImplemented" in str(e) or "501" in str(e):
            pytest.skip(f"moto 미지원: {e}")
        raise
    assert all(f.raw["code"] != "CA-11" for f in findings)
    print("OK moto IAM 루트키 부재")


@mock_aws
def test_iam_password_policy_missing_flagged():
    # moto 새 계정은 비밀번호 정책 없음 → CA-10 위반
    col = ComplianceCollector(region=REGION, checks=[IamPasswordPolicyCheck()])
    try:
        findings = list(col.collect(since=None))
    except ClientError as e:
        if "NotImplemented" in str(e) or "501" in str(e):
            pytest.skip(f"moto 미지원: {e}")
        raise
    assert any(f.raw["code"] == "CA-10" for f in findings)
    print("OK moto IAM 비밀번호 정책 부재 감지")


@mock_aws
def test_cloudtrail_missing_flagged():
    # trail 없음 → CA-20 위반
    col = ComplianceCollector(region=REGION, checks=[CloudTrailEnabledCheck()])
    try:
        findings = list(col.collect(since=None))
    except ClientError as e:
        if "NotImplemented" in str(e) or "501" in str(e):
            pytest.skip(f"moto 미지원: {e}")
        raise
    assert any(f.raw["code"] == "CA-20" for f in findings)
    print("OK moto CloudTrail 미구성 감지")
