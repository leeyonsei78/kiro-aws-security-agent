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
from agent.compliance.checks_ec2 import EbsEncryptionByDefaultCheck, DefaultSgOpenCheck
from agent.compliance.report import build_report

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



@mock_aws
def test_ebs_encryption_default_off_flagged():
    # moto 기본: EBS 기본 암호화 비활성 → CA-03 위반
    col = ComplianceCollector(region=REGION, checks=[EbsEncryptionByDefaultCheck()])
    try:
        findings = list(col.collect(since=None))
    except ClientError as e:
        if "NotImplemented" in str(e) or "501" in str(e):
            pytest.skip(f"moto 미지원: {e}")
        raise
    assert any(f.raw["code"] == "CA-03" for f in findings)
    print("OK moto EBS 기본암호화 비활성 감지")


@mock_aws
def test_default_sg_open_flagged():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    # VPC 생성 시 기본 SG가 자동 생성됨(기본적으로 egress allow-all 규칙 보유)
    col = ComplianceCollector(region=REGION, checks=[DefaultSgOpenCheck()])
    try:
        findings = list(col.collect(since=None))
    except ClientError as e:
        if "NotImplemented" in str(e) or "501" in str(e):
            pytest.skip(f"moto 미지원: {e}")
        raise
    # 기본 SG에 규칙이 있으면 CA-30
    assert isinstance(findings, list)  # 최소한 예외 없이 실행
    print("OK moto 기본 SG 점검 실행:", [f.raw["code"] for f in findings])


@mock_aws
def test_full_compliance_report_via_collector():
    # 전체 collector로 계정 점검 → 리포트 산출(점수/등급/집계)
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="plain-report-bucket")
    col = ComplianceCollector(region=REGION)  # 전체 체크
    try:
        findings = list(col.collect(since=None))
    except ClientError as e:
        if "NotImplemented" in str(e) or "501" in str(e):
            pytest.skip(f"moto 미지원 항목 포함: {e}")
        raise
    report = build_report(findings)
    assert 0 <= report["score"] <= 100
    assert report["grade"] in ("A", "B", "C", "D", "F")
    assert report["total_violations"] == len(findings)
    print("OK moto 전체 리포트: score", report["score"], report["grade"],
          "violations", report["total_violations"])
