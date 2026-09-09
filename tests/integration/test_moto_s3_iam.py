"""moto 기반 S3 / IAM / Access Analyzer 통합 테스트.

  - S3PublicBlockRemediator._apply (put_public_access_block)
  - IamDisableKeyRemediator._apply (update_access_key)
  - AccessAnalyzerCollector.collect (list_analyzers → 빈 결과 graceful)
"""

import boto3
from moto import mock_aws

from agent.models import SecurityFinding, Severity, Resource
from agent.remediators.s3_public_block import S3PublicBlockRemediator
from agent.remediators.iam_disable_key import IamDisableKeyRemediator
from agent.collectors.access_analyzer import AccessAnalyzerCollector

REGION = "us-east-1"


@mock_aws
def test_s3_public_block_apply_real():
    s3 = boto3.client("s3", region_name=REGION)
    bucket = "my-exposed-bucket"
    s3.create_bucket(Bucket=bucket)

    finding = SecurityFinding(
        id="sh-s3", source="securityhub", title="S3 public",
        severity=Severity.CRITICAL, finding_type="Effects/Data Exposure/Public S3 bucket",
        resources=[Resource(type="AwsS3Bucket", id=f"arn:aws:s3:::{bucket}", region=REGION)],
    )

    r = S3PublicBlockRemediator(dry_run=False, region=REGION)
    assert r.can_handle(finding)
    result = r.remediate(finding)
    assert result.status.value == "APPLIED"

    # Public Access Block이 실제로 걸렸는지 확인
    conf = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert conf["BlockPublicAcls"] is True
    assert conf["IgnorePublicAcls"] is True
    assert conf["BlockPublicPolicy"] is True
    assert conf["RestrictPublicBuckets"] is True


@mock_aws
def test_iam_disable_key_apply_real():
    iam = boto3.client("iam", region_name=REGION)
    user = "alice"
    iam.create_user(UserName=user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    assert key["Status"] == "Active"

    finding = SecurityFinding(
        id="gd-iam", source="guardduty", title="creds exfil", severity=Severity.HIGH,
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        raw={"Resource": {"AccessKeyDetails": {
            "AccessKeyId": access_key_id, "UserName": user, "UserType": "IAMUser"}}},
    )

    r = IamDisableKeyRemediator(dry_run=False, region=REGION)
    assert r.can_handle(finding)
    result = r.remediate(finding)
    assert result.status.value == "APPLIED"

    # 키가 Inactive로 바뀌었는지 확인
    keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    target = next(k for k in keys if k["AccessKeyId"] == access_key_id)
    assert target["Status"] == "Inactive"


@mock_aws
def test_access_analyzer_collect_empty_real():
    # analyzer가 없을 때 collect가 예외 없이 빈 결과를 내는지(graceful) 검증
    collector = AccessAnalyzerCollector(region=REGION)
    findings = list(collector.collect(since=None))
    assert findings == []


@mock_aws
def test_access_analyzer_collect_with_analyzer_real():
    client = boto3.client("accessanalyzer", region_name=REGION)
    client.create_analyzer(analyzerName="acct-analyzer", type="ACCOUNT")
    collector = AccessAnalyzerCollector(region=REGION)
    # findings가 없어도 예외 없이 순회되어야 함 (analyzer는 존재)
    findings = list(collector.collect(since=None))
    assert isinstance(findings, list)
