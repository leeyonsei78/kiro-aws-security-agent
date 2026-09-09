"""boto3 없이 정규화/필터/알림 파이프라인을 검증하는 스모크 테스트.

네트워크(INTEGRATIONS_ONLY) 환경에서도 돌도록 collector의 AWS 호출은 우회하고,
실시간 이벤트(parse_event) 경로와 필터/알림 로직만 검증한다.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import run_event, _filter
from agent.models import Severity
from agent.collectors.guardduty import GuardDutyCollector
from agent.collectors.securityhub import SecurityHubCollector
from agent.notifiers.stdout import StdoutNotifier


# --- 샘플 EventBridge 이벤트 (AWS 실제 스키마 형태) --------------------------
GUARDDUTY_EVENT = {
    "source": "aws.guardduty",
    "detail-type": "GuardDuty Finding",
    "detail": {
        "Id": "gd-finding-1",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Title": "SSH brute force against i-0abc",
        "Description": "EC2 instance i-0abc is being probed via SSH.",
        "Severity": 8.0,
        "AccountId": "111122223333",
        "Region": "ap-northeast-2",
        "CreatedAt": "2026-09-09T00:00:00.000Z",
        "UpdatedAt": "2026-09-09T00:05:00.000Z",
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {"InstanceId": "i-0abc"},
        },
    },
}

SECURITYHUB_EVENT = {
    "source": "aws.securityhub",
    "detail-type": "Security Hub Findings - Imported",
    "detail": {
        "findings": [
            {
                "Id": "sh-finding-1",
                "Title": "S3 bucket is public",
                "Description": "Bucket allows public read.",
                "Severity": {"Label": "CRITICAL", "Normalized": 90},
                "Types": ["Effects/Data Exposure"],
                "AwsAccountId": "111122223333",
                "Region": "ap-northeast-2",
                "CreatedAt": "2026-09-09T00:00:00.000Z",
                "UpdatedAt": "2026-09-09T00:05:00.000Z",
                "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::my-bucket", "Region": "ap-northeast-2"}],
                "Remediation": {"Recommendation": {"Text": "Block public access", "Url": "https://example.com"}},
            },
            {
                "Id": "sh-finding-low",
                "Title": "Info finding",
                "Severity": {"Label": "LOW", "Normalized": 20},
                "Types": ["Software and Configuration Checks"],
                "AwsAccountId": "111122223333",
                "Region": "ap-northeast-2",
                "Resources": [],
            },
        ]
    },
}


def test_guardduty_normalize():
    findings = list(GuardDutyCollector().parse_event(GUARDDUTY_EVENT))
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "guardduty"
    assert f.severity == Severity.HIGH  # 8.0 -> HIGH
    assert f.resources[0].id == "i-0abc"
    print("OK guardduty normalize:", f.to_dict())


def test_securityhub_normalize():
    findings = list(SecurityHubCollector().parse_event(SECURITYHUB_EVENT))
    assert len(findings) == 2
    crit = [x for x in findings if x.severity == Severity.CRITICAL][0]
    assert crit.resources[0].id == "arn:aws:s3:::my-bucket"
    assert "Block public access" in crit.remediation
    print("OK securityhub normalize:", [x.severity.name for x in findings])


def test_filter_min_severity():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.HIGH)
    findings = list(SecurityHubCollector().parse_event(SECURITYHUB_EVENT))
    kept = _filter(findings, cfg)
    # CRITICAL만 통과, LOW 제외
    assert len(kept) == 1
    assert kept[0].severity == Severity.CRITICAL
    print("OK filter min_severity=HIGH -> kept", len(kept))


def test_dedup():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.LOW)
    findings = list(GuardDutyCollector().parse_event(GUARDDUTY_EVENT)) * 3
    kept = _filter(findings, cfg)
    assert len(kept) == 1  # 동일 dedup_key 3개 -> 1개
    print("OK dedup 3->1")


def test_run_event_end_to_end():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.MEDIUM)
    result = run_event(SECURITYHUB_EVENT, cfg)
    assert result["matched"] == 1  # CRITICAL만 (LOW 제외)
    assert "stdout" in result["notifiers"]
    print("OK end-to-end run_event:", result["matched"], result["notifiers"])


def test_run_event_unknown_type_skipped():
    cfg = Config(collectors=[], notifiers=["stdout"])
    result = run_event({"detail-type": "Scheduled Event", "source": "aws.events"}, cfg)
    assert result.get("skipped") is True
    print("OK unknown event skipped")


if __name__ == "__main__":
    test_guardduty_normalize()
    test_securityhub_normalize()
    test_filter_min_severity()
    test_dedup()
    test_run_event_end_to_end()
    test_run_event_unknown_type_skipped()
    print("\nALL TESTS PASSED")
