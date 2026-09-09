"""추가 확장 2종 검증: CloudTrail collector, IAM 키 비활성화 remediator.

boto3 실제 호출은 network 제한으로 미실행. parse_event/정규화/_plan/화이트리스트/
handler 라우팅을 검증한다.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import _remediate
from agent.models import SecurityFinding, Severity
from agent.remediators.base import RemediationStatus
from agent.remediators.iam_disable_key import IamDisableKeyRemediator
from agent.collectors.cloudtrail import CloudTrailCollector
from agent.handler import _is_realtime_finding_event


# --- CloudTrail collector ---------------------------------------------------
def _ct_event(event_name, identity_type="IAMUser", user_name="alice"):
    record = {
        "eventID": "ct-1",
        "eventName": event_name,
        "eventTime": "2026-09-09T00:00:00Z",
        "awsRegion": "ap-northeast-2",
        "sourceIPAddress": "203.0.113.5",
        "recipientAccountId": "111122223333",
        "userIdentity": {"type": identity_type, "userName": user_name, "accountId": "111122223333"},
    }
    return {"source": "aws.cloudtrail", "detail-type": "AWS API Call via CloudTrail", "detail": record}


def test_ct_risky_event_normalize():
    c = CloudTrailCollector(region="ap-northeast-2")
    f = list(c.parse_event(_ct_event("StopLogging")))[0]
    assert f.severity == Severity.CRITICAL
    assert f.finding_type == "SuspiciousActivity:CloudTrail/StopLogging"
    assert "203.0.113.5" in f.description
    print("OK ct StopLogging -> CRITICAL")


def test_ct_root_activity_elevates():
    c = CloudTrailCollector(region="ap-northeast-2")
    # CreateAccessKey는 기본 MEDIUM이나, 루트가 하면 상향
    f = list(c.parse_event(_ct_event("CreateAccessKey", identity_type="Root", user_name="")))[0]
    assert f.severity >= Severity.HIGH
    assert "루트" in f.description or "루트" in f.title
    print("OK ct root activity elevates:", f.severity.name)


def test_ct_ignores_uninteresting_event():
    c = CloudTrailCollector(region="ap-northeast-2")
    # 위험 목록에 없고 루트도 아니면 무시
    assert list(c.parse_event(_ct_event("DescribeInstances"))) == []
    print("OK ct ignores benign event")


def test_ct_lookup_events_json_parse():
    # collect 경로에서 쓰는 CloudTrailEvent(JSON 문자열) 정규화 확인
    c = CloudTrailCollector(region="ap-northeast-2")
    record = {
        "eventName": "DeleteTrail", "eventTime": "2026-09-09T01:00:00Z",
        "awsRegion": "ap-northeast-2", "sourceIPAddress": "198.51.100.9",
        "userIdentity": {"type": "IAMUser", "userName": "bob", "accountId": "111122223333"},
    }
    ev = {"EventId": "e-1", "EventName": "DeleteTrail", "Username": "bob",
          "EventTime": "2026-09-09T01:00:00Z", "CloudTrailEvent": json.dumps(record)}
    f = c._normalize(ev, Severity.CRITICAL, "CloudTrail 삭제")
    assert f.severity == Severity.CRITICAL
    assert f.account_id == "111122223333"
    assert f.resources[0].id == "bob"
    print("OK ct lookup_events JSON parse")


# --- IAM disable key remediator --------------------------------------------
def _gd_iam_finding(user_type="IAMUser", user_name="alice", key="AKIAEXAMPLE12345"):
    return SecurityFinding(
        id="gd-iam-1", source="guardduty", title="creds exfil",
        severity=Severity.HIGH,
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        raw={"Resource": {"AccessKeyDetails": {
            "AccessKeyId": key, "UserName": user_name, "UserType": user_type,
        }}},
    )


def test_iam_disable_plan():
    r = IamDisableKeyRemediator(dry_run=True)
    f = _gd_iam_finding()
    assert r.can_handle(f)
    result = r.remediate(f)
    assert result.status == RemediationStatus.DRY_RUN
    a = result.actions[0]
    assert a.api == "iam:UpdateAccessKey"
    assert a.params["Status"] == "Inactive"
    assert a.params["AccessKeyId"] == "AKIAEXAMPLE12345"
    # 감사 로그 설명에는 마스킹된 키만 노출
    assert "AKIA...2345" in a.description
    print("OK iam disable plan (masked):", a.description)


def test_iam_disable_skips_role():
    r = IamDisableKeyRemediator(dry_run=True)
    # 역할(AssumedRole)은 대상 아님
    f = _gd_iam_finding(user_type="AssumedRole", user_name="some-role")
    assert r.can_handle(f) is False
    print("OK iam disable skips non-IAMUser")


def test_iam_disable_skips_root():
    r = IamDisableKeyRemediator(dry_run=True)
    f = _gd_iam_finding(user_name="root")
    assert r.can_handle(f) is False
    print("OK iam disable skips root")


# --- handler 라우팅 ---------------------------------------------------------
def test_handler_recognizes_cloudtrail_event():
    assert _is_realtime_finding_event(_ct_event("StopLogging")) is True
    # 스케줄 이벤트는 실시간 아님
    assert _is_realtime_finding_event({"detail-type": "Scheduled Event", "source": "aws.events"}) is False
    print("OK handler routes cloudtrail realtime / schedule poll")


# --- core 통합 --------------------------------------------------------------
def test_core_iam_disable_dry_run():
    cfg = Config(
        collectors=[], notifiers=["stdout"],
        remediation_enabled=True, remediation_dry_run=True,
        remediators=["iam_disable_key"],
    )
    results = _remediate([_gd_iam_finding()], cfg)
    assert len(results) == 1
    assert results[0]["status"] == "DRY_RUN"
    assert results[0]["remediator"] == "iam_disable_key"
    print("OK core iam_disable_key dry-run")


if __name__ == "__main__":
    test_ct_risky_event_normalize()
    test_ct_root_activity_elevates()
    test_ct_ignores_uninteresting_event()
    test_ct_lookup_events_json_parse()
    test_iam_disable_plan()
    test_iam_disable_skips_role()
    test_iam_disable_skips_root()
    test_handler_recognizes_cloudtrail_event()
    test_core_iam_disable_dry_run()
    print("\nALL EXTENSION2 TESTS PASSED")
