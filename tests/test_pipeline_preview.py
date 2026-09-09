"""전체 파이프라인 미리보기 + notifier render + 서버 /api/pipeline 검증.

preview_pipeline은 알림을 실제 전송하지 않고(render), remediator를 강제 dry-run으로
계획만 산출한다. boto3 미설치 환경에서도 동작(대응은 _plan만).
"""

import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import preview_pipeline
from agent.models import Severity, SecurityFinding
from agent.notifiers.slack import SlackNotifier
from agent.notifiers.email_sns import EmailSnsNotifier
from agent.notifiers.stdout import StdoutNotifier
from agent.webui import server as srv


# --- 샘플 (원격 IP/서브넷 포함 → NACL 대응 유발) ---
GD_SSH = {
    "source": "aws.guardduty", "detail-type": "GuardDuty Finding",
    "detail": {"Id": "gd-ssh", "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
               "Title": "SSH brute force", "Severity": 8.0, "Region": "ap-northeast-2",
               "Service": {"Action": {"NetworkConnectionAction": {"RemoteIpDetails": {"IpAddressV4": "203.0.113.5"}}}},
               "Resource": {"ResourceType": "Instance", "InstanceDetails": {
                   "InstanceId": "i-0abc", "NetworkInterfaces": [{"SubnetId": "subnet-1"}]}}},
}
GD_IAM = {
    "source": "aws.guardduty", "detail-type": "GuardDuty Finding",
    "detail": {"Id": "gd-iam", "Type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
               "Title": "Creds exfil", "Severity": 8.0, "Region": "ap-northeast-2",
               "Resource": {"AccessKeyDetails": {"AccessKeyId": "AKIAEXAMPLE12345", "UserName": "alice", "UserType": "IAMUser"}}},
}
FORTINET = 'devname="FGT" logid="1" type="utm" subtype="ips" level="alert" srcip=203.0.113.5 attack="Backdoor"'


# --- notifier render ---
def test_notifier_render_no_send():
    findings = list(__import__("agent.collectors.guardduty", fromlist=["GuardDutyCollector"])
                    .GuardDutyCollector().parse_event(GD_SSH))
    assert findings
    # slack render는 전송 없이 문자열
    slack = SlackNotifier(webhook_url="")  # URL 없어도 render는 동작
    msg = slack.render(findings)
    assert "AWS 보안 finding 감지" in msg and "SSH brute force" in msg
    # email render는 제목 라인 포함
    email = EmailSnsNotifier(topic_arn="")
    em = email.render(findings)
    assert em.startswith("제목:")
    # stdout render (base 기본 구현)
    assert "SSH brute force" in StdoutNotifier().render(findings)
    print("OK notifier render (slack/email/stdout, 전송 없음)")


def test_notifier_render_empty():
    assert "없음" in SlackNotifier(webhook_url="").render([])
    print("OK notifier render empty")


# --- preview_pipeline: 알림 + 대응 ---
def test_pipeline_nacl_remediation_plan():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.MEDIUM)
    r = preview_pipeline(event=GD_SSH, cfg=cfg)
    assert r["ok"] and r["matched"] == 1
    # 알림 미리보기 존재
    assert any(n["notifier"] == "stdout" for n in r["notifications"])
    assert r["notifications"][0]["message"]
    # nacl_block_ip 대응 계획(dry-run)
    rem = [x for x in r["remediations"] if x["remediator"] == "nacl_block_ip"]
    assert rem and rem[0]["status"] == "DRY_RUN"
    assert rem[0]["actions"][0]["api"] == "ec2:CreateNetworkAclEntry"
    print("OK pipeline: stdout 알림 + nacl dry-run 계획")


def test_pipeline_iam_remediation_plan():
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.MEDIUM)
    r = preview_pipeline(event=GD_IAM, cfg=cfg)
    rem = [x for x in r["remediations"] if x["remediator"] == "iam_disable_key"]
    assert rem and rem[0]["status"] == "DRY_RUN"
    assert rem[0]["actions"][0]["api"] == "iam:UpdateAccessKey"
    print("OK pipeline: iam_disable_key dry-run 계획")


def test_pipeline_firewall_no_remediation():
    # 방화벽 finding은 대응 대상 아님 → remediations 비어야
    cfg = Config(collectors=[], notifiers=["stdout"], min_severity=Severity.MEDIUM)
    r = preview_pipeline(firewall_payload={"firewall_raw": FORTINET}, cfg=cfg)
    assert r["ok"] and r["matched"] == 1
    assert r["remediations"] == []
    print("OK pipeline: 방화벽 finding은 대응 없음")


def test_pipeline_no_actual_send_or_change():
    # slack/email을 활성화해도 render만 하고 실제 전송/AWS 호출을 하지 않아야(예외 없이 동작)
    cfg = Config(collectors=[], notifiers=["slack", "email_sns"], min_severity=Severity.MEDIUM,
                 slack_webhook_url="https://example.invalid/hook", sns_topic_arn="arn:aws:sns:x:1:t")
    r = preview_pipeline(event=GD_SSH, cfg=cfg)
    labels = [n["notifier"] for n in r["notifications"]]
    assert "slack" in labels and "email_sns" in labels
    print("OK pipeline: slack/email render만(실제 전송 없음)")


# --- 서버 /api/pipeline (소켓 없이 핸들러 구동) ---
class FakeHandler(srv.Handler):
    def __init__(self, path, body=b""):
        self.path = path
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.headers = {"Content-Length": str(len(body))}
        self._status = None
    def send_response(self, c, m=None): self._status = c
    def send_header(self, k, v): pass
    def end_headers(self): pass
    def address_string(self): return "t"
    def out(self):
        return self._status, json.loads(self.wfile.getvalue().decode())


def call(path, obj):
    h = FakeHandler(path, json.dumps(obj).encode())
    h.do_POST()
    return h.out()


def test_server_pipeline_firewall():
    st, d = call("/api/pipeline", {"kind": "firewall", "raw": FORTINET, "vendor": "auto", "min_severity": "MEDIUM"})
    assert st == 200 and d["ok"] and d["matched"] == 1
    assert "notifications" in d and "remediations" in d
    print("OK server /api/pipeline firewall")


def test_server_pipeline_event():
    st, d = call("/api/pipeline", {"kind": "event", "event": json.dumps(GD_SSH), "min_severity": "MEDIUM"})
    assert st == 200 and d["ok"]
    assert any(r["remediator"] == "nacl_block_ip" for r in d["remediations"])
    print("OK server /api/pipeline event (+대응 계획)")


def test_server_pipeline_bad_event():
    st, d = call("/api/pipeline", {"kind": "event", "event": "not json"})
    assert st == 400 and d["ok"] is False
    print("OK server /api/pipeline 잘못된 event -> 400")


if __name__ == "__main__":
    test_notifier_render_no_send()
    test_notifier_render_empty()
    test_pipeline_nacl_remediation_plan()
    test_pipeline_iam_remediation_plan()
    test_pipeline_firewall_no_remediation()
    test_pipeline_no_actual_send_or_change()
    test_server_pipeline_firewall()
    test_server_pipeline_event()
    test_server_pipeline_bad_event()
    print("\nALL PIPELINE PREVIEW TESTS PASSED")
