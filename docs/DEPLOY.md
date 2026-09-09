# 배포 가이드 (AWS Lambda)

에이전트는 하나의 Lambda 함수로 세 트리거를 모두 처리한다:
**주기적 폴링**(EventBridge 스케줄), **실시간 이벤트**(EventBridge 패턴), **방화벽 webhook**(API Gateway HTTP).

배포 방식은 3가지: **수동(zip)**, **SAM**, **Terraform**. 코드에 외부 의존성이 없어(런타임 boto3 + 표준 라이브러리) 별도 빌드 없이 `src/`를 그대로 패키징한다.

---

## 방법 1: SAM (권장)

[`deploy/sam/template.yaml`](../deploy/sam/template.yaml)이 Lambda + IAM + SNS + EventBridge(스케줄/이벤트) + (선택)HTTP API를 한 번에 만든다.

```bash
cd deploy/sam
sam build
sam deploy --guided \
  --parameter-overrides \
    MinSeverity=HIGH \
    Collectors=guardduty,securityhub \
    NotificationEmail=sec@example.com \
    SlackWebhookUrl=https://hooks.slack.com/services/XXX/YYY/ZZZ \
    EnableFirewallEndpoint=true
```

주요 파라미터:

| 파라미터 | 기본값 | 설명 |
|----------|--------|------|
| `MinSeverity` | `MEDIUM` | 알림 임계 심각도 |
| `Collectors` | `guardduty,securityhub` | 폴링 collector |
| `SlackWebhookUrl` / `NotificationEmail` | - | 알림 채널(선택) |
| `ScheduleExpression` | `rate(1 hour)` | 폴링 주기 |
| `RemediationEnabled` / `RemediationDryRun` | `false` / `true` | 자동 대응 |
| `EnableFirewallEndpoint` | `false` | 방화벽 webhook용 HTTP API 생성 |
| `EnableRemediationPolicy` | `false` | 대응(쓰기) IAM 권한 부여 |

> **자동 대응을 실제로 적용하려면** `RemediationEnabled=true`, `RemediationDryRun=false`, `EnableRemediationPolicy=true` 세 가지를 모두 지정해야 한다(3중 안전장치).

배포 후 출력(`Outputs`)에 `FirewallWebhookUrl`, `AlertsTopicArn`이 표시된다.

---

## 방법 2: Terraform

[`deploy/terraform/`](../deploy/terraform/)에 동일 구성을 HCL로 정의했다.

```bash
cd deploy/terraform
terraform init
terraform apply \
  -var 'region=ap-northeast-2' \
  -var 'min_severity=HIGH' \
  -var 'notification_email=sec@example.com' \
  -var 'enable_firewall_endpoint=true'
```

`archive_file`이 `src/`를 자동으로 zip으로 묶는다. 출력에 `function_arn`, `alerts_topic_arn`, `firewall_webhook_url`이 나온다.

실제 대응 적용 시: `-var 'remediation_enabled=true' -var 'remediation_dry_run=false' -var 'enable_remediation_policy=true'`.

---

## 방법 3: 수동 (zip)

```bash
cd src
zip -r ../function.zip agent
```

- Runtime: `python3.11` 이상, Handler: `agent.handler.lambda_handler`
- IAM: 읽기 전용 권한 [iam/agent-policy.json](../iam/agent-policy.json), 대응 시 [iam/remediation-policy.json](../iam/remediation-policy.json) 추가
- 트리거는 아래 "트리거 배선" 참고로 수동 구성

### 트리거 배선

**(A) 주기적 폴링** — EventBridge 스케줄 `rate(5 minutes)` → Lambda.
`LOOKBACK_MINUTES`를 주기보다 약간 크게 두면 누락 없이 겹쳐 조회한다(중복은 `dedup_key`로 제거).

**(B) 실시간** — EventBridge 이벤트 패턴(각 규칙을 같은 Lambda로):
```json
{ "source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"] }
{ "source": ["aws.securityhub"], "detail-type": ["Security Hub Findings - Imported"] }
{ "source": ["aws.access-analyzer"], "detail-type": ["Access Analyzer Finding"] }
```

**(C) 방화벽 webhook** — API Gateway HTTP API `POST /firewall` → Lambda(프록시 통합).
방화벽 장비가 이 URL로 로그를 POST 한다. `?vendor=fortinet`으로 벤더 지정 가능(미지정 시 자동 감지).

핸들러가 이벤트 형태(`httpMethod`/`requestContext.http` → HTTP, `detail-type` → 실시간, 그 외 → 폴링)로 경로를 자동 구분한다.

---

## 검증

```bash
# 폴링 경로 (수동 호출 = 빈 payload)
aws lambda invoke --function-name security-agent-agent --payload '{}' out.json

# 실시간 경로 (샘플 이벤트로 로컬 테스트)
python -m agent.cli --event sample_event.json

# 방화벽 webhook (배포 후 URL로)
curl -X POST "$FIREWALL_URL?vendor=fortinet" \
  --data 'devname=x logid=1 type=utm subtype=ips level=alert srcip=1.2.3.4 attack=Backdoor'
```

배포 전 로컬에서 파싱/정규화/필터 결과를 브라우저로 확인하려면 [웹 검증 콘솔](WEBUI.md)을 사용한다.

> **보안 권장**: 방화벽 HTTP API에는 인증(API 키/mTLS/IP 허용목록)을 걸어 방화벽 장비만 접근하도록 제한하세요.
