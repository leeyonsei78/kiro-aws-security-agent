# AWS Security Monitoring Agent

[![CI](https://github.com/leeyonsei78/kiro-aws-security-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/leeyonsei78/kiro-aws-security-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

AWS 보안 서비스/장비의 findings(위협 탐지 결과)를 **수집 → 정규화 → 필터링 → 알림**하는 확장 가능한 에이전트입니다.

> 🚀 **처음 오셨나요?** [**따라하기 매뉴얼**](따라하기_매뉴얼.md)을 그대로 따라 하면 내려받기부터 실행·검증(AWS 없이 약 10분)까지 완료할 수 있습니다.
>
> 🧭 **이어서 개발하시나요?** [**PROJECT_STATUS.md**](PROJECT_STATUS.md)에 현재까지 완료한 것 / 다음 후보 / 재개 방법이 정리돼 있습니다.

## 특징

- **플러그인 구조**: 새 보안 소스(Collector)와 알림 채널(Notifier)을 코어 수정 없이 추가
- **통합 스키마**: 소스가 달라도 `SecurityFinding` 하나로 정규화
- **두 가지 실행 모드**: 주기적 폴링(EventBridge 스케줄) + 실시간 이벤트(EventBridge event pattern)
- **확장 로드맵 반영**: WAF/Shield/Inspector/Config/CloudTrail/네트워크/써드파티, 그리고 자동 대응(remediation)을 위한 확장 포인트 마련

## 현재 지원 (MVP)

| 구분 | 지원 |
|------|------|
| Collector | Amazon GuardDuty, AWS Security Hub, Security Group(위험 개방 감지), IAM Access Analyzer(외부 공유), CloudTrail(위험 API 감지), VPC Flow Logs(이상 트래픽), 써드파티 방화벽(Palo Alto / Fortinet / Check Point / CEF), 컴플라이언스 점검(KISA/CIS 기반 CA 항목) |
| Notifier | Slack (Incoming Webhook), Email (SNS) |
| Remediator | `nacl_block_ip`, `sg_revoke_ingress`, `s3_public_block`, `waf_ipset_block`, `iam_disable_key`, `ec2_quarantine` |
| 실행 | AWS Lambda (스케줄 폴링 / 실시간 이벤트 / API Gateway HTTP 수신), 로컬 CLI |

> 자동 대응은 **기본 비활성 + dry-run 기본**입니다. 실제 변경은 `REMEDIATION_ENABLED=true`와 `REMEDIATION_DRY_RUN=false`를 모두 명시해야 수행됩니다. 자세한 내용은 [docs/CONFIG.md](docs/CONFIG.md) 참고.

## 로드맵 (확장 예정)

- Collector: WAF, Shield, Inspector, Config
- 실시간 이벤트 기반 처리 강화

## 프로젝트 구조

```
src/agent/
  models.py            # 통합 SecurityFinding 데이터 모델 (+ parse_ts)
  config.py            # 환경변수 기반 설정
  aws.py               # boto3 클라이언트 생성 공통 헬퍼
  finding_utils.py     # finding raw 파싱 공통 헬퍼 (GuardDuty 원격 IP 등)
  webhook_auth.py      # 방화벽 webhook 인증 (API 키 / IP 허용목록)
  registry.py          # collector/notifier/remediator 플러그인 등록
  core.py              # 오케스트레이션 (수집→정규화→필터→알림→대응, preview_parse)
  collectors/
    base.py            # BaseCollector 인터페이스
    guardduty.py       # GuardDuty collector
    securityhub.py     # Security Hub collector
    security_group.py  # Security Group 위험 개방 감지 collector
    access_analyzer.py # IAM Access Analyzer(외부 공유) collector
    cloudtrail.py      # CloudTrail 위험 API 호출 감지 collector
    vpc_flow_logs.py   # VPC Flow Logs 이상 트래픽 감지 collector
    firewall_syslog.py # 써드파티 방화벽 수신 collector (webhook/syslog)
  firewall/            # 써드파티 방화벽 벤더 파서
    base.py            # BaseFirewallParser 인터페이스
    registry.py        # 파서 등록 + 벤더 자동 감지
    fortinet.py        # FortiGate key=value 파서
    paloalto.py        # PAN-OS CSV 파서
    checkpoint.py      # Check Point key=value 파서
    cef.py             # CEF 공통 파서 (벤더 fallback)
    util.py            # key=value / syslog 헤더 파싱 유틸
  notifiers/
    base.py            # BaseNotifier 인터페이스
    slack.py           # Slack notifier
    email_sns.py       # Email(SNS) notifier
    stdout.py          # stdout notifier (로컬/디버깅)
  remediators/
    base.py            # BaseRemediator + 안전장치(dry-run/화이트리스트/감사)
    nacl_block_ip.py   # 위협 IP를 NACL deny로 차단
    sg_revoke_ingress.py # SG 인터넷 개방 규칙 회수
    s3_public_block.py   # 공개 S3 버킷에 Public Access Block 적용
    waf_ipset_block.py   # 악성 IP를 WAF IPSet에 추가(앱 계층 차단)
    iam_disable_key.py   # 침해 의심 IAM 액세스 키 비활성화
    ec2_quarantine.py    # 침해 의심 EC2를 격리 SG로 교체
  webui/               # 로컬 웹 검증 콘솔 (http.server + 단일 HTML)
    server.py          # 검증 서버
    page.py            # UI 페이지
  handler.py           # Lambda 진입점 (스케줄 + 실시간 이벤트 + 방화벽 HTTP)
  cli.py               # 로컬 실행용 CLI
deploy/
  sam/template.yaml    # SAM 배포 템플릿
  terraform/           # Terraform 배포 구성
```

## 로컬 실행

```bash
pip install -r requirements.txt
# AWS 자격증명은 표준 방식(환경변수/프로파일)으로 설정
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export MIN_SEVERITY="MEDIUM"
PYTHONPATH=src python -m agent.cli --lookback-minutes 60
```

## 웹 검증 콘솔 (배포 없이 확인)

로그/이벤트를 브라우저에 붙여넣어 **전체 파이프라인(정규화→필터→알림→자동대응)** 을 즉시 확인 (AWS 자격증명 불필요):

가장 쉬운 방법 — **`run.bat`(Windows) 더블클릭** 또는 **`./run.sh`(macOS/Linux)**. 서버가 뜨고 브라우저가 자동으로 열립니다. (boto3·AWS 자격증명 불필요)

명령으로 실행 시 OS별 문법:

```bash
# macOS/Linux
PYTHONPATH=src python -m agent.webui.server        # http://127.0.0.1:8080
# Windows PowerShell
$env:PYTHONPATH="src"; python -m agent.webui.server
```

접속하면 **전체 기능 개요 · 방화벽 · AWS 이벤트 · 컴플라이언스 · 용어 사전** 5개 탭이 있으며, 각 화면에서 무엇을 점검/수집하는지 설명을 제공합니다.

- **파싱·필터만** 모드: 정규화된 finding과 심각도 필터 통과/제외 확인
- **전체 파이프라인** 모드: 위에 더해 **알림 메시지 미리보기**(Slack/Email/stdout)와 **자동 대응 dry-run 계획**(NACL/SG/S3/WAF/IAM/EC2)까지 — 실제 전송·변경은 없음

자세한 사용법은 [docs/WEBUI.md](docs/WEBUI.md).

## 배포

- **SAM**: [`deploy/sam/template.yaml`](deploy/sam/template.yaml)
- **Terraform**: [`deploy/terraform/`](deploy/terraform/)

Lambda + IAM + SNS + EventBridge(스케줄/실시간) + (선택)방화벽 HTTP API를 한 번에 생성. 절차는 [docs/DEPLOY.md](docs/DEPLOY.md).

자세한 설정은 [docs/CONFIG.md](docs/CONFIG.md) 참고.


## 개발 / 테스트

```bash
# 린트 (미사용 import/변수/재정의 검사)
ruff check src/agent --select F401,F811,F841

# 단위 테스트 (boto3 없이 동작 — stub 경로 사용)
for t in tests/test_*.py; do PYTHONPATH="tests/_stubs" python "$t"; done

# 통합 테스트 (실제 boto3 호출 경로를 moto 가상 AWS로 검증)
pip install -r requirements-dev.txt
PYTHONPATH=src python -m pytest tests/integration -v
```

- **단위 테스트**: 외부 의존성 없이 파싱·정규화·필터·라우팅·인증을 검증 (`tests/test_*.py`)
- **통합 테스트**: `moto`로 실제 AWS 호출 경로(`collect` / remediator `_apply`)를 검증 (`tests/integration/`). moto 미설치 시 자동 skip.

push/PR 시 [GitHub Actions CI](.github/workflows/ci.yml)가 두 종류를 모두 자동 실행합니다 (단위: Python 3.10/3.11/3.12, 통합: moto 잡).

## 참고 / 감사의 글

- 컴플라이언스 점검(`compliance` collector) 항목 코드 체계(`CA-nn`)와 클라우드 하드닝 관점은 KISA 주요정보통신기반시설 가이드 기반 [cdppcorp/KESE-KIT](https://github.com/cdppcorp/KESE-KIT) (MIT)의 접근을 **참고**했습니다. 점검 로직은 본 프로젝트에서 boto3로 새로 구현했습니다.

## 라이선스

[MIT](LICENSE) © 2026 leeyonsei78
