# 프로젝트 진행 상태 (이어서 작업용)

> 다음 세션에서 이 파일을 먼저 읽으면 어디까지 했고 무엇을 이어서 할지 바로 파악됩니다.
> 최종 업데이트: 2026-09-09 · 저장소: https://github.com/leeyonsei78/kiro-aws-security-agent (public)

---

## 한 줄 요약

AWS 보안 신호 + 써드파티 방화벽 로그를 **수집 → 정규화 → 필터 → 알림 → 자동 대응**하는 확장형 에이전트. 플러그인 구조, 웹 검증 콘솔, SAM/Terraform 배포, CI(단위+moto 통합)까지 완성. 현재 CI 전부 green.

---

## ✅ 지금까지 완료한 것

### 코어 기능
- **Collector 8종**: `guardduty`, `securityhub`, `security_group`, `access_analyzer`, `cloudtrail`, `vpc_flow_logs`, `firewall_syslog`, `compliance`(점검 16종: CA 11 + SC 3(공급망) + ZT 2(제로트러스트) + 점수/리포트, KESE-KIT 참고)
- **Notifier 3종**: `slack`, `email_sns`, `stdout` (각각 `render()`로 전송 없이 미리보기 지원)
- **Remediator 6종**: `nacl_block_ip`, `sg_revoke_ingress`, `s3_public_block`, `waf_ipset_block`, `iam_disable_key`, `ec2_quarantine` (기본 비활성 + dry-run + 화이트리스트 + 감사로그)
- **방화벽 파서 4종**: `fortinet`, `paloalto`, `checkpoint`, `cef` (자동 벤더 감지)
- **Lambda handler**: 스케줄 폴링 + EventBridge 실시간 + 방화벽 HTTP webhook 3경로 자동 라우팅

### 품질/운영
- **리팩터링 완료**: 공통 모듈 `aws.py`(make_client), `finding_utils.py`(guardduty_remote_ip), `models.parse_ts`, firewall `util`(slug/severity). ruff(F401/F811/F841) 통과
- **웹 검증 콘솔** (`src/agent/webui/`): 브라우저에서 로그/이벤트 붙여넣어 전체 파이프라인 확인. 두 모드(파싱·필터만 / 전체 파이프라인=알림 미리보기+대응 dry-run). AWS 자격증명 불필요.
- **방화벽 webhook 인증** (`webhook_auth.py`): API 키(X-Api-Key, 상수시간 비교) + IP 허용목록(CIDR). 둘 다 미설정 시 경고 후 통과.
- **배포**: `deploy/sam/template.yaml`, `deploy/terraform/` (Lambda+IAM+SNS+EventBridge+선택 HTTP API, 인증/대응 파라미터화)
- **CI**: `.github/workflows/ci.yml` — 단위 테스트(py3.10/3.11/3.12) + moto 통합 잡. 현재 전부 success.
- **LICENSE**: MIT
- **문서**: `README.md`, `따라하기_매뉴얼.md`(스크린샷 5종 포함), `docs/{CONFIG,DEPLOY,WEBUI,EXTENDING}.md`

### 테스트 (총 9 단위 스위트 + 통합)
- 단위: `tests/test_*.py` — pipeline, remediation, extensions(1~3), firewall, webhook_auth, webui, pipeline_preview
  - 실행: `for t in tests/test_*.py; do PYTHONPATH="tests/_stubs" python "$t"; done`
- 통합(moto): `tests/integration/test_moto_*.py` — EC2/S3/IAM 실제 호출 경로. moto 미설치 시 자동 skip.
  - 실행: `pip install -r requirements-dev.txt && PYTHONPATH=src python -m pytest tests/integration -v`

---

## ⏭️ 다음에 이어서 할 후보 (우선순위 순)

1. **실제 웹 콘솔 스크린샷으로 교체**
   - 현재 `docs/img/*.svg`는 실제 렌더링이 아니라 색상·레이아웃 재현 이미지(sandbox에 브라우저 없어서).
   - 본인 PC에서 `PYTHONPATH=src python -m agent.webui.server` 실행 → 브라우저 캡처 → `docs/img/`에 PNG로 교체하면 매뉴얼이 더 정확해짐.

2. **영어 문서** (`README_EN.md`, 매뉴얼 영어판) — 오픈소스 공유/홍보용.

3. **CONTRIBUTING.md + 이슈/PR 템플릿** (`.github/`) — 기여 편의, public 저장소 기본기.

4. **통합 테스트 확대** — moto가 지원하는 범위에서 WAFv2 IPSet, CloudTrail 등 추가 커버.

5. **남은 collector** (Inspector, Config, WAF, Shield) — 다만 대부분 Security Hub에 집계되어 우선순위 낮음.

6. **알림 채널 추가** — PagerDuty/MS Teams notifier 등.

> 특별한 선호가 없으면 **1번(실제 스크린샷) 또는 3번(CONTRIBUTING/템플릿)** 부터 권장.

---

## 🔧 이어서 작업 재개 방법

```bash
# 1) 코드 받기 (또는 기존 sandbox면 이미 있음)
git clone https://github.com/leeyonsei78/kiro-aws-security-agent.git
cd kiro-aws-security-agent

# 2) 상태 확인
cat PROJECT_STATUS.md          # 이 파일
git log --oneline -5

# 3) 로컬 검증 (AWS 불필요)
for t in tests/test_*.py; do PYTHONPATH="tests/_stubs" python "$t"; done   # 단위 테스트
PYTHONPATH=src python -m agent.webui.server                                # 웹 콘솔 → http://127.0.0.1:8080

# 4) 새 작업 후 반영
ruff check src/agent --select F401,F811,F841
git add . && git commit -m "..." && git push origin main
# CI 결과: gh api repos/leeyonsei78/kiro-aws-security-agent/actions/runs?per_page=1
```

---

## ⚠️ 환경 제약 메모 (중요)

- 이 개발 sandbox는 **네트워크 제한(INTEGRATIONS_ONLY)** 이라 `pip install boto3/moto` **불가**.
  → 단위 테스트는 `tests/_stubs`의 boto3 stub으로 실행. moto 통합 테스트는 **CI(GitHub Actions)에서만** 실제 실행됨.
- sandbox에 **브라우저(chromium) 없음** → 웹 콘솔 실제 캡처 불가. 스크린샷은 SVG 재현본.
- GitHub 연동은 Settings > Agent > Connect GitHub 로 이미 연결됨(계정 leeyonsei78). push/PR은 `git push` / `gh api` REST로 처리.

---

## 파일 구조 빠른 참조

```
src/agent/
  models.py config.py aws.py finding_utils.py registry.py core.py
  handler.py cli.py webhook_auth.py
  collectors/  (guardduty, securityhub, security_group, access_analyzer, cloudtrail, vpc_flow_logs, firewall_syslog)
  notifiers/   (slack, email_sns, stdout, base)
  remediators/ (nacl_block_ip, sg_revoke_ingress, s3_public_block, waf_ipset_block, iam_disable_key, ec2_quarantine, base)
  firewall/    (fortinet, paloalto, checkpoint, cef, registry, util, base)
  webui/       (server, page)
deploy/  (sam/, terraform/)
docs/    (CONFIG, DEPLOY, WEBUI, EXTENDING, img/)
tests/   (test_*.py 단위, integration/ moto, _stubs/ boto3 stub)
.github/workflows/ci.yml
```
