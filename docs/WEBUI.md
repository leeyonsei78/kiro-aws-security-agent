# 웹 검증 콘솔

배포 없이 로컬 브라우저에서 **로그/이벤트를 붙여넣어 전체 파이프라인(파싱 → 정규화 → 심각도 필터 → 알림 → 자동 대응)** 을 즉시 확인하는 개발용 도구입니다. 표준 라이브러리만 사용하며 **AWS 자격증명이 필요 없습니다**. 알림은 실제 전송 없이 메시지만 미리보기하고, 자동 대응은 실제 변경 없이 dry-run 계획만 산출합니다.

## 두 가지 모드

- **파싱·필터만**: 정규화된 finding과 심각도 필터 통과/제외를 확인
- **전체 파이프라인**: 위에 더해 **알림 메시지 미리보기**(Slack/Email/stdout 채널별)와 **자동 대응 dry-run 계획**(NACL/SG/S3/WAF/IAM/EC2 remediator)까지 표시

## 실행

> 웹 콘솔은 **boto3나 AWS 자격증명이 필요 없습니다.** (파싱/미리보기 전용)

### 가장 쉬운 방법 — 더블클릭

- **Windows**: 저장소 폴더의 **`run.bat`** 더블클릭 → 서버 실행 + 브라우저 자동 열기
- **macOS/Linux**: 터미널에서 **`./run.sh`** (최초 1회 `chmod +x run.sh`)

### 명령으로 실행 (OS별 문법 주의)

| 환경 | 명령 |
|------|------|
| Windows PowerShell | `$env:PYTHONPATH="src"; python -m agent.webui.server` |
| Windows CMD | `set PYTHONPATH=src && python -m agent.webui.server` |
| macOS/Linux | `PYTHONPATH=src python -m agent.webui.server` |

포트 변경: `--port 9000`. 접속: **http://127.0.0.1:8080**

## 사용법

브라우저에서 접속하면 기본으로 **전체 기능 개요** 탭이 열립니다. 탭은 5개입니다:

- **전체 기능 개요**: 이 에이전트의 모든 기능을 한눈에 — 각 수집기가 **무엇을·어디서 수집하는지**와 예시 상황까지 설명. Collector 8 / Notifier 3 / Remediator 6 / 방화벽 4벤더 / 컴플라이언스 16종.
- **써드파티 방화벽 로그**: 방화벽 로그 한 줄을 붙여넣어 파싱/정규화 체험
- **AWS 이벤트(JSON)**: GuardDuty/Security Hub 이벤트로 전체 파이프라인 체험
- **컴플라이언스 점검 항목**: 16개 점검 항목 카탈로그 + 점수/등급 데모 리포트
- **용어 사전 (초보자용)**: GuardDuty·IAM·Security Group·dry-run 등 21개 용어를 쉬운 말로 설명

각 탭에서 실제 동작을 테스트합니다:

1. **탭 선택** — "전체 기능 개요" / "써드파티 방화벽 로그" / "AWS 이벤트(JSON)" / "컴플라이언스 점검 항목"
2. **입력** — 로그 라인(방화벽) 또는 EventBridge JSON(이벤트)을 붙여넣기. 상단 **샘플 칩**으로 예시를 바로 채울 수 있음
3. **벤더/최소 심각도** 선택 (방화벽은 `auto` 자동 감지 지원)
4. **모드 선택** — "파싱·필터만" 또는 "전체 파이프라인"
5. **분석** 클릭 → 우측에 결과 표시
   - 요약: 정규화 건수 / 필터 통과 / 제외 / 최소 심각도 / (파이프라인 모드) 대응 계획 수
   - 필터에서 제외된 finding은 흐리게(dim) + "필터 제외" 뱃지로 표시
   - 전체 파이프라인 모드: **📣 알림 미리보기**(채널별 메시지)와 **🛠️ 자동 대응 dry-run 계획**(상태·API·파라미터) 섹션 추가

## 엔드포인트 (프로그램 접근)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/` | 검증 UI (HTML) |
| GET | `/api/capabilities` | 전체 기능 개요(collector/notifier/remediator/방화벽 벤더/컴플라이언스 수) |
| GET | `/api/meta` | 지원 벤더/이벤트타입/심각도/컴플라이언스 항목 목록 |
| GET | `/api/compliance-report` | 컴플라이언스 데모 리포트(점수/등급/카테고리 집계) |
| POST | `/api/firewall` | 방화벽 파싱·필터: `{"raw": "<로그>", "vendor": "auto", "min_severity": "MEDIUM"}` |
| POST | `/api/event` | 이벤트 파싱·필터: `{"event": {<EventBridge JSON>}, "min_severity": "MEDIUM"}` |
| POST | `/api/pipeline` | 전체 파이프라인: 위 입력 + `"kind": "firewall"\|"event"` → 알림/대응 포함 |

응답 예:
```json
{
  "ok": true, "total": 2, "matched": 1, "filtered_out": 1, "min_severity": "CRITICAL",
  "all_findings": [ ... ], "matched_findings": [ ... ]
}
```

> 이 콘솔은 **검증 전용**입니다. 실제 알림/자동 대응은 실행하지 않으므로 안전하게 파서/필터 동작을 확인할 수 있습니다. 운영 배포는 [DEPLOY.md](DEPLOY.md)를 참고하세요.
