# 웹 검증 콘솔

배포 없이 로컬 브라우저에서 **로그/이벤트를 붙여넣어 파싱 → 정규화 → 심각도 필터 결과**를 즉시 확인하는 개발용 도구입니다. 표준 라이브러리만 사용하며 **AWS 자격증명이 필요 없습니다**(실시간 이벤트/방화벽 파싱 경로만 사용, 알림/대응은 호출하지 않음).

## 실행

```bash
python -m agent.webui.server                 # http://127.0.0.1:8080
python -m agent.webui.server --port 9000 --host 0.0.0.0
```

`src/`가 `PYTHONPATH`에 있어야 합니다:

```bash
PYTHONPATH=src python -m agent.webui.server
```

## 사용법

브라우저에서 접속 후:

1. **탭 선택** — "써드파티 방화벽 로그" 또는 "AWS 이벤트(JSON)"
2. **입력** — 로그 라인(방화벽) 또는 EventBridge JSON(이벤트)을 붙여넣기. 상단 **샘플 칩**으로 예시를 바로 채울 수 있음
3. **벤더/최소 심각도** 선택 (방화벽은 `auto` 자동 감지 지원)
4. **분석** 클릭 → 우측에 정규화된 finding이 심각도 배지와 함께 표시됨
   - 요약: 정규화 건수 / 필터 통과 / 제외 / 최소 심각도
   - 필터에서 제외된 finding은 흐리게(dim) + "필터 제외" 뱃지로 표시

## 엔드포인트 (프로그램 접근)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/` | 검증 UI (HTML) |
| GET | `/api/meta` | 지원 벤더/이벤트타입/심각도 목록 |
| POST | `/api/firewall` | `{"raw": "<로그>", "vendor": "auto", "min_severity": "MEDIUM"}` |
| POST | `/api/event` | `{"event": {<EventBridge JSON>}, "min_severity": "MEDIUM"}` |

응답 예:
```json
{
  "ok": true, "total": 2, "matched": 1, "filtered_out": 1, "min_severity": "CRITICAL",
  "all_findings": [ ... ], "matched_findings": [ ... ]
}
```

> 이 콘솔은 **검증 전용**입니다. 실제 알림/자동 대응은 실행하지 않으므로 안전하게 파서/필터 동작을 확인할 수 있습니다. 운영 배포는 [DEPLOY.md](DEPLOY.md)를 참고하세요.
