#!/usr/bin/env bash
# ============================================================
#  AWS Security Agent - 웹 검증 콘솔 실행 (macOS / Linux)
#  실행: ./run.sh   (최초 1회 chmod +x run.sh 필요할 수 있음)
#  AWS 자격증명이 필요 없습니다.
# ============================================================
set -e
cd "$(dirname "$0")"

# Python 실행기 찾기
if command -v python3 >/dev/null 2>&1; then
  PYEXE=python3
elif command -v python >/dev/null 2>&1; then
  PYEXE=python
else
  echo "[오류] Python이 설치되어 있지 않습니다. https://www.python.org/downloads/ 에서 설치하세요."
  exit 1
fi

export PYTHONPATH=src
URL="http://127.0.0.1:8080"

echo ""
echo "============================================================"
echo "  AWS Security Agent - 웹 검증 콘솔"
echo "  주소: $URL"
echo "  종료하려면 Ctrl+C 를 누르세요."
echo "============================================================"
echo ""

# 브라우저 자동 열기(2초 뒤, 백그라운드)
( sleep 2
  if command -v open >/dev/null 2>&1; then open "$URL"        # macOS
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"  # Linux
  fi
) >/dev/null 2>&1 &

# 서버 실행
exec "$PYEXE" -m agent.webui.server
