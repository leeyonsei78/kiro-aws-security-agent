@echo off
chcp 65001 >nul
REM ============================================================
REM  AWS Security Agent - 웹 검증 콘솔 실행 (Windows)
REM  이 파일을 더블클릭하면 서버가 뜨고 브라우저가 자동으로 열립니다.
REM  AWS 자격증명이 필요 없습니다.
REM  chcp 65001 = 콘솔을 UTF-8로 설정(한글 깨짐 방지)
REM ============================================================
setlocal
cd /d "%~dp0"

REM Python 실행기 찾기 (python 또는 py)
set "PYEXE=python"
where python >nul 2>nul
if errorlevel 1 (
  where py >nul 2>nul
  if errorlevel 1 (
    echo [ERROR] Python not found / Python이 설치되어 있지 않습니다.
    echo         https://www.python.org/downloads/ 에서 설치하세요.
    echo         설치 시 "Add Python to PATH" 를 반드시 체크하세요.
    pause
    exit /b 1
  )
  set "PYEXE=py"
)

REM 파이썬 출력도 UTF-8로(로그 한글 깨짐 방지)
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONPATH=src"
set "URL=http://127.0.0.1:8080"

echo.
echo ============================================================
echo   AWS Security Agent - Web Console / 웹 검증 콘솔
echo   URL: %URL%
echo   Press Ctrl+C in this window to stop / 종료하려면 Ctrl+C
echo ============================================================
echo.

REM 서버가 뜰 시간을 준 뒤 브라우저 자동 열기(2초 지연, 별도 프로세스)
start "" cmd /c "timeout /t 2 >nul & start %URL%"

REM 서버 실행 (이 창에서 계속 실행됨)
%PYEXE% -m agent.webui.server

echo.
echo Server stopped / 서버가 종료되었습니다.
pause
