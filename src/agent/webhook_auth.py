"""방화벽 webhook(HTTP) 인증.

API Gateway로 들어온 요청을 collector로 넘기기 전에 검증한다:
  1. API 키: 헤더 X-Api-Key 값이 설정 키와 일치해야 함(상수 시간 비교).
  2. IP 허용목록: 소스 IP가 허용 IP/CIDR 목록에 포함돼야 함.

두 설정이 모두 비어 있으면 인증을 적용하지 않는다(기존 동작 유지 + 경고 로그).
API Gateway REST(v1)와 HTTP(v2) 이벤트 형식을 모두 지원한다.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from hmac import compare_digest

from .config import Config

logger = logging.getLogger(__name__)


@dataclass
class AuthResult:
    ok: bool
    status: int = 200
    reason: str = ""


def _headers_lower(event: dict) -> dict[str, str]:
    """헤더 키를 소문자로 정규화(HTTP 헤더는 대소문자 무시)."""
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): v for k, v in headers.items()}


def extract_api_key(event: dict) -> str:
    return _headers_lower(event).get("x-api-key", "") or ""


def extract_source_ip(event: dict) -> str:
    """API Gateway v1/v2 이벤트에서 소스 IP 추출."""
    rc = event.get("requestContext") or {}
    if isinstance(rc, dict):
        # HTTP API (v2)
        http = rc.get("http")
        if isinstance(http, dict) and http.get("sourceIp"):
            return http["sourceIp"]
        # REST API (v1)
        identity = rc.get("identity")
        if isinstance(identity, dict) and identity.get("sourceIp"):
            return identity["sourceIp"]
    # 프록시/직접 헤더 fallback (X-Forwarded-For의 첫 IP)
    xff = _headers_lower(event).get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return ""


def _ip_allowed(ip: str, allowed: list[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowed:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            logger.warning("firewall_allowed_ips 항목 파싱 실패: %r", entry)
            continue
    return False


def authorize(event: dict, cfg: Config) -> AuthResult:
    """방화벽 HTTP 요청 인증. 통과 시 ok=True, 실패 시 상태코드/사유 포함."""
    if not cfg.firewall_auth_configured:
        # 인증 미설정: 기존 동작 유지하되, 공개 노출 위험을 경고로 남김.
        logger.warning(
            "firewall webhook 인증이 설정되지 않음(FIREWALL_API_KEY/FIREWALL_ALLOWED_IPS). "
            "공개 엔드포인트로 노출될 수 있습니다."
        )
        return AuthResult(ok=True)

    # 1) API 키 검사(설정된 경우)
    if cfg.firewall_api_key:
        provided = extract_api_key(event)
        if not provided or not compare_digest(provided, cfg.firewall_api_key):
            return AuthResult(ok=False, status=401, reason="유효하지 않은 API 키")

    # 2) IP 허용목록 검사(설정된 경우)
    if cfg.firewall_allowed_ips:
        ip = extract_source_ip(event)
        if not _ip_allowed(ip, cfg.firewall_allowed_ips):
            return AuthResult(ok=False, status=403, reason=f"허용되지 않은 소스 IP: {ip or '알수없음'}")

    return AuthResult(ok=True)
