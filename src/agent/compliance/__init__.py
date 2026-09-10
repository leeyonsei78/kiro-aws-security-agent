"""컴플라이언스 점검 규칙.

AWS 계정 구성을 점검해 위반 항목을 SecurityFinding으로 산출한다.
점검 항목 체계(코드 부여 방식, 클라우드/계정 하드닝 관점)는 KISA 기반
KESE-KIT(https://github.com/cdppcorp/KESE-KIT, MIT)의 접근을 참고했으며,
점검 로직은 본 프로젝트에서 boto3로 새로 구현했다.
"""
