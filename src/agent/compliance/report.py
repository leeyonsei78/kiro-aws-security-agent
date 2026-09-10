"""컴플라이언스 점수/리포트 요약.

compliance collector가 산출한 finding 목록을 입력받아
카테고리별/심각도별 집계와 100점 만점 점수를 계산한다.

점수 모델(감점식):
  - 기준 100점에서 위반 심각도별 가중치를 합산해 차감(하한 0).
  - 가중치: CRITICAL 40, HIGH 15, MEDIUM 5, LOW 2, INFORMATIONAL 0.
  - 등급: A(90+) B(75+) C(60+) D(40+) F(그 미만).
전체 finding 중 source가 "compliance"인 것만 대상으로 한다.
"""

from __future__ import annotations

from ..models import SecurityFinding, Severity

SEVERITY_PENALTY = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 0,
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def build_report(findings: list[SecurityFinding]) -> dict:
    """컴플라이언스 finding 목록 → 요약 리포트(dict).

    finding에는 raw["code"], raw["category"](없으면 "기타"), severity가 있다고 가정한다.
    compliance 이외 source는 무시한다.
    """
    comp = [f for f in findings if f.source == "compliance"]

    by_severity: dict[str, int] = {s.name: 0 for s in Severity}
    by_category: dict[str, dict] = {}
    items: list[dict] = []
    penalty = 0

    for f in comp:
        sev = f.severity
        by_severity[sev.name] += 1
        penalty += SEVERITY_PENALTY.get(sev, 0)

        code = (f.raw or {}).get("code", "")
        category = (f.raw or {}).get("category") or _category_from_finding(f)
        cat = by_category.setdefault(category, {"violations": 0, "by_severity": {}})
        cat["violations"] += 1
        cat["by_severity"][sev.name] = cat["by_severity"].get(sev.name, 0) + 1

        items.append({
            "code": code,
            "category": category,
            "severity": sev.name,
            "title": f.title,
            "resource": (f.resources[0].id if f.resources and f.resources[0].id else "-"),
            "remediation": f.remediation,
        })

    score = max(0, 100 - penalty)
    return {
        "score": score,
        "grade": _grade(score),
        "total_violations": len(comp),
        "by_severity": by_severity,
        "by_category": by_category,
        "items": items,
    }


def _category_from_finding(f: SecurityFinding) -> str:
    # raw에 category가 없으면 standards/타입에서 유추 불가 → 기타
    return "기타"


def format_report_text(report: dict) -> str:
    """리포트를 사람이 읽는 텍스트로(터미널/알림용)."""
    lines = [
        "===== AWS 컴플라이언스 리포트 =====",
        f"점수: {report['score']}/100  (등급 {report['grade']})",
        f"위반 항목: {report['total_violations']}건",
        "",
        "[심각도별]",
    ]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    for s in order:
        n = report["by_severity"].get(s, 0)
        if n:
            lines.append(f"  - {s}: {n}")
    lines.append("")
    lines.append("[카테고리별]")
    for cat, info in sorted(report["by_category"].items(), key=lambda x: -x[1]["violations"]):
        lines.append(f"  - {cat}: {info['violations']}건")
    if report["items"]:
        lines.append("")
        lines.append("[위반 상세]")
        for it in sorted(report["items"], key=lambda x: x["code"]):
            lines.append(f"  [{it['code']}] ({it['severity']}) {it['title']} — {it['resource']}")
    return "\n".join(lines)



def demo_report() -> dict:
    """웹 콘솔용 데모 리포트: 등록된 모든 체크가 '위반'이라고 가정해 리포트를 계산.

    AWS 자격증명 없이 리포트 UI/점수 산정 방식을 보여주기 위한 예시다.
    """
    from ..models import Resource, SecurityFinding, utcnow
    from .registry import all_checks

    findings = []
    for c in all_checks():
        findings.append(SecurityFinding(
            id=f"compliance:{c.code}:demo",
            source="compliance",
            title=f"[{c.code}] {c.title}",
            severity=c.severity,
            finding_type=c.finding_type,
            resources=[Resource(type="AwsAccount", id="demo")],
            created_at=utcnow(),
            updated_at=utcnow(),
            remediation=c.remediation,
            raw={"code": c.code, "category": c.category, "standards": list(c.standards)},
        ))
    return build_report(findings)
