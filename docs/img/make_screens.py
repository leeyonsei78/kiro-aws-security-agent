"""매뉴얼용 웹 콘솔 화면 이미지(SVG) 생성기.

이 sandbox에는 브라우저(chromium)가 없어 실제 렌더링 캡처가 불가능하므로,
실제 webui/page.py 의 색상·레이아웃을 그대로 반영한 SVG mockup을 생성한다.
표시되는 데이터(정규화 결과)는 preview_parse의 실제 출력과 동일하다.

실행: python docs/img/make_screens.py
결과: docs/img/*.svg
"""

from __future__ import annotations

import html
import os

# webui/page.py 의 실제 팔레트
BG = "#0f172a"; PANEL = "#1e293b"; PANEL2 = "#273449"; TEXT = "#e2e8f0"
MUTED = "#94a3b8"; ACCENT = "#38bdf8"; BORDER = "#334155"
SEV = {"CRITICAL": ("#ef4444", "#ffffff"), "HIGH": ("#f97316", "#0b1220"),
       "MEDIUM": ("#eab308", "#0b1220"), "LOW": ("#3b82f6", "#ffffff"),
       "INFORMATIONAL": ("#64748b", "#ffffff")}

W = 1100
FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif"
MONO = "ui-monospace,Menlo,monospace"


def esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def rect(x, y, w, h, fill, rx=8, stroke=None, sw=1):
    s = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"'
    if stroke:
        s += f' stroke="{stroke}" stroke-width="{sw}"'
    return s + "/>"


def text(x, y, s, fill=TEXT, size=14, weight="normal", family=FONT, anchor="start"):
    return (f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
            f'font-weight="{weight}" font-family="{family}" text-anchor="{anchor}">{esc(s)}</text>')


def sev_badge(x, y, label):
    bg, fg = SEV[label]
    w = 22 + len(label) * 7.2
    return rect(x, y, w, 20, bg, rx=6) + text(x + w / 2, y + 14, label, fill=fg, size=11, weight="bold", anchor="middle"), w


def header():
    parts = [rect(0, 0, W, 56, PANEL, rx=0)]
    parts.append(text(24, 35, "🛡️ AWS Security Agent", size=18, weight="600"))
    parts.append(text(250, 35, "검증 콘솔 — 로그/이벤트를 붙여넣어 파싱·정규화·필터 결과를 확인", fill=MUTED, size=13))
    parts.append(f'<line x1="0" y1="56" x2="{W}" y2="56" stroke="{BORDER}"/>')
    return "".join(parts)


def tabs(active, x=24, y=76):
    labels = [("firewall", "써드파티 방화벽 로그"), ("event", "AWS 이벤트(JSON)")]
    out = []
    cx = x
    for key, lab in labels:
        w = 20 + len(lab) * 11
        is_active = key == active
        out.append(rect(cx, y, w, 32, PANEL2, rx=8, stroke=ACCENT if is_active else BORDER))
        out.append(text(cx + w / 2, y + 21, lab, fill=TEXT if is_active else MUTED, size=13, anchor="middle"))
        cx += w + 8
    return "".join(out)


def input_box(x, y, w, h, lines, placeholder=False):
    out = [rect(x, y, w, h, "#0b1220", rx=8, stroke=BORDER)]
    ty = y + 20
    color = MUTED if placeholder else TEXT
    for ln in lines:
        # 폭 초과분 자르기
        maxc = int((w - 20) / 7.0)
        out.append(text(x + 10, ty, ln[:maxc], fill=color, size=12.5, family=MONO))
        ty += 18
    return "".join(out)


def chip(x, y, label, w=None):
    w = w or (18 + len(label) * 7.4)
    return rect(x, y, w, 22, PANEL2, rx=11, stroke=BORDER) + \
        text(x + w / 2, y + 15, label, fill=MUTED, size=11.5, anchor="middle"), w


def button(x, y, label, primary=True):
    w = 24 + len(label) * 9
    bg = ACCENT if primary else PANEL2
    fg = "#04283b" if primary else TEXT
    return rect(x, y, w, 34, bg, rx=8, stroke=None if primary else BORDER) + \
        text(x + w / 2, y + 22, label, fill=fg, size=13, weight="600", anchor="middle"), w


def left_panel(active_tab, vendor_val, sev_val, input_lines, placeholder, chips):
    x, y, w = 24, 120, 520
    out = [rect(x, y, w, 470, PANEL, rx=10, stroke=BORDER)]
    out.append(tabs(active_tab, x + 16, y + 16))
    inner = x + 16
    label_y = y + 78
    if active_tab == "firewall":
        out.append(text(inner, label_y, "벤더", fill=MUTED, size=12))
        out.append(rect(inner, label_y + 8, 180, 30, PANEL2, rx=8, stroke=BORDER))
        out.append(text(inner + 10, label_y + 28, vendor_val + "  ▾", size=13))
        out.append(text(inner, label_y + 62, "방화벽 로그 (한 줄에 하나)", fill=MUTED, size=12))
        out.append(input_box(inner, label_y + 70, w - 32, 150, input_lines, placeholder))
        cy = label_y + 232
    else:
        out.append(text(inner, label_y, "EventBridge 이벤트 JSON", fill=MUTED, size=12))
        out.append(input_box(inner, label_y + 8, w - 32, 210, input_lines, placeholder))
        cy = label_y + 230
    # 샘플 칩
    cx = inner
    for c in chips:
        s, cw = chip(cx, cy, c)
        out.append(s)
        cx += cw + 6
        if cx > x + w - 120:
            cx = inner
            cy += 28
    # 최소 심각도 + 버튼
    by = y + 400
    out.append(text(inner, by, "최소 심각도(필터)", fill=MUTED, size=12))
    out.append(rect(inner, by + 8, 150, 30, PANEL2, rx=8, stroke=BORDER))
    out.append(text(inner + 10, by + 28, sev_val + "  ▾", size=13))
    b1, w1 = button(inner + 165, by + 6, "분석", primary=True)
    out.append(b1)
    b2, _ = button(inner + 165 + w1 + 10, by + 6, "지우기", primary=False)
    out.append(b2)
    return "".join(out)


def summary_line(x, y, total, matched, filtered, minsev):
    parts = []
    segs = [("정규화: ", str(total), "건   "), ("필터 통과: ", str(matched), "건   "),
            ("제외: ", str(filtered), "건   "), ("최소 심각도: ", minsev, "")]
    cx = x
    for pre, val, post in segs:
        parts.append(text(cx, y, pre, fill=TEXT, size=13)); cx += len(pre) * 7.3
        parts.append(text(cx, y, val, fill=ACCENT, size=13, weight="700")); cx += len(val) * 8
        parts.append(text(cx, y, post, fill=TEXT, size=13)); cx += len(post) * 7.3
    return "".join(parts)


def finding_card(x, y, w, f, dimmed=False):
    op = ' opacity="0.45"' if dimmed else ""
    out = [f'<g{op}>']
    out.append(rect(x, y, w, 78, PANEL2, rx=8, stroke=BORDER))
    badge, bw = sev_badge(x + 12, y + 12, f["severity"])
    out.append(badge)
    tx = x + 12 + bw + 10
    out.append(text(tx, y + 27, f["title"], size=14, weight="600"))
    if dimmed:
        out.append(rect(x + w - 92, y + 12, 80, 20, PANEL, rx=6, stroke=BORDER))
        out.append(text(x + w - 52, y + 26, "필터 제외", fill=MUTED, size=11, anchor="middle"))
    out.append(text(x + 12, y + 50, f"source: {f['source']}  ·  type: {f['type']}", fill=MUTED, size=12))
    out.append(text(x + 12, y + 68, f"resource: {f['res']}  ·  account: {f['acct']}  ·  region: {f['region']}", fill=MUTED, size=12))
    out.append("</g>")
    return "".join(out)


def right_panel(summary, findings):
    x, y, w = 560, 120, 516
    out = [rect(x, y, w, 470, PANEL, rx=10, stroke=BORDER)]
    if summary is None:
        out.append(text(x + w / 2, y + 230, "결과가 여기에 표시됩니다.", fill=MUTED, size=13, anchor="middle"))
        return "".join(out)
    out.append(summary_line(x + 18, y + 30, *summary))
    cy = y + 54
    for f in findings:
        out.append(finding_card(x + 16, cy, w - 32, f, dimmed=f.get("dim", False)))
        cy += 88
    return "".join(out)


def svg(body, h=610):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" '
            f'viewBox="0 0 {W} {h}" font-family="{FONT}">'
            f'{rect(0,0,W,h,BG,rx=0)}{body}</svg>')


def write(name, body):
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(svg(body))
    print("wrote", path)


# --- 실제 preview_parse 출력과 동일한 데이터 ---
FORT_LINE = 'devname="FGT60F" logid="0419016384" type="utm" subtype="ips" level="alert" srcip=203.0.113.5 dstip=10.0.0.7 action="dropped" attack="Backdoor.Double.Door"'
FW_CHIPS = ["Fortinet (IPS/alert)", "Palo Alto (THREAT)", "Check Point", "CEF (공통)"]
EV_CHIPS = ["GuardDuty Finding", "Security Hub (S3 public)"]

fort_finding = {"severity": "CRITICAL", "title": "FortiGate ips - Backdoor.Double.Door",
                "source": "firewall/fortinet", "type": "Firewall:Fortinet/ips/Threat",
                "res": "203.0.113.5", "acct": "-", "region": "-"}
cp_finding = {"severity": "HIGH", "title": "Check Point SmartDefense - Port Scan",
              "source": "firewall/checkpoint", "type": "Firewall:CheckPoint/SmartDefense/Threat",
              "res": "203.0.113.11", "acct": "-", "region": "-", "dim": True}
gd_finding = {"severity": "HIGH", "title": "SSH brute force against i-0abc",
              "source": "guardduty", "type": "UnauthorizedAccess:EC2/SSHBruteForce",
              "res": "i-0abc", "acct": "111122223333", "region": "ap-northeast-2"}


def screen_initial():
    body = header() + left_panel("firewall", "auto", "MEDIUM",
                                 ["예) devname=... type=utm subtype=ips level=alert srcip=... attack=..."],
                                 True, FW_CHIPS) + right_panel(None, [])
    write("01_initial.svg", body)


def screen_fortinet():
    body = header() + left_panel("firewall", "auto", "MEDIUM",
                                 [FORT_LINE], False, FW_CHIPS) + \
        right_panel((1, 1, 0, "MEDIUM"), [fort_finding])
    write("02_fortinet.svg", body)


def screen_filter():
    body = header() + left_panel("firewall", "auto", "CRITICAL",
                                 ['product="SmartDefense" action="Drop" src=203.0.113.11 attack="Port Scan" severity="High"'],
                                 False, FW_CHIPS) + \
        right_panel((1, 0, 1, "CRITICAL"), [cp_finding])
    write("03_filter.svg", body)


def screen_event():
    body = header() + left_panel("event", "auto", "MEDIUM",
                                 ['{', '  "source": "aws.guardduty",',
                                  '  "detail-type": "GuardDuty Finding",',
                                  '  "detail": { "Type": "Unauthorized', '    Access:EC2/SSHBruteForce", ... }', '}'],
                                 False, EV_CHIPS) + \
        right_panel((1, 1, 0, "MEDIUM"), [gd_finding])
    write("04_event.svg", body)


if __name__ == "__main__":
    screen_initial()
    screen_fortinet()
    screen_filter()
    screen_event()
    print("done")
