"""웹 검증 UI의 단일 HTML 페이지 (외부 의존성 없음)."""

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWS Security Agent · 검증 콘솔</title>
<style>
  :root {
    --bg:#0f172a; --panel:#1e293b; --panel2:#273449; --text:#e2e8f0; --muted:#94a3b8;
    --accent:#38bdf8; --border:#334155;
    --crit:#ef4444; --high:#f97316; --med:#eab308; --low:#3b82f6; --info:#64748b;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:var(--bg); color:var(--text); }
  header { padding:18px 24px; border-bottom:1px solid var(--border); display:flex;
           align-items:center; gap:12px; }
  header h1 { font-size:18px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:13px; }
  main { display:grid; grid-template-columns:1fr 1fr; gap:16px; padding:20px 24px; }
  @media (max-width: 960px){ main{ grid-template-columns:1fr; } }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }
  .tabs { display:flex; gap:8px; margin-bottom:12px; }
  .tab { padding:7px 14px; border-radius:8px; cursor:pointer; background:var(--panel2);
         color:var(--muted); border:1px solid var(--border); font-size:13px; }
  .tab.active { color:var(--text); border-color:var(--accent); }
  label { display:block; font-size:12px; color:var(--muted); margin:10px 0 4px; }
  textarea { width:100%; min-height:220px; background:#0b1220; color:var(--text);
             border:1px solid var(--border); border-radius:8px; padding:10px; font-family:ui-monospace,Menlo,monospace;
             font-size:12.5px; resize:vertical; }
  select, .btn { background:var(--panel2); color:var(--text); border:1px solid var(--border);
                 border-radius:8px; padding:8px 12px; font-size:13px; cursor:pointer; }
  .btn.primary { background:var(--accent); color:#04283b; border-color:var(--accent); font-weight:600; }
  .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:12px; }
  .samples { display:flex; gap:6px; flex-wrap:wrap; margin-top:6px; }
  .chip { font-size:11.5px; padding:4px 9px; border-radius:999px; background:var(--panel2);
          border:1px solid var(--border); color:var(--muted); cursor:pointer; }
  .chip:hover { color:var(--text); border-color:var(--accent); }
  .summary { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:12px; font-size:13px; }
  .summary b { color:var(--accent); }
  .finding { border:1px solid var(--border); border-radius:8px; padding:10px 12px; margin-bottom:8px;
             background:var(--panel2); }
  .finding.dim { opacity:.5; }
  .finding .top { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .sev { font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; color:#0b1220; }
  .sev.CRITICAL{background:var(--crit);color:#fff;} .sev.HIGH{background:var(--high);}
  .sev.MEDIUM{background:var(--med);} .sev.LOW{background:var(--low);color:#fff;} .sev.INFORMATIONAL{background:var(--info);color:#fff;}
  .finding .title { font-weight:600; font-size:14px; }
  .finding .meta { color:var(--muted); font-size:12px; margin-top:4px; word-break:break-all; }
  .badge { font-size:11px; color:var(--muted); border:1px solid var(--border); padding:1px 7px; border-radius:6px; }
  .empty { color:var(--muted); font-size:13px; padding:20px; text-align:center; }
  .err { color:var(--crit); font-size:13px; margin-top:10px; white-space:pre-wrap; }
  code { color:var(--accent); }
</style>
</head>
<body>
<header>
  <h1>🛡️ AWS Security Agent</h1>
  <span class="sub">검증 콘솔 — 로그/이벤트를 붙여넣어 파싱·정규화·필터 결과를 확인</span>
</header>
<main>
  <section class="card">
    <div class="tabs">
      <div class="tab active" data-tab="firewall" onclick="switchTab('firewall')">써드파티 방화벽 로그</div>
      <div class="tab" data-tab="event" onclick="switchTab('event')">AWS 이벤트(JSON)</div>
    </div>

    <div id="pane-firewall">
      <label>벤더</label>
      <select id="vendor"></select>
      <label>방화벽 로그 (한 줄에 하나)</label>
      <textarea id="fw-input" placeholder="예) devname=... type=utm subtype=ips level=alert srcip=... attack=..."></textarea>
      <div class="samples" id="fw-samples"></div>
    </div>

    <div id="pane-event" style="display:none">
      <label>EventBridge 이벤트 JSON</label>
      <textarea id="ev-input" placeholder='{"detail-type":"GuardDuty Finding","detail":{...}}'></textarea>
      <div class="samples" id="ev-samples"></div>
    </div>

    <div class="row">
      <div>
        <label style="margin:0">최소 심각도(필터)</label>
        <select id="min-sev"></select>
      </div>
      <button class="btn primary" style="align-self:flex-end" onclick="analyze()">분석</button>
      <button class="btn" style="align-self:flex-end" onclick="clearAll()">지우기</button>
    </div>
    <div class="err" id="err"></div>
  </section>

  <section class="card">
    <div class="summary" id="summary"><span class="empty">결과가 여기에 표시됩니다.</span></div>
    <div id="results"></div>
  </section>
</main>

<script>
const FW_SAMPLES = {
  "Fortinet (IPS/alert)": 'devname="FGT60F" logid="0419016384" type="utm" subtype="ips" level="alert" srcip=203.0.113.5 dstip=10.0.0.7 action="dropped" attack="Backdoor.Double.Door"',
  "Palo Alto (THREAT)": '1,2026/09/09 00:00:00,001901000001,THREAT,vulnerability,2049,2026/09/09 00:00:00,203.0.113.9,10.0.0.20,0.0.0.0,0.0.0.0,rule1,,,web-browsing,vsys1,trust,untrust,eth1/1,eth1/2,fwd,2026/09/09 00:00:00,12345,1,80,443,0,0,0x0,tcp,reset-both,"evil.com/x",SQL-Injection(9999),any,high,client-to-server',
  "Check Point": 'product="SmartDefense" action="Drop" src=203.0.113.11 dst=10.0.0.30 proto=tcp service=445 attack="Port Scan" severity="High"',
  "CEF (공통)": 'CEF:0|Palo Alto Networks|PAN-OS|10.1|spyware|Spyware Detected|8|src=203.0.113.20 dst=10.0.0.40 act=blocked'
};
const EV_SAMPLES = {
  "GuardDuty Finding": {
    "source":"aws.guardduty","detail-type":"GuardDuty Finding",
    "detail":{"Id":"gd-1","Type":"UnauthorizedAccess:EC2/SSHBruteForce","Title":"SSH brute force","Description":"i-0abc SSH probe","Severity":8.0,"AccountId":"111122223333","Region":"ap-northeast-2","Resource":{"ResourceType":"Instance","InstanceDetails":{"InstanceId":"i-0abc"}}}
  },
  "Security Hub (S3 public)": {
    "source":"aws.securityhub","detail-type":"Security Hub Findings - Imported",
    "detail":{"findings":[{"Id":"sh-1","Title":"S3 bucket is public","Description":"public read","Severity":{"Label":"CRITICAL","Normalized":90},"Types":["Effects/Data Exposure"],"AwsAccountId":"111122223333","Region":"ap-northeast-2","Resources":[{"Type":"AwsS3Bucket","Id":"arn:aws:s3:::my-bucket","Region":"ap-northeast-2"}]}]}
  }
};

let META = {vendors:["auto"], severities:["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"]};

async function loadMeta(){
  try {
    const r = await fetch('/api/meta'); META = await r.json();
  } catch(e) {}
  const v = document.getElementById('vendor');
  v.innerHTML = META.vendors.map(x=>`<option value="${x}">${x}</option>`).join('');
  const ms = document.getElementById('min-sev');
  ms.innerHTML = META.severities.map(x=>`<option value="${x}" ${x==='MEDIUM'?'selected':''}>${x}</option>`).join('');
  // 샘플 칩
  document.getElementById('fw-samples').innerHTML =
    Object.keys(FW_SAMPLES).map(k=>`<span class="chip" onclick="loadFw('${k.replace(/'/g,"\\'")}')">${k}</span>`).join('');
  document.getElementById('ev-samples').innerHTML =
    Object.keys(EV_SAMPLES).map(k=>`<span class="chip" onclick="loadEv('${k.replace(/'/g,"\\'")}')">${k}</span>`).join('');
}
function loadFw(k){ document.getElementById('fw-input').value = FW_SAMPLES[k]; }
function loadEv(k){ document.getElementById('ev-input').value = JSON.stringify(EV_SAMPLES[k], null, 2); }

let currentTab = 'firewall';
function switchTab(t){
  currentTab = t;
  document.querySelectorAll('.tab').forEach(el=>el.classList.toggle('active', el.dataset.tab===t));
  document.getElementById('pane-firewall').style.display = t==='firewall'?'block':'none';
  document.getElementById('pane-event').style.display = t==='event'?'block':'none';
}
function clearAll(){
  document.getElementById('fw-input').value='';
  document.getElementById('ev-input').value='';
  document.getElementById('results').innerHTML='';
  document.getElementById('summary').innerHTML='<span class="empty">결과가 여기에 표시됩니다.</span>';
  document.getElementById('err').textContent='';
}

async function analyze(){
  document.getElementById('err').textContent='';
  const minSev = document.getElementById('min-sev').value;
  let url, body;
  if (currentTab==='firewall'){
    url='/api/firewall';
    body={ raw: document.getElementById('fw-input').value, vendor: document.getElementById('vendor').value, min_severity: minSev };
  } else {
    url='/api/event';
    body={ event: document.getElementById('ev-input').value, min_severity: minSev };
  }
  try {
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    const data = await r.json();
    render(data);
  } catch(e){ document.getElementById('err').textContent='요청 실패: '+e; }
}

function render(data){
  if(!data.ok){
    document.getElementById('err').textContent = (data.reason||data.error||'파싱 실패')
      + (data.supported? '\n지원 detail-type: '+data.supported.join(', ') : '');
    document.getElementById('summary').innerHTML='<span class="empty">-</span>';
    document.getElementById('results').innerHTML='';
    return;
  }
  document.getElementById('summary').innerHTML =
    `<span>정규화: <b>${data.total}</b>건</span>`+
    `<span>필터 통과: <b>${data.matched}</b>건</span>`+
    `<span>제외: <b>${data.filtered_out}</b>건</span>`+
    `<span>최소 심각도: <b>${data.min_severity}</b></span>`;

  const matchedIds = new Set(data.matched_findings.map(f=>f.id));
  const rows = data.all_findings.map(f=>{
    const passed = matchedIds.has(f.id);
    const res = (f.resources&&f.resources[0]&&f.resources[0].id)||'-';
    return `<div class="finding ${passed?'':'dim'}">
      <div class="top">
        <span class="sev ${f.severity}">${f.severity}</span>
        <span class="title">${esc(f.title)}</span>
        ${passed?'':'<span class="badge">필터 제외</span>'}
      </div>
      <div class="meta">source: <code>${esc(f.source)}</code> · type: ${esc(f.finding_type||'-')}<br>
        resource: ${esc(res)} · account: ${esc(f.account_id||'-')} · region: ${esc(f.region||'-')}</div>
    </div>`;
  }).join('');
  document.getElementById('results').innerHTML = rows || '<div class="empty">정규화된 finding이 없습니다. 입력을 확인하세요.</div>';
}
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

loadMeta();
</script>
</body>
</html>
"""
