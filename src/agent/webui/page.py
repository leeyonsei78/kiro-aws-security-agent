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
    --accent:#38bdf8; --border:#334155; --green:#22c55e;
    --crit:#ef4444; --high:#f97316; --med:#eab308; --low:#3b82f6; --info:#64748b;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:var(--bg); color:var(--text); }
  header { padding:18px 24px; border-bottom:1px solid var(--border); display:flex;
           align-items:center; gap:12px; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:13px; }
  main { display:grid; grid-template-columns:1fr 1fr; gap:16px; padding:20px 24px; }
  @media (max-width: 1000px){ main{ grid-template-columns:1fr; } }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }
  .tabs { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
  .tab { padding:7px 14px; border-radius:8px; cursor:pointer; background:var(--panel2);
         color:var(--muted); border:1px solid var(--border); font-size:13px; }
  .tab.active { color:var(--text); border-color:var(--accent); }
  label { display:block; font-size:12px; color:var(--muted); margin:10px 0 4px; }
  textarea { width:100%; min-height:200px; background:#0b1220; color:var(--text);
             border:1px solid var(--border); border-radius:8px; padding:10px; font-family:ui-monospace,Menlo,monospace;
             font-size:12.5px; resize:vertical; }
  select, .btn { background:var(--panel2); color:var(--text); border:1px solid var(--border);
                 border-radius:8px; padding:8px 12px; font-size:13px; cursor:pointer; }
  .btn.primary { background:var(--accent); color:#04283b; border-color:var(--accent); font-weight:600; }
  .row { display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap; margin-top:12px; }
  .samples { display:flex; gap:6px; flex-wrap:wrap; margin-top:6px; }
  .chip { font-size:11.5px; padding:4px 9px; border-radius:999px; background:var(--panel2);
          border:1px solid var(--border); color:var(--muted); cursor:pointer; }
  .chip:hover { color:var(--text); border-color:var(--accent); }
  .toggle { display:flex; gap:0; border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  .toggle div { padding:8px 12px; font-size:12.5px; cursor:pointer; color:var(--muted); background:var(--panel2); }
  .toggle div.on { background:var(--accent); color:#04283b; font-weight:600; }
  .summary { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:12px; font-size:13px; }
  .summary b { color:var(--accent); }
  h3.sec { font-size:13px; color:var(--muted); margin:16px 0 8px; text-transform:uppercase; letter-spacing:.04em; }
  .finding { border:1px solid var(--border); border-radius:8px; padding:10px 12px; margin-bottom:8px; background:var(--panel2); }
  .finding.dim { opacity:.5; }
  .finding .top { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .sev { font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; color:#0b1220; }
  .sev.CRITICAL{background:var(--crit);color:#fff;} .sev.HIGH{background:var(--high);}
  .sev.MEDIUM{background:var(--med);} .sev.LOW{background:var(--low);color:#fff;} .sev.INFORMATIONAL{background:var(--info);color:#fff;}
  .finding .title { font-weight:600; font-size:14px; }
  .finding .meta { color:var(--muted); font-size:12px; margin-top:4px; word-break:break-all; }
  .badge { font-size:11px; color:var(--muted); border:1px solid var(--border); padding:1px 7px; border-radius:6px; }
  .notif { border:1px solid var(--border); border-radius:8px; margin-bottom:8px; background:var(--panel2); }
  .notif .hd { padding:8px 12px; font-size:13px; font-weight:600; border-bottom:1px solid var(--border); }
  .notif pre { margin:0; padding:10px 12px; font-family:ui-monospace,Menlo,monospace; font-size:12px;
               white-space:pre-wrap; word-break:break-all; color:var(--text); max-height:220px; overflow:auto; }
  .rem { border:1px solid var(--border); border-radius:8px; padding:10px 12px; margin-bottom:8px; background:var(--panel2); }
  .rem .top { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .st { font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; }
  .st.DRY_RUN{background:#1e3a8a;color:#bfdbfe;} .st.APPLIED{background:var(--green);color:#04283b;}
  .st.SKIPPED,.st.NO_ACTION{background:var(--panel);color:var(--muted);border:1px solid var(--border);}
  .st.FAILED,.st.ERROR{background:var(--crit);color:#fff;}
  .rem code { color:var(--accent); font-size:12px; }
  .rem .params { color:var(--muted); font-size:11.5px; margin-top:4px; font-family:ui-monospace,Menlo,monospace; word-break:break-all; }
  .empty { color:var(--muted); font-size:13px; padding:20px; text-align:center; }
  .err { color:var(--crit); font-size:13px; margin-top:10px; white-space:pre-wrap; }
  code { color:var(--accent); }
  .hint { color:var(--muted); font-size:11.5px; margin-top:6px; }
  .scorecard { display:flex; align-items:center; gap:16px; padding:14px 16px; margin-bottom:12px;
               border:1px solid var(--border); border-radius:10px; background:var(--panel2); }
  .scorecard .num { font-size:38px; font-weight:800; line-height:1; }
  .grade-A,.grade-B{color:var(--green);} .grade-C{color:var(--med);}
  .grade-D{color:var(--high);} .grade-F{color:var(--crit);}
  .catbar { display:flex; align-items:center; gap:8px; margin:4px 0; font-size:12.5px; }
  .catbar .bar { height:8px; border-radius:4px; background:var(--accent); }
  .catbar .lbl { width:90px; color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>🛡️ AWS Security Agent</h1>
  <span class="sub">검증 콘솔 — 로그/이벤트를 붙여넣어 전체 파이프라인(정규화·필터·알림·자동대응)을 확인</span>
</header>
<main>
  <section class="card">
    <div class="tabs">
      <div class="tab active" data-tab="overview" onclick="switchTab('overview')">전체 기능 개요</div>
      <div class="tab" data-tab="firewall" onclick="switchTab('firewall')">써드파티 방화벽 로그</div>
      <div class="tab" data-tab="event" onclick="switchTab('event')">AWS 이벤트(JSON)</div>
      <div class="tab" data-tab="compliance" onclick="switchTab('compliance')">컴플라이언스 점검 항목</div>
    </div>

    <div id="pane-overview">
      <p class="hint" style="font-size:13px">이 에이전트가 제공하는 <b>전체 기능</b>입니다. 수집(Collector) → 정규화 → 필터 → 알림(Notifier) → 자동 대응(Remediator) 파이프라인과 지원 항목을 한눈에 보여줍니다. 각 탭에서 실제 동작을 테스트할 수 있습니다.</p>
      <div class="row" style="margin-top:8px"><button class="btn primary" onclick="showOverview()">기능 개요 불러오기</button></div>
    </div>

    <div id="pane-firewall" style="display:none">
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

    <div id="pane-compliance" style="display:none">
      <p class="hint" style="font-size:13px">이 에이전트가 점검하는 <b>AWS 컴플라이언스 항목</b> 목록입니다. 실제 점검은 배포된 에이전트가 AWS 계정을 스캔해 위반을 finding으로 산출하고 <b>점수/리포트</b>로 요약합니다(웹 콘솔은 항목 카탈로그 및 데모 리포트 표시). 항목 체계는 KISA 기반 <a href="https://github.com/cdppcorp/KESE-KIT" style="color:var(--accent)">KESE-KIT</a>(MIT)의 클라우드 점검 코드 방식을 참고했습니다.</p>
      <div class="row" style="margin-top:8px">
        <button class="btn" onclick="showChecks()">점검 항목 목록</button>
        <button class="btn primary" onclick="showReport()">데모 리포트 보기</button>
      </div>
    </div>

    <div class="row" id="controls-row">
      <div>
        <label style="margin:0">모드</label>
        <div class="toggle" id="mode-toggle">
          <div data-mode="parse" class="on" onclick="setMode('parse')">파싱·필터만</div>
          <div data-mode="pipeline" onclick="setMode('pipeline')">전체 파이프라인</div>
        </div>
      </div>
      <div>
        <label style="margin:0">최소 심각도(필터)</label>
        <select id="min-sev"></select>
      </div>
      <button class="btn primary" onclick="analyze()">분석</button>
      <button class="btn" onclick="clearAll()">지우기</button>
    </div>
    <div class="hint" id="mode-hint">전체 파이프라인 모드는 <b>알림 메시지 미리보기</b>와 <b>자동 대응 dry-run 계획</b>까지 보여줍니다(실제 전송·변경 없음).</div>
    <div class="err" id="err"></div>
  </section>

  <section class="card">
    <div class="summary" id="summary"><span class="empty">결과가 여기에 표시됩니다.</span></div>
    <div id="results"></div>
  </section>
</main>

<script>
const FW_SAMPLES = {
  "Fortinet IPS(alert)": 'devname="FGT60F" logid="0419016384" type="utm" subtype="ips" level="alert" srcip=203.0.113.5 dstip=10.0.0.7 action="dropped" attack="Backdoor.Double.Door"',
  "Fortinet 차단(traffic)": 'devname="FGT" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=198.51.100.4 dstip=10.0.0.9 action="deny" service="HTTPS"',
  "Palo Alto THREAT": '1,2026/09/09 00:00:00,001901000001,THREAT,vulnerability,2049,2026/09/09 00:00:00,203.0.113.9,10.0.0.20,0.0.0.0,0.0.0.0,rule1,,,web-browsing,vsys1,trust,untrust,eth1/1,eth1/2,fwd,2026/09/09 00:00:00,12345,1,80,443,0,0,0x0,tcp,reset-both,"evil.com/x",SQL-Injection(9999),any,high,client-to-server',
  "Palo Alto TRAFFIC": '1,2026/09/09 00:00:00,001901000001,TRAFFIC,end,2049,2026/09/09 00:00:00,192.0.2.10,10.0.0.5,0.0.0.0,0.0.0.0,rule1,,,ssl,vsys1,trust,untrust,eth1/1,eth1/2,fwd,2026/09/09,111,1,443,50000,0,0,0x0,tcp,allow',
  "Check Point": 'product="SmartDefense" action="Drop" src=203.0.113.11 dst=10.0.0.30 proto=tcp service=445 attack="Port Scan" severity="High"',
  "CEF(공통)": 'CEF:0|Palo Alto Networks|PAN-OS|10.1|spyware|Spyware Detected|8|src=203.0.113.20 dst=10.0.0.40 act=blocked',
  "여러 줄 혼합": 'devname="FGT" logid="1" type="utm" subtype="ips" level="alert" srcip=203.0.113.5 attack="Backdoor"\nproduct="SmartDefense" action="Drop" src=203.0.113.11 attack="Port Scan" severity="High"\nCEF:0|Fortinet|FortiGate|7.0|1|Malware|9|src=198.51.100.7 act=blocked',
};
const EV_SAMPLES = {
  "GuardDuty SSH BruteForce (→NACL 차단)": {
    "source":"aws.guardduty","detail-type":"GuardDuty Finding",
    "detail":{"Id":"gd-ssh","Type":"UnauthorizedAccess:EC2/SSHBruteForce","Title":"SSH brute force against i-0abc","Description":"EC2 i-0abc SSH probe","Severity":8.0,"AccountId":"111122223333","Region":"ap-northeast-2",
      "Service":{"Action":{"NetworkConnectionAction":{"RemoteIpDetails":{"IpAddressV4":"203.0.113.5"}}}},
      "Resource":{"ResourceType":"Instance","InstanceDetails":{"InstanceId":"i-0abc","NetworkInterfaces":[{"SubnetId":"subnet-1"}]}}}
  },
  "GuardDuty EC2 백도어 (→EC2 격리*)": {
    "source":"aws.guardduty","detail-type":"GuardDuty Finding",
    "detail":{"Id":"gd-c2","Type":"Backdoor:EC2/C&CActivity.B","Title":"C2 activity","Severity":8.5,"AccountId":"111122223333","Region":"ap-northeast-2",
      "Resource":{"ResourceType":"Instance","InstanceDetails":{"InstanceId":"i-0def","NetworkInterfaces":[{"SecurityGroups":[{"GroupId":"sg-web"}]}]}}}
  },
  "GuardDuty IAM 자격증명 (→키 비활성화*)": {
    "source":"aws.guardduty","detail-type":"GuardDuty Finding",
    "detail":{"Id":"gd-iam","Type":"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS","Title":"Creds exfil","Severity":8.0,"AccountId":"111122223333","Region":"ap-northeast-2",
      "Resource":{"AccessKeyDetails":{"AccessKeyId":"AKIAEXAMPLE12345","UserName":"alice","UserType":"IAMUser"}}}
  },
  "Security Hub S3 public (→S3 차단*)": {
    "source":"aws.securityhub","detail-type":"Security Hub Findings - Imported",
    "detail":{"findings":[{"Id":"sh-s3","Title":"S3 bucket is public","Description":"public read","Severity":{"Label":"CRITICAL","Normalized":90},"Types":["Effects/Data Exposure"],"AwsAccountId":"111122223333","Region":"ap-northeast-2","Resources":[{"Type":"AwsS3Bucket","Id":"arn:aws:s3:::my-bucket","Region":"ap-northeast-2"}]}]}
  },
  "Access Analyzer 외부공유": {
    "source":"aws.access-analyzer","detail-type":"Access Analyzer Finding",
    "detail":{"id":"aa-1","resourceType":"AWS::S3::Bucket","resource":"arn:aws:s3:::exposed","isPublic":true,"status":"ACTIVE","action":["s3:GetObject"],"principal":{"AWS":"*"}}
  },
};

let META = {vendors:["auto"], severities:["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"]};
let CAPS = null;
let currentTab = 'overview';
let currentMode = 'parse';

async function loadMeta(){
  try { META = await (await fetch('/api/meta')).json(); } catch(e) {}
  document.getElementById('vendor').innerHTML = META.vendors.map(x=>`<option value="${x}">${x}</option>`).join('');
  document.getElementById('min-sev').innerHTML = META.severities.map(x=>`<option value="${x}" ${x==='MEDIUM'?'selected':''}>${x}</option>`).join('');
  document.getElementById('fw-samples').innerHTML = Object.keys(FW_SAMPLES).map(k=>`<span class="chip" onclick="loadFw('${jsEsc(k)}')">${esc(k)}</span>`).join('');
  document.getElementById('ev-samples').innerHTML = Object.keys(EV_SAMPLES).map(k=>`<span class="chip" onclick="loadEv('${jsEsc(k)}')">${esc(k)}</span>`).join('');
}
function jsEsc(s){ return s.replace(/\\/g,"\\\\").replace(/'/g,"\\'"); }
function loadFw(k){ document.getElementById('fw-input').value = FW_SAMPLES[k]; }
function loadEv(k){ document.getElementById('ev-input').value = JSON.stringify(EV_SAMPLES[k], null, 2); }

function switchTab(t){
  currentTab = t;
  document.querySelectorAll('.tab').forEach(el=>el.classList.toggle('active', el.dataset.tab===t));
  document.getElementById('pane-overview').style.display = t==='overview'?'block':'none';
  document.getElementById('pane-firewall').style.display = t==='firewall'?'block':'none';
  document.getElementById('pane-event').style.display = t==='event'?'block':'none';
  document.getElementById('pane-compliance').style.display = t==='compliance'?'block':'none';
  // 개요/컴플라이언스 탭에서는 모드/필터/분석 컨트롤 숨김(입력 없는 조회형 탭)
  const noControls = (t==='compliance' || t==='overview');
  document.getElementById('controls-row').style.display = noControls?'none':'flex';
  document.getElementById('mode-hint').style.display = noControls?'none':'block';
  if (t==='compliance') showChecks();
  if (t==='overview') showOverview();
}

async function showOverview(){
  document.getElementById('err').textContent='';
  if (!CAPS){
    try { CAPS = await (await fetch('/api/capabilities')).json(); }
    catch(e){ document.getElementById('err').textContent='기능 개요 로드 실패: '+e; return; }
  }
  const c = CAPS;
  document.getElementById('summary').innerHTML =
    `<span>Collector <b>${c.collectors.length}</b></span>`+
    `<span>Notifier <b>${c.notifiers.length}</b></span>`+
    `<span>Remediator <b>${c.remediators.length}</b></span>`+
    `<span>방화벽 벤더 <b>${c.firewall_vendors.length}</b></span>`+
    `<span>컴플라이언스 <b>${c.compliance_count}</b>종</span>`;

  const sec = (title, emoji)=>`<h3 class="sec">${emoji} ${title}</h3>`;
  const card = (name, label, desc, extra)=>`<div class="finding">
      <div class="top"><span class="title">${esc(label)}</span><span class="badge">${esc(name)}</span></div>
      <div class="meta">${esc(desc)}${extra?('<br>'+extra):''}</div></div>`;

  let html = sec('수집 · Collectors', '📥');
  html += c.collectors.map(x=>card(x.name, x.label, x.desc, x.mode?`모드: <code>${esc(x.mode)}</code>`:'')).join('');
  html += sec('알림 · Notifiers', '📣');
  html += c.notifiers.map(x=>card(x.name, x.label, x.desc)).join('');
  html += sec('자동 대응 · Remediators (기본 dry-run)', '🛠️');
  html += c.remediators.map(x=>{
    const t = (x.supported_types||[]).slice(0,2).join(', ');
    return card(x.name, x.label, x.desc, t?`대상: <code>${esc(t)}${x.supported_types.length>2?' 외':''}</code>`:'');
  }).join('');
  html += sec('써드파티 방화벽 파서 · Firewall Parsers', '🧱');
  html += `<div class="finding"><div class="meta">${c.firewall_vendors.map(v=>`<code>${esc(v)}</code>`).join(' · ')} (자동 감지 지원)</div></div>`;
  html += sec('실시간 이벤트 타입 · EventBridge', '⚡');
  html += `<div class="finding"><div class="meta">${(c.event_types||[]).map(e=>esc(e)).join('<br>')}</div></div>`;
  document.getElementById('results').innerHTML = html;
}

function showChecks(){
  const checks = META.compliance_checks || [];
  document.getElementById('summary').innerHTML =
    `<span>점검 항목: <b>${checks.length}</b>개</span><span>근거: <b>KISA CII / CIS AWS</b></span>`;
  const rows = checks.map(c=>`<div class="finding">
      <div class="top"><span class="sev ${c.severity}">${c.severity}</span>
        <span class="title">[${esc(c.code)}] ${esc(c.title)}</span>
        <span class="badge">${esc(c.category||c.service)}</span></div>
      <div class="meta">근거: ${esc((c.standards||[]).join(', ')||'-')}<br>권고: ${esc(c.remediation||'-')}</div>
    </div>`).join('');
  document.getElementById('results').innerHTML = rows || '<div class="empty">등록된 점검 항목이 없습니다.</div>';
}

async function showReport(){
  document.getElementById('err').textContent='';
  try {
    const r = await (await fetch('/api/compliance-report')).json();
    renderReport(r);
  } catch(e){ document.getElementById('err').textContent='리포트 요청 실패: '+e; }
}

function renderReport(r){
  document.getElementById('summary').innerHTML =
    `<span>데모 리포트</span><span>위반: <b>${r.total_violations}</b>건</span>`;
  const maxCat = Math.max(1, ...Object.values(r.by_category).map(c=>c.violations));
  let html = `<div class="scorecard">
      <div class="num grade-${esc(r.grade)}">${r.score}</div>
      <div>
        <div style="font-size:15px;font-weight:700">등급 ${esc(r.grade)} <span style="color:var(--muted);font-weight:400">/ 100점</span></div>
        <div class="meta">위반 ${r.total_violations}건 · CRITICAL ${r.by_severity.CRITICAL||0} · HIGH ${r.by_severity.HIGH||0} · MEDIUM ${r.by_severity.MEDIUM||0}</div>
      </div></div>`;
  html += '<h3 class="sec">카테고리별</h3>';
  html += Object.entries(r.by_category).sort((a,b)=>b[1].violations-a[1].violations).map(([cat,info])=>{
    const w = Math.round(info.violations/maxCat*180);
    return `<div class="catbar"><span class="lbl">${esc(cat)}</span><span class="bar" style="width:${w}px"></span><span>${info.violations}건</span></div>`;
  }).join('');
  html += '<h3 class="sec">위반 항목</h3>';
  html += (r.items||[]).sort((a,b)=>a.code.localeCompare(b.code)).map(it=>`<div class="finding">
      <div class="top"><span class="sev ${it.severity}">${it.severity}</span>
        <span class="title">[${esc(it.code)}] ${esc(it.title)}</span>
        <span class="badge">${esc(it.category)}</span></div>
      <div class="meta">리소스: ${esc(it.resource)}<br>권고: ${esc(it.remediation||'-')}</div>
    </div>`).join('');
  document.getElementById('results').innerHTML = html;
}
function setMode(m){
  currentMode = m;
  document.querySelectorAll('#mode-toggle div').forEach(el=>el.classList.toggle('on', el.dataset.mode===m));
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
  if (currentMode === 'pipeline'){
    url='/api/pipeline';
    body={ kind: currentTab, min_severity: minSev };
    if (currentTab==='firewall'){ body.raw=document.getElementById('fw-input').value; body.vendor=document.getElementById('vendor').value; }
    else { body.event=document.getElementById('ev-input').value; }
  } else if (currentTab==='firewall'){
    url='/api/firewall';
    body={ raw: document.getElementById('fw-input').value, vendor: document.getElementById('vendor').value, min_severity: minSev };
  } else {
    url='/api/event';
    body={ event: document.getElementById('ev-input').value, min_severity: minSev };
  }
  try {
    const data = await (await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})).json();
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
  let sum = `<span>정규화: <b>${data.total}</b>건</span>`+
    `<span>필터 통과: <b>${data.matched}</b>건</span>`+
    `<span>제외: <b>${data.filtered_out}</b>건</span>`+
    `<span>최소 심각도: <b>${data.min_severity}</b></span>`;
  if (data.remediations) sum += `<span>대응 계획: <b>${data.remediations.length}</b>건</span>`;
  document.getElementById('summary').innerHTML = sum;

  const matchedIds = new Set(data.matched_findings.map(f=>f.id));
  let html = '<h3 class="sec">Findings</h3>';
  html += data.all_findings.map(f=>{
    const passed = matchedIds.has(f.id);
    const res = (f.resources&&f.resources[0]&&f.resources[0].id)||'-';
    return `<div class="finding ${passed?'':'dim'}">
      <div class="top"><span class="sev ${f.severity}">${f.severity}</span>
        <span class="title">${esc(f.title)}</span>${passed?'':'<span class="badge">필터 제외</span>'}</div>
      <div class="meta">source: <code>${esc(f.source)}</code> · type: ${esc(f.finding_type||'-')}<br>
        resource: ${esc(res)} · account: ${esc(f.account_id||'-')} · region: ${esc(f.region||'-')}</div>
    </div>`;
  }).join('') || '<div class="empty">정규화된 finding이 없습니다.</div>';

  // 전체 파이프라인 모드: 알림 + 대응
  if (data.notifications){
    html += '<h3 class="sec">📣 알림 미리보기 (전송 안 함)</h3>';
    html += data.notifications.map(n=>`<div class="notif"><div class="hd">${esc(n.label)}</div><pre>${esc(n.message)}</pre></div>`).join('')
      || '<div class="empty">활성 알림 채널이 없습니다.</div>';
  }
  if (data.remediations){
    html += '<h3 class="sec">🛠️ 자동 대응 dry-run 계획 (실제 변경 안 함)</h3>';
    html += data.remediations.length ? data.remediations.map(r=>{
      const a = (r.actions&&r.actions[0])||{};
      const params = a.params? JSON.stringify(a.params) : '';
      return `<div class="rem"><div class="top"><span class="st ${r.status}">${r.status}</span>
        <span><b>${esc(r.remediator)}</b></span>${a.api?`<code>${esc(a.api)}</code>`:''}</div>
        ${a.description?`<div class="meta">${esc(a.description)}</div>`:''}
        ${params?`<div class="params">${esc(params)}</div>`:''}
        ${r.message?`<div class="meta">${esc(r.message)}</div>`:''}</div>`;
    }).join('') : '<div class="empty">유발된 자동 대응이 없습니다. (대응 대상 finding_type이 아니거나 대상 리소스 정보 부족)</div>';
  }
  document.getElementById('results').innerHTML = html;
}
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

loadMeta();
showOverview();   // 기본 탭: 전체 기능 개요
</script>
</body>
</html>
"""
