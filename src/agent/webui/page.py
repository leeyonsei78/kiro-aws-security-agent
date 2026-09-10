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
      <div class="tab" data-tab="target" onclick="switchTab('target')">모니터링 대상 지정</div>
      <div class="tab" data-tab="glossary" onclick="switchTab('glossary')">용어 사전 (초보자용)</div>
    </div>

    <div id="pane-overview">
      <p class="hint" style="font-size:13px">이 에이전트가 제공하는 <b>전체 기능</b>입니다. 수집(Collector) → 정규화 → 필터 → 알림(Notifier) → 자동 대응(Remediator) 파이프라인과 지원 항목을 한눈에 보여줍니다. 각 탭에서 실제 동작을 테스트할 수 있습니다.</p>
      <div class="row" style="margin-top:8px"><button class="btn primary" onclick="showOverview()">기능 개요 불러오기</button></div>
    </div>

    <div id="pane-firewall" style="display:none">
      <p class="hint" style="font-size:13px">🧱 <b>무엇을 하나요?</b> Palo Alto·Fortinet·Check Point 등 방화벽 장비가 남긴 <b>로그 한 줄</b>을 붙여넣으면, 어느 벤더인지 자동 인식해 위협 내용·심각도·출발지 IP를 <b>통합 형식(finding)</b>으로 변환합니다. 아래 샘플 칩을 눌러 바로 체험해 보세요.</p>
      <label>벤더 (auto = 자동 인식)</label>
      <select id="vendor"></select>
      <label>방화벽 로그 (한 줄에 하나)</label>
      <textarea id="fw-input" placeholder="예) devname=... type=utm subtype=ips level=alert srcip=... attack=..."></textarea>
      <div class="samples" id="fw-samples"></div>
    </div>

    <div id="pane-event" style="display:none">
      <p class="hint" style="font-size:13px">⚡ <b>무엇을 하나요?</b> GuardDuty·Security Hub 같은 AWS 보안 서비스가 EventBridge로 보내는 <b>이벤트(JSON)</b>를 붙여넣으면, 위협을 통합 형식으로 정규화하고 심각도 필터·알림·자동 대응 계획까지 미리 볼 수 있습니다. 샘플 칩으로 체험해 보세요.</p>
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

    <div id="pane-target" style="display:none">
      <p class="hint" style="font-size:13px">🎯 <b>어느 AWS 계정/리전을 어떤 항목으로 모니터링할지</b> 지정합니다. 웹 콘솔은 실제 스캔을 하지 않고(자격증명 불필요), 아래에서 고른 대상을 <b>실제 배포/실행에 쓸 설정</b>(환경변수·SAM·Terraform·CLI)으로 만들어 줍니다. 그 설정으로 배포하면 해당 계정을 모니터링합니다.</p>
      <label>리전 (예: ap-northeast-2, us-east-1)</label>
      <input id="tg-region" type="text" placeholder="ap-northeast-2"
        style="width:100%;background:#0b1220;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 10px;font-size:13px">
      <label>모니터링할 항목 (Collector) — 체크</label>
      <div id="tg-collectors" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px"></div>
      <label style="margin-top:12px">최소 심각도(이 이상만 알림)</label>
      <select id="tg-sev"></select>
      <div class="row" style="margin-top:12px">
        <button class="btn primary" onclick="genTarget()">설정 만들기</button>
        <button class="btn" onclick="showTarget()">현재 대상 상태</button>
      </div>
    </div>

    <div id="pane-glossary" style="display:none">
      <p class="hint" style="font-size:13px">📖 AWS 보안 용어와 이 프로그램이 다루는 장비/서비스를 초보자용으로 설명합니다. 아래에 자동으로 목록이 표시됩니다.</p>
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
  document.getElementById('pane-target').style.display = t==='target'?'block':'none';
  document.getElementById('pane-glossary').style.display = t==='glossary'?'block':'none';
  // 조회형/설정형 탭에서는 파싱용 모드/필터/분석 컨트롤 숨김
  const noControls = (t==='compliance' || t==='overview' || t==='glossary' || t==='target');
  document.getElementById('controls-row').style.display = noControls?'none':'flex';
  document.getElementById('mode-hint').style.display = noControls?'none':'block';
  if (t==='compliance') showChecks();
  if (t==='overview') showOverview();
  if (t==='glossary') showGlossary();
  if (t==='target') initTarget();
}

let TARGET_INIT = false;
async function initTarget(){
  // collector 체크박스와 심각도 옵션을 1회 채우고 현재 상태 표시
  if (!TARGET_INIT){
    let st = null;
    try { st = await (await fetch('/api/target')).json(); } catch(e) {}
    const avail = (st && st.available_collectors) || [];
    document.getElementById('tg-collectors').innerHTML = avail.map(c=>{
      const checked = (st.active_collectors||[]).includes(c.name) ? 'checked' : '';
      const scan = c.account_scan ? '' : ' (수신형)';
      return `<label style="display:inline-flex;align-items:center;gap:5px;font-size:12.5px;color:var(--text);margin:0">
        <input type="checkbox" value="${esc(c.name)}" ${checked}> ${esc(c.label)}${scan}</label>`;
    }).join('');
    document.getElementById('tg-sev').innerHTML = (META.severities||["MEDIUM"]).map(s=>`<option ${s===(st&&st.min_severity||'MEDIUM')?'selected':''}>${s}</option>`).join('');
    if (st && st.region_set) document.getElementById('tg-region').value = st.region;
    TARGET_INIT = true;
  }
  showTarget();
}

async function showTarget(){
  document.getElementById('err').textContent='';
  let st;
  try { st = await (await fetch('/api/target')).json(); }
  catch(e){ document.getElementById('err').textContent='대상 상태 로드 실패: '+e; return; }
  document.getElementById('summary').innerHTML =
    `<span>현재 리전: <b>${esc(st.region)}</b></span>`+
    `<span>활성 항목: <b>${(st.active_collectors||[]).length}</b></span>`+
    `<span>최소 심각도: <b>${esc(st.min_severity)}</b></span>`+
    `<span>자격증명 감지: <b>${st.credentials_detected?'예':'아니오(웹은 불필요)'}</b></span>`;
  let html = `<div class="finding"><div class="meta">${esc(st.note)}</div></div>`;
  html += '<h3 class="sec">현재 대상 요약</h3>';
  html += `<div class="finding"><div class="meta">
      계정: ${esc(st.account)}<br>리전: <code>${esc(st.region)}</code><br>
      활성 Collector: ${(st.active_collectors||[]).map(c=>`<code>${esc(c)}</code>`).join(' ')}</div></div>`;
  document.getElementById('results').innerHTML = html;
}

async function genTarget(){
  document.getElementById('err').textContent='';
  const region = document.getElementById('tg-region').value.trim();
  const cols = Array.from(document.querySelectorAll('#tg-collectors input:checked')).map(x=>x.value);
  const sev = document.getElementById('tg-sev').value;
  if (cols.length===0){ document.getElementById('err').textContent='최소 1개 항목을 선택하세요.'; return; }
  try {
    const s = await (await fetch('/api/target',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({region, collectors:cols, min_severity:sev})})).json();
    renderTargetSetup(s);
  } catch(e){ document.getElementById('err').textContent='설정 생성 실패: '+e; }
}

function block(title, code){
  return `<h3 class="sec">${esc(title)}</h3><div class="notif"><pre>${esc(code)}</pre></div>`;
}
function renderTargetSetup(s){
  document.getElementById('summary').innerHTML =
    `<span>대상 리전: <b>${esc(s.region)}</b></span>`+
    `<span>항목: <b>${(s.collectors||[]).length}</b></span>`+
    `<span>최소 심각도: <b>${esc(s.min_severity)}</b></span>`;
  let html = `<div class="finding"><div class="meta">아래 설정 중 <b>사용하는 배포 방식</b>의 값을 복사해 적용하면, 지정한 계정/리전을 모니터링합니다.</div></div>`;
  html += block('① 환경변수 (.env / 컨테이너)', s.env);
  html += block('② CLI 실행 — Windows PowerShell', s.cli_powershell);
  html += block('② CLI 실행 — macOS/Linux', s.cli_bash);
  html += block('③ SAM 배포', s.sam);
  html += block('④ Terraform (terraform.tfvars)', s.terraform_tfvars);
  document.getElementById('results').innerHTML = html;
}

const GLOSSARY = [
  {term:"finding", desc:"보안 서비스가 찾아낸 '이상/위협 결과' 한 건. 이 프로그램은 모든 소스의 finding을 하나의 통합 형식으로 정규화합니다."},
  {term:"심각도 (Severity)", desc:"위협의 위험도. INFORMATIONAL < LOW < MEDIUM < HIGH < CRITICAL 순. '최소 심각도' 필터로 낮은 건 걸러냅니다."},
  {term:"GuardDuty", desc:"AWS의 위협 탐지 서비스. 로그를 머신러닝으로 분석해 무차별 대입 공격·악성 통신·자격증명 도용 등을 자동 탐지합니다."},
  {term:"Security Hub", desc:"여러 보안 서비스의 결과를 한곳에 모으는 통합 서비스. GuardDuty·Inspector·Config 결과를 표준 형식(ASFF)으로 집계합니다."},
  {term:"Security Group (SG)", desc:"AWS 리소스(EC2 등)에 붙는 가상 방화벽. 어떤 IP·포트가 들어올 수 있는지 규칙으로 정의합니다. 인터넷 전체(0.0.0.0/0) 개방이 위험합니다."},
  {term:"NACL (Network ACL)", desc:"서브넷(네트워크 구획) 단위의 방화벽. Security Group과 달리 '차단(deny)' 규칙을 명시할 수 있어 공격 IP 차단에 씁니다."},
  {term:"IAM", desc:"AWS의 계정·권한 관리 서비스. 사용자·역할·정책·액세스 키를 다룹니다. 루트 계정, MFA, 액세스 키가 핵심 점검 대상입니다."},
  {term:"MFA (다중 인증)", desc:"비밀번호 외에 추가 인증(앱 코드 등)을 요구하는 보안 장치. 콘솔 로그인 사용자에게 필수 권장."},
  {term:"액세스 키 (Access Key)", desc:"프로그램이 AWS를 호출할 때 쓰는 장기 자격증명(AKIA...로 시작). 유출되면 위험하므로 주기적 교체·최소화가 필요합니다."},
  {term:"CloudTrail", desc:"계정의 모든 API 호출(누가·언제·무엇)을 기록하는 감사 로그 서비스. 로깅을 끄거나 루트로 설정 변경 시 위험 신호입니다."},
  {term:"VPC / Flow Logs", desc:"VPC는 내 AWS 가상 네트워크. Flow Logs는 그 안팎 트래픽 기록으로, 포트 스캔·대량 접속 거부 같은 이상 징후를 봅니다."},
  {term:"S3", desc:"AWS의 파일 저장소(버킷). 실수로 '퍼블릭 공개'되거나 암호화가 꺼져 있으면 데이터 유출 위험이 큽니다."},
  {term:"EC2", desc:"AWS의 가상 서버. 감염 의심 시 '격리'(격리용 SG로 교체)해 네트워크에서 고립시키되, 포렌식을 위해 종료하지 않습니다."},
  {term:"RDS", desc:"AWS의 관리형 데이터베이스. 퍼블릭 접근 허용·저장 암호화 미설정이 주요 점검 항목입니다."},
  {term:"ECR", desc:"컨테이너 이미지 저장소. 이미지 스캔(취약점 점검)과 태그 불변성(공급망 변조 방지)이 중요합니다."},
  {term:"WAF", desc:"웹 애플리케이션 방화벽. CloudFront/ALB 앞단에서 웹 공격을 차단. 악성 IP를 IPSet에 넣어 차단합니다."},
  {term:"Remediator (자동 대응)", desc:"위협 발견 시 자동으로 조치하는 기능(IP 차단·키 비활성화 등). 기본은 dry-run(계획만, 실제 변경 안 함)이라 안전합니다."},
  {term:"dry-run", desc:"'모의 실행'. 실제로 바꾸지 않고 '무엇을 할지 계획'만 보여줍니다. 이 프로그램의 자동 대응 기본값입니다."},
  {term:"컴플라이언스 점검", desc:"계정 설정이 보안 기준(KISA/CIS)에 맞는지 자체 점검하는 기능. 16개 항목을 검사해 100점 만점 점수·등급으로 요약합니다."},
  {term:"CIS / KISA", desc:"보안 설정 기준을 제시하는 표준. CIS는 국제 벤치마크, KISA는 한국인터넷진흥원 가이드. 컴플라이언스 점검의 근거입니다."},
  {term:"써드파티 방화벽", desc:"AWS가 아닌 상용 방화벽 장비(Palo Alto·Fortinet·Check Point). 이 프로그램은 그 로그를 받아 통합 형식으로 변환합니다."},
];

function showGlossary(){
  document.getElementById('summary').innerHTML = `<span>용어 <b>${GLOSSARY.length}</b>개 · 초보자용 설명</span>`;
  document.getElementById('results').innerHTML = GLOSSARY.map(g=>`<div class="finding">
      <div class="top"><span class="title">${esc(g.term)}</span></div>
      <div class="meta">${esc(g.desc)}</div></div>`).join('');
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

  // 수집기: 설명 + 수집 정보 + 예시까지 상세 표시
  const collectorCard = (x)=>`<div class="finding">
      <div class="top"><span class="title">${esc(x.label)}</span><span class="badge">${esc(x.name)}</span>${x.mode?`<span class="badge">${esc(x.mode)}</span>`:''}</div>
      <div class="meta">${esc(x.desc||'')}
        ${x.collects?`<br>🔎 <b>수집 정보</b>: ${esc(x.collects)}`:''}
        ${x.example?`<br>💡 ${esc(x.example)}`:''}</div></div>`;

  let html = sec('수집 · Collectors (무엇을 어디서 가져오는가)', '📥');
  html += c.collectors.map(collectorCard).join('');
  html += sec('알림 · Notifiers (탐지 결과를 어디로 보내는가)', '📣');
  html += c.notifiers.map(x=>card(x.name, x.label, x.desc + (x.collects?` — ${x.collects}`:''))).join('');
  html += sec('자동 대응 · Remediators (위협 발견 시 무엇을 하는가, 기본 dry-run)', '🛠️');
  html += c.remediators.map(x=>{
    const t = (x.supported_types||[]).slice(0,2).join(', ');
    const extra = (x.example?`💡 ${esc(x.example)}`:'')
      + (t?`<br>대상 유형: <code>${esc(t)}${x.supported_types.length>2?' 외':''}</code>`:'');
    return card(x.name, x.label, x.desc, extra);
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
