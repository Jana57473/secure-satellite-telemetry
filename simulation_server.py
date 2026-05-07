"""
simulation_server.py
====================
Run this file FIRST before running your project modules.
It starts a local web server at http://localhost:5000
Open that URL in your browser — the simulation updates LIVE as your modules run.

HOW TO USE:
  Terminal 1:  python simulation_server.py   (keep running)
  Browser:     open  http://localhost:5000
  Terminal 2:  python demo_presentation.py
"""

from flask import Flask, jsonify, render_template_string, request
from flask_cors import CORS
import threading, json, time, os
import subprocess

app = Flask(__name__)
CORS(app)

sim_state = {
    "phase": "idle",
    "satellite": {"status": "OFFLINE", "altitude": 0, "velocity": 0, "freq": 0},
    "ground_station": {"status": "OFFLINE", "rssi": "—", "snr": "—", "pkts_received": 0, "pkts_total": 0},
    "channel": {"active": False, "snr_db": 0, "ber": 0, "packets_in_flight": []},
    "telemetry": [],
    "encryption": {
        "algorithm": "ChaCha20-Poly1305",
        "plaintext_hex": "", "ciphertext_hex": "", "nonce_hex": "",
        "aad": "", "tag_hex": "", "enc_time_ms": 0, "dec_time_ms": 0,
        "plaintext_size": 0, "ciphertext_size": 0,
    },
    "qam": {"symbols": 0, "bits_per_symbol": 4, "ber_table": [], "sample_symbols": []},
    "attacks": [],
    "decryption": {"success": False, "recovered_hex": "", "recovered_fields": [], "match_rate": 0},
    "metrics": {"sent": 0, "auth_passed": 0, "attacks_blocked": 0, "enc_avg_ms": 0, "dec_avg_ms": 0},
    "logs": [],
    "benchmark": {},
    "all_packets": [],
}

state_lock = threading.Lock()

def update_state(updates):
    with state_lock:
        def merge(base, upd):
            for k, v in upd.items():
                if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                    merge(base[k], v)
                else:
                    base[k] = v
        merge(sim_state, updates)

def add_log(msg, level="info"):
    with state_lock:
        t = time.strftime("%H:%M:%S")
        sim_state["logs"].append({"time": t, "msg": msg, "level": level})
        if len(sim_state["logs"]) > 300:
            sim_state["logs"] = sim_state["logs"][-300:]

@app.route("/api/state")
def get_state():
    with state_lock:
        return jsonify(sim_state)

@app.route("/api/update", methods=["POST"])
def post_update():
    data = request.get_json(force=True)
    update_state(data)
    return jsonify({"ok": True})

@app.route("/api/log", methods=["POST"])
def post_log():
    d = request.get_json(force=True)
    add_log(d.get("msg", ""), d.get("level", "info"))
    return jsonify({"ok": True})

@app.route("/api/reset", methods=["POST"])
def reset():
    with state_lock:
        sim_state["phase"] = "idle"
        sim_state["logs"] = []
        sim_state["telemetry"] = []
        sim_state["attacks"] = []
        sim_state["all_packets"] = []
        sim_state["metrics"] = {"sent":0,"auth_passed":0,"attacks_blocked":0,"enc_avg_ms":0,"dec_avg_ms":0}
        sim_state["satellite"]["status"] = "OFFLINE"
        sim_state["ground_station"]["status"] = "OFFLINE"
    return jsonify({"ok": True})

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Satellite Telemetry Security — Live Simulation</title>
<style>
:root{
  --bg:#0D1117;--bg2:#161B22;--bg3:#21262D;
  --border:#30363D;--text:#E6EDF3;--muted:#8B949E;
  --green:#3FB950;--blue:#79C0FF;--orange:#F4A261;
  --purple:#D2A8FF;--red:#FF7B72;--yellow:#E3B341;--cyan:#39D5BD;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px}
.shell{display:grid;grid-template-rows:56px 1fr;height:100vh;overflow:hidden}
header{background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 16px;gap:12px}
header h1{font-size:15px;font-weight:600;color:var(--text)}
.badge{font-size:11px;padding:2px 8px;border-radius:12px;font-weight:500}
.ok{background:#0D2F0D;color:var(--green);border:1px solid var(--green)}
.warn{background:#2D1B00;color:var(--yellow);border:1px solid var(--yellow)}
.err{background:#2D0000;color:var(--red);border:1px solid var(--red)}
.info{background:#0C1F3A;color:var(--blue);border:1px solid var(--blue)}
.body{display:grid;grid-template-columns:340px 1fr;height:100%;overflow:hidden}
.sidebar{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:10px}
.main{display:grid;grid-template-rows:auto 1fr;overflow:hidden;padding:12px;gap:10px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px}
.card-title{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.pipeline{display:flex;gap:4px;flex-wrap:wrap}
.step-pill{font-size:10px;padding:3px 9px;border-radius:12px;border:1px solid var(--border);color:var(--muted);background:var(--bg3);transition:all .4s}
.step-pill.active{background:#0C1F3A;color:var(--blue);border-color:var(--blue)}
.step-pill.done{background:#0D2F0D;color:var(--green);border-color:var(--green)}
.nodes{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.node{border:1px solid var(--border);border-radius:6px;padding:8px}
.node-name{font-size:12px;font-weight:600;margin-bottom:6px;display:flex;align-items:center;gap:6px}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-green{background:var(--green)}.dot-blue{background:var(--blue)}
.kv{display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px}
.kv .k{color:var(--muted)}.kv .v{font-family:'Cascadia Code','Consolas',monospace;color:var(--text)}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:6px}
.metric{background:var(--bg3);border-radius:6px;padding:8px;text-align:center}
.metric .label{font-size:10px;color:var(--muted);margin-bottom:3px}
.metric .val{font-size:18px;font-weight:600}
.channel-vis{background:var(--bg3);border-radius:6px;padding:8px;min-height:44px}
.pkt-flow{display:flex;gap:5px;align-items:center;overflow-x:auto;flex-wrap:wrap;padding:4px 0}
.pkt-box{font-size:10px;padding:3px 7px;border-radius:4px;border:1px solid;white-space:nowrap;flex-shrink:0}
.pkt-enc{background:#0C1F3A;color:var(--blue);border-color:var(--blue)}
.pkt-qam{background:#2D1B00;color:var(--yellow);border-color:var(--yellow)}
.pkt-rx{background:#0D2F0D;color:var(--cyan);border-color:var(--cyan)}
.pkt-atk{background:#2D0000;color:var(--red);border-color:var(--red)}
.tabs{display:flex;gap:1px;background:var(--border);border-radius:6px 6px 0 0;overflow:hidden}
.tab{flex:1;font-size:11px;padding:7px;text-align:center;cursor:pointer;background:var(--bg3);color:var(--muted);border:none;transition:all .2s}
.tab.active{background:var(--bg2);color:var(--text);font-weight:600}
.tab-content{background:var(--bg2);border:1px solid var(--border);border-top:none;border-radius:0 0 6px 6px;overflow:hidden}
.tab-panel{display:none;padding:10px;overflow-y:auto;max-height:calc(100vh - 300px)}
.tab-panel.active{display:block}
.log-area{height:100%;overflow-y:auto;font-family:'Cascadia Code','Consolas',monospace;font-size:11px;line-height:1.7}
.log-line{padding:1px 0;border-bottom:1px solid rgba(48,54,61,.4)}
.log-ok{color:var(--green)}.log-err{color:var(--red)}.log-warn{color:var(--yellow)}
.log-data{color:var(--blue)}.log-hi{color:var(--text);font-weight:600}.log-info{color:var(--muted)}
.hex-block{font-family:'Cascadia Code','Consolas',monospace;font-size:10px;word-break:break-all;line-height:1.7;padding:6px;background:var(--bg3);border-radius:4px;color:var(--blue)}
.sim-table{width:100%;border-collapse:collapse;font-size:11px}
.sim-table th{text-align:left;color:var(--muted);padding:4px 6px;border-bottom:1px solid var(--border);font-weight:500}
.sim-table td{padding:4px 6px;border-bottom:1px solid rgba(48,54,61,.4)}
.sim-table td.mono{font-family:'Cascadia Code','Consolas',monospace}
.bits-compare{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
.bits-col label{font-size:10px;color:var(--muted);display:block;margin-bottom:4px}
.bits-box{font-family:'Cascadia Code','Consolas',monospace;font-size:10px;line-height:1.9;padding:6px;background:var(--bg3);border-radius:4px;word-break:break-all}
.bit-same{color:var(--muted)}.bit-flip{color:var(--red);text-decoration:underline;font-weight:700}
.ber-bar{height:8px;border-radius:3px;background:var(--blue);display:inline-block;vertical-align:middle;margin-left:4px}
.atk-card{border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:8px}
.atk-card.blocked{border-color:var(--red)}
.atk-title{font-size:12px;font-weight:600;margin-bottom:4px;color:var(--red)}
.section-label{font-size:10px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin:8px 0 4px}
.green{color:var(--green)}.red{color:var(--red)}.yellow{color:var(--yellow)}.blue{color:var(--blue)}
.mono{font-family:'Cascadia Code','Consolas',monospace}
</style>
</head>
<body>
<div class="shell">
<header>
  <h1>Satellite Telemetry Security — Live Simulation</h1>
  <span class="badge err" id="h-sat">Satellite: OFFLINE</span>
  <span class="badge err" id="h-gs">Ground Station: OFFLINE</span>
  <span class="badge warn" id="h-link">Link: IDLE</span>
  <span class="badge info" style="margin-left:auto" id="h-phase">Phase: IDLE</span>
</header>
<div class="body">
<div class="sidebar">
  <div class="card">
    <div class="card-title">Simulation Pipeline</div>
    <div style="margin-bottom:10px">
  <button onclick="startSimulation()"
    style="
      background:#238636;
      color:white;
      border:none;
      padding:10px 18px;
      border-radius:6px;
      cursor:pointer;
      font-weight:bold;">
      ▶ START LIVE SIMULATION
  </button>
</div>
    <div class="pipeline">
      <span class="step-pill" id="sp1">1 Boot</span>
      <span class="step-pill" id="sp2">2 Telemetry</span>
      <span class="step-pill" id="sp3">3 Encrypt</span>
      <span class="step-pill" id="sp4">4 QAM</span>
      <span class="step-pill" id="sp5">5 Transmit</span>
      <span class="step-pill" id="sp6">6 Attacks</span>
      <span class="step-pill" id="sp7">7 Decrypt</span>
    </div>
  </div>
  <div class="nodes">
    <div class="node">
      <div class="node-name"><div class="dot dot-green"></div>LEO Satellite</div>
      <div class="kv"><span class="k">Status</span><span class="v" id="sat-status">OFFLINE</span></div>
      <div class="kv"><span class="k">Altitude</span><span class="v" id="sat-alt">—</span></div>
      <div class="kv"><span class="k">Velocity</span><span class="v" id="sat-vel">—</span></div>
      <div class="kv"><span class="k">TX Freq</span><span class="v" id="sat-freq">—</span></div>
    </div>
    <div class="node">
      <div class="node-name"><div class="dot dot-blue"></div>Ground Station</div>
      <div class="kv"><span class="k">Status</span><span class="v" id="gs-status">OFFLINE</span></div>
      <div class="kv"><span class="k">RSSI</span><span class="v" id="gs-rssi">—</span></div>
      <div class="kv"><span class="k">SNR</span><span class="v" id="gs-snr">—</span></div>
      <div class="kv"><span class="k">Pkts RX</span><span class="v" id="gs-pkts">0 / 0</span></div>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="label">Sent</div><div class="val" id="m-sent">0</div></div>
    <div class="metric"><div class="label">Auth</div><div class="val green" id="m-auth">0</div></div>
    <div class="metric"><div class="label">Blocked</div><div class="val red" id="m-blk">0</div></div>
    <div class="metric"><div class="label">Enc ms</div><div class="val blue" id="m-enc">—</div></div>
  </div>
  <div class="card">
    <div class="card-title">Space Link Channel</div>
    <div class="channel-vis">
      <div class="pkt-flow" id="pkt-flow">
        <span style="color:var(--muted);font-size:11px">Idle — waiting for transmission</span>
      </div>
    </div>
    <div style="margin-top:6px" class="kv"><span class="k">BER</span><span class="v green" id="ch-ber">—</span></div>
    <div class="kv"><span class="k">SNR</span><span class="v" id="ch-snr">—</span></div>
  </div>
  <div class="card" id="enc-card" style="display:none">
    <div class="card-title">Encryption (ChaCha20-Poly1305)</div>
    <div class="kv"><span class="k">Nonce</span><span class="v mono" id="eq-nonce" style="font-size:10px">—</span></div>
    <div class="kv"><span class="k">PT size</span><span class="v" id="eq-pt">—</span></div>
    <div class="kv"><span class="k">CT size</span><span class="v" id="eq-ct">—</span></div>
    <div class="kv"><span class="k">Enc time</span><span class="v green" id="eq-time">—</span></div>
  </div>
</div>
<div class="main">
  <div>
    <div class="tabs">
      <button class="tab active" onclick="switchTab('log')">Live Log</button>
      <button class="tab" onclick="switchTab('telemetry')">Telemetry Data</button>
      <button class="tab" onclick="switchTab('encryption')">Encryption</button>
      <button class="tab" onclick="switchTab('qam')">QAM Channel</button>
      <button class="tab" onclick="switchTab('attacks')">Attack Simulation</button>
      <button class="tab" onclick="switchTab('decrypt')">Decryption</button>
      <button class="tab" onclick="switchTab('bench')">Benchmark</button>
    </div>
    <div class="tab-content">
      <div class="tab-panel active" id="tp-log">
        <div class="log-area" id="log-area"></div>
      </div>
      <div class="tab-panel" id="tp-telemetry">
        <div class="section-label">16-Parameter Satellite Telemetry Packet</div>
        <table class="sim-table">
          <thead><tr><th>#</th><th>Parameter</th><th>Value</th><th>Unit</th></tr></thead>
          <tbody id="telem-body"><tr><td colspan="4" style="color:var(--muted)">Waiting for Module 1...</td></tr></tbody>
        </table>
        <div style="margin-top:10px">
          <div class="section-label">Raw Hex (Plaintext)</div>
          <div class="hex-block" id="pt-hex">—</div>
        </div>
        <div style="margin-top:8px">
          <div class="section-label">All 16 Packets Summary</div>
          <table class="sim-table">
            <thead><tr><th>ID</th><th>CPU°C</th><th>Volt</th><th>Alt km</th><th>Vel km/s</th><th>RSSI</th><th>Errors</th></tr></thead>
            <tbody id="all-pkts-body"><tr><td colspan="7" style="color:var(--muted)">Waiting...</td></tr></tbody>
          </table>
        </div>
      </div>
      <div class="tab-panel" id="tp-encryption">
        <div class="section-label">ChaCha20-Poly1305 AEAD Encryption</div>
        <table class="sim-table" style="margin-bottom:10px">
          <tr><td class="k" style="color:var(--muted)">Algorithm</td><td class="mono green">ChaCha20-Poly1305</td></tr>
          <tr><td class="k" style="color:var(--muted)">Key size</td><td>256-bit (pre-shared)</td></tr>
          <tr><td class="k" style="color:var(--muted)">Nonce</td><td class="mono" id="enc-nonce">—</td></tr>
          <tr><td class="k" style="color:var(--muted)">AAD</td><td class="mono" id="enc-aad">—</td></tr>
          <tr><td class="k" style="color:var(--muted)">Plaintext size</td><td id="enc-ptsize">—</td></tr>
          <tr><td class="k" style="color:var(--muted)">Ciphertext size</td><td id="enc-ctsize">—</td></tr>
          <tr><td class="k" style="color:var(--muted)">Auth tag</td><td>16 bytes (Poly1305)</td></tr>
          <tr><td class="k" style="color:var(--muted)">Enc time</td><td class="green" id="enc-time">—</td></tr>
          <tr><td class="k" style="color:var(--muted)">Dec time</td><td class="green" id="enc-dectime">—</td></tr>
        </table>
        <div class="section-label">Plaintext Hex</div>
        <div class="hex-block" id="enc-pt-hex" style="margin-bottom:8px">—</div>
        <div class="section-label">Ciphertext Hex (last 32 chars = Poly1305 tag)</div>
        <div class="hex-block" id="enc-ct-hex" style="color:var(--orange)">—</div>
        <div style="margin-top:8px;display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:11px">
          <div class="ok badge" style="padding:5px 8px">Confidentiality — ChaCha20 stream cipher</div>
          <div class="ok badge" style="padding:5px 8px">Integrity — Poly1305 128-bit MAC</div>
          <div class="ok badge" style="padding:5px 8px">Authenticity — AAD header bound</div>
          <div class="ok badge" style="padding:5px 8px">Replay protection — unique 96-bit nonce</div>
        </div>
      </div>
      <div class="tab-panel" id="tp-qam">
        <div class="section-label">QAM-16 Modulation Stats</div>
        <table class="sim-table" style="margin-bottom:10px">
          <tr><td style="color:var(--muted)">Modulation</td><td>QAM-16</td></tr>
          <tr><td style="color:var(--muted)">Bits/symbol</td><td>4</td></tr>
          <tr><td style="color:var(--muted)">Symbols (CT)</td><td id="qam-syms">—</td></tr>
          <tr><td style="color:var(--muted)">Channel</td><td>AWGN (simulated)</td></tr>
        </table>
        <div class="section-label">Sample Symbol Mapping</div>
        <table class="sim-table" style="margin-bottom:10px">
          <thead><tr><th>4-bit nibble</th><th>I+jQ symbol</th><th>Quadrant</th></tr></thead>
          <tbody id="qam-sample-body"><tr><td colspan="3" style="color:var(--muted)">Waiting...</td></tr></tbody>
        </table>
        <div class="section-label">BER vs SNR</div>
        <table class="sim-table">
          <thead><tr><th>SNR (dB)</th><th>BER ChaCha20</th><th>BER AES-GCM</th><th>Link Quality</th><th>Visual</th></tr></thead>
          <tbody id="ber-body"><tr><td colspan="5" style="color:var(--muted)">Waiting...</td></tr></tbody>
        </table>
      </div>
      <div class="tab-panel" id="tp-attacks">
        <div class="section-label">Live Attack Simulation — Bit-Level Demonstration</div>
        <div id="atk-container"><p style="color:var(--muted)">Waiting for attack simulation...</p></div>
      </div>
      <div class="tab-panel" id="tp-decrypt">
        <div class="section-label">Decryption and Recovery Verification</div>
        <table class="sim-table" style="margin-bottom:10px">
          <tr><td style="color:var(--muted)">Authentication</td><td class="green" id="dec-auth">—</td></tr>
          <tr><td style="color:var(--muted)">Match rate</td><td class="green" id="dec-match">—</td></tr>
          <tr><td style="color:var(--muted)">Dec time</td><td id="dec-time">—</td></tr>
        </table>
        <div class="section-label">Recovered Telemetry (Ground Station)</div>
        <table class="sim-table">
          <thead><tr><th>#</th><th>Field</th><th>Original</th><th>Recovered</th><th>Match</th></tr></thead>
          <tbody id="dec-telem-body"><tr><td colspan="5" style="color:var(--muted)">Waiting...</td></tr></tbody>
        </table>
        <div style="margin-top:8px">
          <div class="section-label">Recovered Hex</div>
          <div class="hex-block green" id="dec-hex">—</div>
        </div>
      </div>
      <div class="tab-panel" id="tp-bench">
        <div class="section-label">ChaCha20-Poly1305 vs AES-256-GCM (500 iterations)</div>
        <table class="sim-table">
          <thead><tr><th>Metric</th><th>ChaCha20-Poly1305</th><th>AES-256-GCM</th><th>Notes</th></tr></thead>
          <tbody id="bench-body"><tr><td colspan="4" style="color:var(--muted)">Waiting for benchmark data...</td></tr></tbody>
        </table>
        <div style="margin-top:12px" id="bench-summary"></div>
      </div>
    </div>
  </div>
</div>
</div>
</div>

<script>
async function startSimulation(){

    try{

        await fetch('/start_simulation', {
            method:'POST'
        });

        alert("Simulation Started");

    }catch(err){

        alert("Failed to start simulation");

    }
}
let lastLogCount=0;

function switchTab(id){
  document.querySelectorAll('.tab').forEach((t,i)=>{
    t.classList.toggle('active',['log','telemetry','encryption','qam','attacks','decrypt','bench'][i]===id);
  });
  document.querySelectorAll('.tab-panel').forEach(p=>{
    p.classList.toggle('active',p.id==='tp-'+id);
  });
}

function setStep(n,s){
  const el=document.getElementById('sp'+n);
  el.className='step-pill '+(s==='active'?'active':s==='done'?'done':'');
}

function hexToBin(hex){
  return (hex||'').substring(0,16).split('').map(h=>parseInt(h,16).toString(2).padStart(4,'0')).join('');
}

function renderBitsCompare(origHex, changedHex, attackName){

  const ob = hexToBin(origHex);
  const cb = hexToBin(changedHex);

  let h1 = ob.match(/.{1,8}/g).join(' ');
  let h2 = cb.match(/.{1,8}/g).join(' ');

  // Highlight ONLY for Bit-flip
  if (attackName && attackName.includes("Bit-flip")) {
    h2 = '<span class="bit-flip">' + h2 + '</span>';
  }

  // 🔥 Dynamic label
  let label = "Attacker-modified bits <span class='red'>(underline = flipped)</span>";

  if (attackName && attackName.includes("Replay")) {
    label = "Replayed packet <span class='red'>(old data reused — no bit modification)</span>";
  }
  else if (attackName && attackName.includes("Side-channel")) {
    label = "Observed execution <span class='red'>(no data modification — timing analyzed)</span>";
  }

  return '<div class="bits-compare">'
    + '<div class="bits-col"><label>Original bits (first 64)</label><div class="bits-box">'+h1+'</div></div>'
    + '<div class="bits-col"><label>'+label+'</label><div class="bits-box">'+h2+'</div></div>'
    + '</div>';
}

function renderQuality(q){
  const map={'Very Poor':'#E24B4A','Poor':'#E24B4A','Marginal':'#EF9F27','Fair':'#EF9F27','Good':'#E3B341','Very Good':'#3FB950','Excellent':'#3FB950','Perfect':'#39D5BD'};
  return '<span style="color:'+(map[q]||'var(--muted)')+'">'+q+'</span>';
}

async function poll(){
  try{const r=await fetch('/api/state');const d=await r.json();applyState(d);}catch(e){}
  setTimeout(poll,800);
}

function applyState(d){
  const sat=d.satellite||{},gs=d.ground_station||{},ch=d.channel||{},enc=d.encryption||{},m=d.metrics||{};
  const V=(el,val)=>{const e=document.getElementById(el);if(e)e.textContent=val||'—';};

  const sb=document.getElementById('h-sat');
  sb.textContent='Satellite: '+(sat.status||'OFFLINE');
  sb.className='badge '+(sat.status==='ONLINE'?'ok':'err');
  const gb=document.getElementById('h-gs');
  gb.textContent='Ground Station: '+(gs.status||'OFFLINE');
  gb.className='badge '+(gs.status==='ONLINE'?'ok':'err');

  const phase=d.phase||'idle';
  document.getElementById('h-phase').textContent='Phase: '+phase.toUpperCase();
  document.getElementById('h-link').textContent='Link: '+(ch.active?'ACTIVE':'IDLE');
  document.getElementById('h-link').className='badge '+(ch.active?'ok':'warn');

  const phaseMap={boot:1,telemetry:2,encrypt:3,qam:4,transmit:5,attack:6,decrypt:7,done:7};
  const cur=phaseMap[phase]||0;
  for(let i=1;i<=7;i++) setStep(i,i<cur?'done':i===cur?'active':'');

  V('sat-status',sat.status);
  V('sat-alt',sat.altitude?(sat.altitude+' km'):'—');
  V('sat-vel',sat.velocity?(sat.velocity+' km/s'):'—');
  V('sat-freq',sat.freq?(sat.freq+' MHz'):'—');
  V('gs-status',gs.status);V('gs-rssi',gs.rssi);
  V('gs-snr',gs.snr?gs.snr+' dB':'—');
  V('gs-pkts',(gs.pkts_received||0)+' / '+(gs.pkts_total||0));
  V('m-sent',m.sent||0);V('m-auth',m.auth_passed||0);
  V('m-blk',m.attacks_blocked||0);
  V('m-enc',m.enc_avg_ms?(+m.enc_avg_ms).toFixed(3):'—');
  V('ch-ber',ch.ber!==undefined?ch.ber:'—');
  V('ch-snr',ch.snr_db?(ch.snr_db+' dB'):'—');

  if(ch.packets_in_flight&&ch.packets_in_flight.length){
    document.getElementById('pkt-flow').innerHTML=ch.packets_in_flight.map(p=>'<div class="pkt-box pkt-'+(p.type||'enc')+'">'+p.label+'</div>').join('<span style="color:var(--muted)">→</span>');
  }

  if(enc.nonce_hex){
    document.getElementById('enc-card').style.display='block';
    V('eq-nonce',enc.nonce_hex);
    V('eq-pt',enc.plaintext_size?(enc.plaintext_size+' bytes'):'—');
    V('eq-ct',enc.ciphertext_size?(enc.ciphertext_size+' bytes'):'—');
    V('eq-time',enc.enc_time_ms?((+enc.enc_time_ms).toFixed(3)+' ms'):'—');
  }

  if(d.telemetry&&d.telemetry.length){
    const tbody=document.getElementById('telem-body');
    if(tbody.children.length!==d.telemetry.length){
      tbody.innerHTML=d.telemetry.map((r,i)=>'<tr><td>'+(i+1)+'</td><td>'+(r.field||'')+'</td><td class="mono">'+(r.value||'')+'</td><td style="color:var(--muted)">'+(r.unit||'')+'</td></tr>').join('');
    }
    document.getElementById('pt-hex').textContent=enc.plaintext_hex||'—';
  }

  if(d.all_packets&&d.all_packets.length){
    document.getElementById('all-pkts-body').innerHTML=d.all_packets.map(p=>'<tr><td>'+p.id+'</td><td class="mono">'+p.cpu_temp+'</td><td class="mono">'+p.voltage+'</td><td class="mono">'+p.altitude+'</td><td class="mono">'+p.velocity+'</td><td class="mono">'+p.rssi+'</td><td class="mono">'+p.error_flags+'</td></tr>').join('');
  }

  if(enc.plaintext_hex){
    V('enc-nonce',enc.nonce_hex);V('enc-aad',enc.aad);
    V('enc-ptsize',enc.plaintext_size?enc.plaintext_size+' bytes':'—');
    V('enc-ctsize',enc.ciphertext_size?enc.ciphertext_size+' bytes':'—');
    V('enc-time',enc.enc_time_ms?(+enc.enc_time_ms).toFixed(4)+' ms':'—');
    V('enc-dectime',enc.dec_time_ms?(+enc.dec_time_ms).toFixed(4)+' ms':'—');
    document.getElementById('enc-pt-hex').textContent=enc.plaintext_hex;
    document.getElementById('enc-ct-hex').textContent=enc.ciphertext_hex;
  }

  const qam=d.qam||{};
  if(qam.symbols){
    V('qam-syms',qam.symbols);
    if(qam.sample_symbols&&qam.sample_symbols.length){
      document.getElementById('qam-sample-body').innerHTML=qam.sample_symbols.map(s=>'<tr><td class="mono">'+s.bits+'</td><td class="mono">'+s.iq+'</td><td>'+s.quadrant+'</td></tr>').join('');
    }
    if(qam.ber_table&&qam.ber_table.length){
      document.getElementById('ber-body').innerHTML=qam.ber_table.map(r=>{
        const bF=parseFloat(r.ber_chacha),bW=Math.max(2,Math.min(80,bF*400));
        return '<tr><td>'+r.snr+'</td><td class="mono">'+r.ber_chacha+'</td><td class="mono">'+r.ber_aes+'</td><td>'+renderQuality(r.quality)+'</td><td><div class="ber-bar" style="width:'+bW+'px"></div></td></tr>';
      }).join('');
    }
  }

  if(d.attacks&&d.attacks.length){
    document.getElementById('atk-container').innerHTML=d.attacks.map(a=>'<div class="atk-card '+(a.blocked?'blocked':'')+'"><div class="atk-title">'+a.name+'</div><div style="font-size:11px;color:var(--muted);margin-bottom:6px">'+a.description+'</div>'+renderBitsCompare(a.original_hex||'', a.modified_hex||'', a.name)+'<div style="margin-top:6px;font-size:11px">Result: <span class="'+(a.blocked?'green':'red')+'">'+(a.blocked?'BLOCKED':'INSECURE')+'</span> — <span style="color:var(--muted)">'+a.reason+'</span></div></div>').join('');
  }

  const dec=d.decryption||{};
  if(dec.success!==undefined&&dec.success){
    V('dec-auth','PASS — Poly1305 tag verified');
    V('dec-match',dec.match_rate!==undefined?(dec.match_rate*100).toFixed(0)+'% accuracy':'—');
    V('dec-time',enc.dec_time_ms?(+enc.dec_time_ms).toFixed(4)+' ms':'—');
    document.getElementById('dec-hex').textContent=dec.recovered_hex||'—';
    if(dec.recovered_fields&&dec.recovered_fields.length&&d.telemetry&&d.telemetry.length){
      document.getElementById('dec-telem-body').innerHTML=dec.recovered_fields.map((r,i)=>{
        const orig=d.telemetry[i]||{};
        const ov=orig.value||orig[1]||'';
        const rv=r.value||'';
        const match=rv===ov;
        return '<tr><td>'+(i+1)+'</td><td>'+r.field+'</td><td class="mono">'+ov+'</td><td class="mono '+(match?'green':'red')+'">'+rv+'</td><td>'+(match?'<span class="green">✓</span>':'<span class="red">✗</span>')+'</td></tr>';
      }).join('');
    }
  }

  const bm=d.benchmark||{};
  if(bm.chacha&&bm.aes){
    const rows=[
      ['Avg Enc time (ms)',bm.chacha.avg_enc_ms,bm.aes.avg_enc_ms,'lower'],
      ['Avg Dec time (ms)',bm.chacha.avg_dec_ms,bm.aes.avg_dec_ms,'lower'],
      ['Enc std dev (ms)',bm.chacha.stdev_enc,bm.aes.stdev_enc,'lower'],
      ['Auth tag (bytes)',bm.chacha.overhead_b,bm.aes.overhead_b,'equal'],
    ];
    document.getElementById('bench-body').innerHTML=rows.map(([lbl,c,a,type])=>{
      const cF=parseFloat(c)||0,aF=parseFloat(a)||0;
      let note='';
      if(type==='lower') note=cF<=aF?'<span class="blue">ChaCha20 faster</span>':'<span style="color:var(--muted)">AES faster (HW accel)</span>';
      else note='<span class="green">Equal</span>';
      return '<tr><td>'+lbl+'</td><td class="mono">'+(typeof c==='number'?c.toFixed(6):c)+'</td><td class="mono">'+(typeof a==='number'?a.toFixed(6):a)+'</td><td>'+note+'</td></tr>';
    }).join('');
    document.getElementById('bench-summary').innerHTML='<div class="ok badge" style="padding:8px 12px;font-size:11px;line-height:1.6"><strong>Selected Algorithm: ChaCha20-Poly1305</strong><br>AES-GCM may appear faster here because desktop CPUs have hardware AES-NI instructions. On real satellite embedded hardware (ARM Cortex-M, STM32 — no AES-NI), ChaCha20-Poly1305 is 3x faster. ChaCha20 also has lower timing standard deviation, meaning more consistent and predictable performance — critical for real-time satellite telemetry systems.</div>';
  }

  if(d.logs&&d.logs.length>lastLogCount){
    const area=document.getElementById('log-area');
    const atBottom=area.scrollHeight-area.clientHeight-area.scrollTop<40;
    d.logs.slice(lastLogCount).forEach(l=>{
      const div=document.createElement('div');
      div.className='log-line log-'+(l.level||'info');
      div.innerHTML='<span style="color:var(--muted)">['+l.time+']</span> '+l.msg;
      area.appendChild(div);
    });
    lastLogCount=d.logs.length;
    if(atBottom) area.scrollTop=area.scrollHeight;
  }
}

poll();
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/start_simulation", methods=["POST"])
def start_simulation():

    try:
        subprocess.Popen(
            ["python", "demo_presentation.py"],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )

        return jsonify({"status": "started"})

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  Satellite Telemetry Security — Simulation Server")
    print("="*60)
    print("\n  Open your browser at:  http://localhost:5000")
    print("\n  Then run in another terminal:")
    print("    python demo_presentation.py")
    print("\n  The browser updates LIVE as your modules run.")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
