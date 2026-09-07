const $ = id => document.getElementById(id);
const state = { cpu: [], net: [], disk: [] };
const MAX = 90;
const canvas = $('telemetryCanvas');
const ctx = canvas.getContext('2d');

function clamp(v){ return Math.max(0, Math.min(100, Number(v) || 0)); }
function esc(value){ const d=document.createElement('div'); d.textContent=value ?? ''; return d.innerHTML; }
function setBar(id,value){ $(id).style.width=`${clamp(value)}%`; }
function push(arr,value){ arr.push(Number(value)||0); if(arr.length>MAX) arr.shift(); }
function kbps(v){ return typeof v === 'string' ? v : `${v||0}`; }

function render(data){
  const cpu=Number(data.cpu?.usage)||0, mem=Number(data.memory?.usage)||0, disk=Number(data.disk?.usage)||0;
  $('host').textContent=`${data.system?.hostname||'UNKNOWN NODE'} · ${data.system?.os||'LOCAL SYSTEM'}`;
  $('hostname').textContent=data.system?.hostname||'--';
  $('os').textContent=data.system?.os||'--';
  $('processor').textContent=data.system?.processor||'--';
  $('arch').textContent=data.system?.machine||'--';
  $('python').textContent=data.system?.python||'--';
  $('cpu').textContent=`${cpu.toFixed(1)}%`; $('coreValue').textContent=`${cpu.toFixed(0)}%`;
  $('cpuMeta').textContent=data.cpu?.cores ?? '--'; $('freq').textContent=data.cpu?.frequency ? `${data.cpu.frequency} MHz` : '--';
  $('memory').textContent=`${mem.toFixed(1)}%`; $('memoryMeta').textContent=`${data.memory?.used||'--'} / ${data.memory?.total||'--'}`;
  $('disk').textContent=`${disk.toFixed(1)}%`; $('diskMeta').textContent=`${data.disk?.free||'--'} free · ${data.disk?.total||'--'} total`;
  $('network').textContent=`↓ ${kbps(data.network?.download)}`; $('networkMeta').textContent=`↑ ${kbps(data.network?.upload)}`;
  setBar('cpuBar',cpu); setBar('memoryBar',mem); setBar('diskBar',disk);

  $('cores').innerHTML=(data.cpu?.per_core||[]).map((v,i)=>`<div class="core"><div><span>C${String(i+1).padStart(2,'0')}</span><strong>${Number(v).toFixed(0)}%</strong></div><b><i style="width:${clamp(v)}%"></i></b></div>`).join('');
  $('processes').innerHTML=(data.processes||[]).slice(0,7).map(p=>`<div class="process"><span class="name">${esc(p.name)}</span><span class="num">${Number(p.cpu||0).toFixed(1)}%</span></div>`).join('');
  if(data.battery?.present) $('battery').textContent=`${Number(data.battery.percent).toFixed(0)}%${data.battery.plugged?' · AC':''}`; else $('battery').textContent='N/A';

  push(state.cpu,cpu); push(state.net,Math.min(100,Math.log10(1+parseFloat(data.network?.download)||1)*28)); push(state.disk,Math.min(100,Math.log10(1+parseFloat(data.network?.upload)||1)*28));
  drawTelemetry(); $('clock').textContent=new Date().toLocaleTimeString();
}

function resize(){ const r=canvas.getBoundingClientRect(),d=window.devicePixelRatio||1; canvas.width=r.width*d; canvas.height=r.height*d; ctx.setTransform(d,0,0,d,0,0); drawTelemetry(); }
function drawLine(values,w,h,offset,scale){
  if(values.length<2)return;
  ctx.beginPath(); values.forEach((v,i)=>{ const x=i*(w/(MAX-1)), y=h-(v/scale)*h*.86-4; i?ctx.lineTo(x,y):ctx.moveTo(x,y); }); ctx.stroke();
}
function drawTelemetry(){
  const w=canvas.clientWidth,h=canvas.clientHeight; if(!w||!h)return; ctx.clearRect(0,0,w,h);
  ctx.strokeStyle='rgba(103,247,255,.08)';ctx.lineWidth=1;
  for(let y=12;y<h;y+=18){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}
  for(let x=0;x<w;x+=80){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,h);ctx.stroke()}
  ctx.strokeStyle='rgba(103,247,255,.9)';ctx.shadowBlur=10;ctx.shadowColor='rgba(103,247,255,.7)';
  drawLine(state.cpu,w,h,0,100);
  ctx.strokeStyle='rgba(57,116,255,.75)';ctx.shadowColor='rgba(57,116,255,.5)'; drawLine(state.net,w,h,0,100);
  ctx.shadowBlur=0;
}

let retry;
function connect(){
  clearTimeout(retry); const ws=new WebSocket('ws://127.0.0.1:8765');
  ws.onopen=()=>{ $('status').textContent='ONLINE'; $('dot').style.background='var(--cyan)'; $('dot').style.boxShadow='0 0 16px var(--cyan)'; };
  ws.onmessage=e=>{ try{const d=JSON.parse(e.data);if(d.type==='metrics')render(d)}catch(err){console.error(err)} };
  ws.onclose=()=>{ $('status').textContent='LINK LOST';$('dot').style.background='#ff4f67';$('dot').style.boxShadow='0 0 14px #ff4f67';retry=setTimeout(connect,2000); };
  ws.onerror=()=>ws.close();
}
window.addEventListener('resize',resize); resize(); connect();
