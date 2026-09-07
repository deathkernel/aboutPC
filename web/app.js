const $=id=>document.getElementById(id);
const state={cpu:[],net:[],disk:[]};const MAX=90;
const canvas=$("telemetryCanvas"),ctx=canvas.getContext("2d");
const clamp=v=>Math.max(0,Math.min(100,Number(v)||0));
const esc=v=>{const d=document.createElement("div");d.textContent=v??"";return d.innerHTML};
const setBar=(id,v)=>{const e=$(id);if(e)e.style.width=`${clamp(v)}%`};
const push=(a,v)=>{a.push(Number(v)||0);if(a.length>MAX)a.shift()};
function duration(sec){sec=Math.max(0,Number(sec)||0);const d=Math.floor(sec/86400);sec%=86400;const h=Math.floor(sec/3600);sec%=3600;const m=Math.floor(sec/60);const s=Math.floor(sec%60);return d?`${d}d ${String(h).padStart(2,"0")}h ${String(m).padStart(2,"0")}m`:`${String(h).padStart(2,"0")}h ${String(m).padStart(2,"0")}m ${String(s).padStart(2,"0")}s`}
function bootDate(ts){if(!ts)return"--";return new Date(ts*1000).toLocaleString([], {day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"})}
function render(d){
 const cpu=Number(d.cpu?.usage)||0,mem=Number(d.memory?.usage)||0,disk=Number(d.disk?.usage)||0;
 $("host").textContent=`${d.system?.hostname||"UNKNOWN NODE"} · ${d.system?.os||"LOCAL SYSTEM"}`;
 $("hostname").textContent=d.system?.hostname||"--";$("os").textContent=d.system?.os||"--";$("processor").textContent=d.system?.processor||"--";$("arch").textContent=d.system?.machine||"--";$("python").textContent=d.system?.python||"--";
 $("cpu").textContent=`${cpu.toFixed(1)}%`;$("cpuMeta").textContent=d.cpu?.cores??"--";$("cpuTemp").textContent=`· TEMP ${d.cpu?.temperature==null?"--":`${Number(d.cpu.temperature).toFixed(0)}°C`}`;
 $("freq").textContent=d.cpu?.frequency?`${d.cpu.frequency} MHz`:"-- MHz";$("boost").textContent=d.cpu?.max_frequency?`MAX ${d.cpu.max_frequency} MHz`:"MAX -- MHz";
 $("memory").textContent=`${mem.toFixed(1)}%`;$("memoryMeta").textContent=`${d.memory?.used||"--"} / ${d.memory?.total||"--"}`;$("swapMeta").textContent=`SWAP ${Number(d.memory?.swap||0).toFixed(1)}%`;
 $("disk").textContent=`${disk.toFixed(1)}%`;$("diskMeta").textContent=`${d.disk?.free||"--"} free · ${d.disk?.total||"--"}`;$("diskIo").textContent=`R ${d.disk?.read_rate||"--"} · W ${d.disk?.write_rate||"--"}`;
 $("network").textContent=`↓ ${d.network?.download||"--"}`;$("networkMeta").textContent=`↑ ${d.network?.upload||"--"}`;$("packets").textContent=`PKT ↓ ${Number(d.network?.packets_recv||0).toLocaleString()} · ↑ ${Number(d.network?.packets_sent||0).toLocaleString()}`;
 setBar("cpuBar",cpu);setBar("memoryBar",mem);setBar("diskBar",disk);
 $("cores").innerHTML=(d.cpu?.per_core||[]).map((v,i)=>`<div class="core ${Number(v)>75?"hot":""}"><div><span>CORE ${i+1}</span><strong>${Number(v).toFixed(0)}%</strong></div><b><i style="width:${clamp(v)}%"></i></b></div>`).join("");
 $("processes").innerHTML=(d.processes||[]).slice(0,7).map(p=>`<div class="process"><span class="name">${esc(p.name)}</span><span class="num">${Number(p.cpu||0).toFixed(1)}%</span><span class="mem">${Number(p.memory||0).toFixed(1)}%</span></div>`).join("");
 $("uptime").textContent=duration(d.system?.uptime);$("boot").textContent=bootDate(d.system?.boot_time);
 const bat=d.battery;if(bat?.present){const pct=Number(bat.percent)||0;$("battery").textContent=`${pct.toFixed(0)}%`;$("batteryBar").style.width=`${clamp(pct)}%`;$("batteryState").textContent=bat.plugged?"CHARGING":"ON BATTERY";$("batteryMode").textContent=bat.plugged?"AC CONNECTED":"DISCHARGING";$("batteryTime").textContent=bat.time_left?`TIME ${duration(bat.time_left)}`:"TIME --"}else{$("battery").textContent="N/A";$("batteryBar").style.width="0%";$("batteryState").textContent="NO CELL";$("batteryMode").textContent="DESKTOP";$("batteryTime").textContent="TIME --"}
 const severity=cpu>90||mem>92||disk>95?"CRITICAL":cpu>75||mem>82||disk>88?"ELEVATED":"NOMINAL";$("systemSignal").textContent=severity;$("health").textContent=`SYSTEM ${severity}`;
 $("network-card")?.classList.toggle("active",!!(parseFloat(d.network?.download)>0||parseFloat(d.network?.upload)>0));
 push(state.cpu,cpu);push(state.net,Math.min(100,Math.log10(1+parseFloat(d.network?.download)||1)*28));push(state.disk,Math.min(100,Math.log10(1+parseFloat(d.network?.upload)||1)*28));drawTelemetry();$("clock").textContent=new Date().toLocaleTimeString();
}
function resize(){const r=canvas.getBoundingClientRect(),d=window.devicePixelRatio||1;canvas.width=r.width*d;canvas.height=r.height*d;ctx.setTransform(d,0,0,d,0,0);drawTelemetry()}
function drawLine(a,w,h){if(a.length<2)return;ctx.beginPath();a.forEach((v,i)=>{const x=i*w/(MAX-1),y=h-v/100*h*.86-4;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()}
function drawTelemetry(){const w=canvas.clientWidth,h=canvas.clientHeight;if(!w||!h)return;ctx.clearRect(0,0,w,h);ctx.lineWidth=1;ctx.strokeStyle="rgba(96,122,111,.12)";for(let y=12;y<h;y+=18){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}for(let x=0;x<w;x+=80){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,h);ctx.stroke()}ctx.strokeStyle="rgba(85,240,160,.9)";ctx.shadowBlur=10;ctx.shadowColor="rgba(85,240,160,.35)";drawLine(state.cpu,w,h);ctx.strokeStyle="rgba(111,141,132,.72)";ctx.shadowBlur=0;drawLine(state.net,w,h);ctx.strokeStyle="rgba(85,240,160,.3)";drawLine(state.disk,w,h)}
let retry;function connect(){clearTimeout(retry);const ws=new WebSocket("ws://127.0.0.1:8765");ws.onopen=()=>{$("status").textContent="LIVE";$("dot").style.background="var(--accent)";$("dot").style.boxShadow="0 0 14px var(--accent)"};ws.onmessage=e=>{try{const d=JSON.parse(e.data);if(d.type==="metrics")render(d)}catch(err){console.error(err)}};ws.onclose=()=>{$("status").textContent="OFFLINE";$("dot").style.background="#e56b78";$("dot").style.boxShadow="0 0 12px #e56b78";retry=setTimeout(connect,2000)};ws.onerror=()=>ws.close()}
window.addEventListener("resize",resize);resize();connect();
