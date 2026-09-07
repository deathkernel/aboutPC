const host = document.getElementById('host');
const status = document.getElementById('status');
const dot = document.getElementById('dot');
const $ = id => document.getElementById(id);

function setBar(id, value) { $(id).style.width = `${Math.max(0, Math.min(100, value))}%`; }
function esc(value) { const d = document.createElement('div'); d.textContent = value ?? ''; return d.innerHTML; }

function render(data) {
  host.textContent = `${data.system.hostname} · ${data.system.os}`;
  $('cpu').textContent = `${data.cpu.usage.toFixed(1)}%`;
  $('cpuMeta').textContent = `${data.cpu.cores} logical cores`;
  $('freq').textContent = data.cpu.frequency ? `${data.cpu.frequency} MHz` : 'frequency unavailable';
  setBar('cpuBar', data.cpu.usage);

  $('memory').textContent = `${data.memory.usage.toFixed(1)}%`;
  $('memoryMeta').textContent = `${data.memory.used} / ${data.memory.total}`;
  setBar('memoryBar', data.memory.usage);

  $('disk').textContent = `${data.disk.usage.toFixed(1)}%`;
  $('diskMeta').textContent = `${data.disk.free} free · ${data.disk.total} total`;
  setBar('diskBar', data.disk.usage);

  $('network').textContent = `↓ ${data.network.download}`;
  $('networkMeta').textContent = `↑ ${data.network.upload}`;

  $('cores').innerHTML = data.cpu.per_core.map((value, i) => `
    <div class="core"><div><span>CORE ${i + 1}</span><strong>${value.toFixed(0)}%</strong></div><b><i style="width:${value}%"></i></b></div>
  `).join('');

  $('system').innerHTML = `
    <dt>HOST</dt><dd>${esc(data.system.hostname)}</dd>
    <dt>OS</dt><dd>${esc(data.system.os)}</dd>
    <dt>CPU</dt><dd>${esc(data.system.processor)}</dd>
    <dt>ARCH</dt><dd>${esc(data.system.machine)}</dd>
    <dt>PYTHON</dt><dd>${esc(data.system.python)}</dd>
  `;

  $('processes').innerHTML = data.processes.map(p => `
    <div class="process"><span class="name">${esc(p.name)}</span><span class="num">${p.cpu.toFixed(1)}%</span><span class="num">${p.memory.toFixed(1)}% RAM</span></div>
  `).join('');

  if (data.battery.present) {
    $('battery').innerHTML = `${data.battery.percent.toFixed(0)}% <small>${data.battery.plugged ? '<span class="plug">PLUGGED IN</span>' : 'ON BATTERY'}</small>`;
  } else {
    $('battery').innerHTML = `<small>No battery detected</small>`;
  }
}

function connect() {
  const ws = new WebSocket('ws://127.0.0.1:8765');
  ws.onopen = () => { status.textContent = 'LIVE'; dot.style.background = '#59f59b'; dot.style.boxShadow = '0 0 12px #59f59b'; };
  ws.onmessage = event => {
    try { const data = JSON.parse(event.data); if (data.type === 'metrics') render(data); } catch (e) { console.error(e); }
  };
  ws.onclose = () => {
    status.textContent = 'OFFLINE'; dot.style.background = '#f05b5b'; dot.style.boxShadow = '0 0 12px #f05b5b';
    setTimeout(connect, 2000);
  };
  ws.onerror = () => ws.close();
}

connect();
