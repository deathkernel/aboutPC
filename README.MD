# aboutPC // Local System Intelligence

> A cinematic, real-time PC monitoring dashboard powered entirely by your local machine.

**aboutPC** combines a deep system analyzer with a futuristic browser dashboard for live CPU, memory, disk, network, battery, process, and system telemetry — without cloud services or external APIs.

## ✦ What it does

### Live System Intelligence
- Real-time CPU usage and per-core load
- CPU frequency and temperature when available
- Memory and swap usage
- Disk capacity and live read/write throughput
- Network upload/download throughput and packet counters
- Battery level, charging state, and remaining time
- Top processes by CPU usage
- Host, OS, architecture, Python version, uptime, and boot time
- Live 90-second system activity visualization

### Unwanted File Scanner
The web dashboard also includes a local **Unwanted Files** scanner for identifying disposable file candidates such as temporary files, cache artifacts, crash dumps, and incomplete downloads.

The scanner is designed for review-first cleanup: it does not blindly delete arbitrary files.

### Cinematic Local Dashboard
- Dark, futuristic HUD-inspired interface
- Green system-intelligence visual language
- Responsive dashboard layout
- Live telemetry over a localhost WebSocket
- No login, cloud backend, or external API
- `index.py` remains the original deep terminal analyzer

## 🧩 Architecture

```text
aboutPC
├── index.py                 # Original deep terminal system analyzer
├── web.py                   # Local telemetry + WebSocket server
├── web/
│   ├── index.html           # Dashboard UI
│   ├── style.css            # Cinematic interface
│   └── app.js               # Live dashboard logic
└── requirements-web.txt     # Web dashboard dependencies
```

The browser connects only to the local machine through:

```text
ws://127.0.0.1:8765
```

No telemetry is sent to a remote service.

## 🚀 Quick Start

### Terminal analyzer

```bash
git clone https://github.com/deathkernel/aboutPC.git
cd aboutPC
pip install -r requirements.txt
python index.py
```

### Web dashboard

Install the web dependencies:

```bash
pip install -r requirements-web.txt
```

Then launch:

```bash
python web.py
```

The dashboard opens in your browser automatically.

## 📦 Requirements

- Python 3.6+
- `psutil`
- `rich` for the terminal interface
- `websockets` for the local web dashboard

See `requirements-web.txt` for the dashboard-specific dependencies.

## 🌍 Platform Support

The project is designed to work across Windows, Linux, and macOS where the underlying system information is available.

Some hardware-specific information depends on the operating system and available permissions.

## 🔒 Privacy

**Local means local.**

- No external API
- No cloud telemetry
- No account required
- No remote monitoring service
- Dashboard communication stays on `127.0.0.1`

## 🛠️ Project Status

aboutPC is an actively evolving local system-intelligence project. The web dashboard focuses on turning raw machine telemetry into a clean, cinematic monitoring experience while keeping the original terminal analyzer intact.

## 📄 License

MIT License.
