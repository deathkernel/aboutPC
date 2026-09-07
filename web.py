#!/usr/bin/env python3
"""aboutPC local web dashboard.

No REST API and no external service: the browser receives live system metrics
through a local WebSocket connection. The existing index.py CLI is untouched.
"""

import asyncio
import json
import os
import platform
import socket
import subprocess
import threading
import webbrowser

import psutil
import websockets

HOST = "127.0.0.1"
PORT = 8765
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def fmt_bytes(value):
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def system_snapshot(previous=None):
    cpu = psutil.cpu_percent(interval=None)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    net = psutil.net_io_counters()
    freq = psutil.cpu_freq()
    battery = psutil.sensors_battery()

    upload = download = 0.0
    if previous:
        dt = max(previous["time"] and (asyncio.get_event_loop().time() - previous["time"]) or 1.0, 0.001)
        upload = max(0, net.bytes_sent - previous["sent"]) / dt
        download = max(0, net.bytes_recv - previous["recv"]) / dt

    top = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            top.append({
                "pid": info["pid"],
                "name": info["name"] or "Unknown",
                "cpu": round(info["cpu_percent"] or 0, 1),
                "memory": round(info["memory_percent"] or 0, 1),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    top.sort(key=lambda item: item["cpu"], reverse=True)

    return {
        "type": "metrics",
        "system": {
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "processor": platform.processor() or platform.uname().processor or "Unknown",
            "uptime": int(psutil.boot_time()),
        },
        "cpu": {
            "usage": round(cpu, 1),
            "cores": len(per_core),
            "per_core": [round(x, 1) for x in per_core],
            "frequency": round(freq.current, 0) if freq else None,
            "max_frequency": round(freq.max, 0) if freq and freq.max else None,
        },
        "memory": {
            "usage": round(memory.percent, 1),
            "used": fmt_bytes(memory.used),
            "total": fmt_bytes(memory.total),
            "available": fmt_bytes(memory.available),
            "swap": round(swap.percent, 1),
        },
        "disk": {
            "usage": round(disk.percent, 1),
            "used": fmt_bytes(disk.used),
            "total": fmt_bytes(disk.total),
            "free": fmt_bytes(disk.free),
        },
        "network": {
            "upload": fmt_bytes(upload) + "/s",
            "download": fmt_bytes(download) + "/s",
            "sent": fmt_bytes(net.bytes_sent),
            "received": fmt_bytes(net.bytes_recv),
        },
        "battery": {
            "present": battery is not None,
            "percent": round(battery.percent, 1) if battery else None,
            "plugged": bool(battery.power_plugged) if battery else None,
        },
        "processes": top[:8],
    }, {"time": asyncio.get_event_loop().time(), "sent": net.bytes_sent, "recv": net.bytes_recv}


async def dashboard(websocket):
    previous = None
    try:
        while True:
            payload, previous = system_snapshot(previous)
            await websocket.send(json.dumps(payload))
            await asyncio.sleep(1)
    except websockets.exceptions.ConnectionClosed:
        pass


def open_dashboard():
    path = os.path.join(WEB_DIR, "index.html")
    webbrowser.open("file:///" + path.replace(os.sep, "/"))


async def main():
    print("\n  aboutPC Web Dashboard")
    print(f"  WebSocket: ws://{HOST}:{PORT}")
    print("  Dashboard will open in your browser.")
    print("  Press Ctrl+C to stop.\n")
    async with websockets.serve(dashboard, HOST, PORT):
        threading.Timer(0.8, open_dashboard).start()
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\naboutPC stopped.")
