#!/usr/bin/env python3
"""
ABOUT PC - Deep System Analyzer with Live Info & Premium UI
"""

import platform
import psutil
import socket
import datetime
import subprocess
import time
import os
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.progress import BarColumn, Progress, TextColumn
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich import box

console = Console()

# ─────────────────────────────────────────────────────────────
# Color scheme & constants
# ─────────────────────────────────────────────────────────────
ACCENT = "bright_green"
DIM    = "grey42"
LABEL  = "grey62"
VALUE  = "white"
WARN   = "yellow"
DANGER = "bright_red"
GOOD   = "green"

# Emojis for sections
ICONS = {
    "system": "🖥️",
    "cpu": "⚙️",
    "memory": "🧠",
    "storage": "💾",
    "network": "🌐",
    "gpu": "🎮",
    "motherboard": "🔌",
    "security": "🔒",
    "battery": "🔋",
    "processes": "📊",
    "live": "⏱️",
}

# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────
def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except:
        return "—"

def fmt_bytes(b, precision=1):
    if b is None or b == "—":
        return "—"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.{precision}f} {unit}"
        b /= 1024
    return f"{b:.{precision}f} PB"

def color_pct(pct, warn=60, danger=85):
    c = ACCENT if pct < warn else WARN if pct < danger else DANGER
    return f"[{c}]{pct:.1f}%[/]"

def kv_table(rows):
    t = Table(box=box.SIMPLE, padding=(0, 1), show_header=False)
    t.add_column(style=LABEL, no_wrap=True)
    t.add_column(style=VALUE)
    for k, v in rows:
        t.add_row(k, v)
    return t

def bar_panel(label, pct, warn=60, danger=85, width=30):
    color = ACCENT if pct < warn else WARN if pct < danger else DANGER
    p = Progress(
        TextColumn("{task.description}", style=DIM),
        BarColumn(bar_width=width, style=color, complete_style=color),
        TextColumn("{task.percentage:>5.1f}%", style=color),
        expand=False,
    )
    p.add_task(label, total=100, completed=pct)
    return p

def make_panel(content, title, icon=None):
    if icon:
        title = f"{icon} [bold]{title}[/]"
    else:
        title = f"[bold]{title}[/]"
    return Panel(content, title=title, title_align="left",
                 border_style=DIM, padding=(0, 1), box=box.ROUNDED)

# ─────────────────────────────────────────────────────────────
# Deep collectors (cross‑platform)
# ─────────────────────────────────────────────────────────────
IS_WIN = platform.system() == "Windows"
IS_LIN = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

def get_virtualization():
    if IS_WIN:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation")
            val, _ = winreg.QueryValueEx(key, "SystemManufacturer")
            if val.lower() in ("microsoft corporation", "vmware", "oracle corporation", "innotek gmbh"):
                return val
        except:
            pass
        return run_cmd("wmic computersystem get manufacturer").split("\n")[-1].strip()
    elif IS_LIN:
        if os.path.exists("/sys/class/dmi/id/product_name"):
            prod = open("/sys/class/dmi/id/product_name").read().strip()
            if any(x in prod.lower() for x in ("kvm", "virtualbox", "vmware", "qemu", "bochs")):
                return prod
        if os.path.exists("/sys/hypervisor/type"):
            return open("/sys/hypervisor/type").read().strip()
    elif IS_MAC:
        return run_cmd("sysctl -n kern.hv_support")
    return "Bare metal (or undetected)"

def get_cpu_deep():
    deep = {"family": "—", "model": "—", "stepping": "—", "microcode": "—", "virt": "—"}
    if IS_LIN:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "cpu family" in line: deep["family"] = line.split(":")[1].strip()
                if "model" in line and "model name" not in line: deep["model"] = line.split(":")[1].strip()
                if "stepping" in line: deep["stepping"] = line.split(":")[1].strip()
                if "microcode" in line: deep["microcode"] = line.split(":")[1].strip()
                if "flags" in line:
                    if "vmx" in line: deep["virt"] = "VT-x"
                    elif "svm" in line: deep["virt"] = "AMD-V"
    elif IS_WIN:
        deep["family"] = run_cmd("wmic cpu get family").split("\n")[-1].strip()
        deep["model"] = run_cmd("wmic cpu get model").split("\n")[-1].strip()
        deep["stepping"] = run_cmd("wmic cpu get stepping").split("\n")[-1].strip()
        deep["microcode"] = run_cmd("wmic cpu get revision").split("\n")[-1].strip()
        if "Hyper-V" in run_cmd("systeminfo | findstr Hyper-V"):
            deep["virt"] = "VT-x (Hyper-V)"
    return deep

def get_memory_slots_deep():
    slots = []
    if IS_WIN:
        raw = run_cmd("wmic memorychip get capacity,speed,manufacturer,partnumber,serialnumber,memorytype,devicelocator")
        lines = [l.strip() for l in raw.split("\n") if l.strip() and "Capacity" not in l and l.strip() != "—"]
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                slots.append({
                    "size": fmt_bytes(int(parts[0]) if parts[0].isdigit() else 0),
                    "speed": parts[1] + " MT/s",
                    "manufacturer": parts[2],
                    "part": parts[3],
                    "serial": parts[4],
                    "type": {20:"DDR",21:"DDR2",24:"DDR3",26:"DDR4",34:"DDR5"}.get(int(parts[5]), f"Type {parts[5]}"),
                    "locator": parts[6] if len(parts) > 6 else "—"
                })
    elif IS_LIN:
        try:
            output = run_cmd("sudo dmidecode --type memory 2>/dev/null")
            if output and output != "—":
                blocks = re.split(r"\n\n", output)
                for blk in blocks:
                    if "Size:" in blk and "No Module Installed" not in blk:
                        size = re.search(r"Size:\s*(\d+)\s*(\w+)", blk)
                        speed = re.search(r"Speed:\s*(\d+)\s*(\w+)", blk)
                        mfr = re.search(r"Manufacturer:\s*(.+)", blk)
                        part = re.search(r"Part Number:\s*(.+)", blk)
                        sn = re.search(r"Serial Number:\s*(.+)", blk)
                        memtype = re.search(r"Type:\s*(\w+)", blk)
                        loc = re.search(r"Locator:\s*(.+)", blk)
                        slots.append({
                            "size": f"{size.group(1)} {size.group(2)}" if size else "—",
                            "speed": f"{speed.group(1)} {speed.group(2)}" if speed else "—",
                            "manufacturer": mfr.group(1).strip() if mfr else "—",
                            "part": part.group(1).strip() if part else "—",
                            "serial": sn.group(1).strip() if sn else "—",
                            "type": memtype.group(1).strip() if memtype else "—",
                            "locator": loc.group(1).strip() if loc else "—"
                        })
        except:
            pass
    return slots

def get_disk_deep_attributes():
    disks = []
    if IS_WIN:
        raw = run_cmd("wmic diskdrive get model,serialnumber,interfacetype,status")
        lines = [l.strip() for l in raw.split("\n") if l.strip() and "Model" not in l]
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                disks.append({
                    "model": parts[0][:30],
                    "serial": parts[1],
                    "interface": parts[2],
                    "smart": parts[3] if len(parts)>3 else "—"
                })
    elif IS_LIN:
        for dev in os.listdir("/sys/block/"):
            if dev.startswith(("loop","ram")): continue
            model_path = f"/sys/block/{dev}/device/model"
            serial_path = f"/sys/block/{dev}/device/serial"
            if os.path.exists(model_path):
                model = open(model_path).read().strip()
                serial = open(serial_path).read().strip() if os.path.exists(serial_path) else "—"
                iface = "NVMe" if os.path.exists(f"/sys/block/{dev}/nvme") else "SATA" if os.path.exists(f"/sys/block/{dev}/device/scsi") else "—"
                smart = run_cmd(f"smartctl -H /dev/{dev} | grep -i 'SMART overall-health'")
                smart = smart.split(":")[-1].strip() if smart else "—"
                disks.append({"model": model, "serial": serial, "interface": iface, "smart": smart})
    return disks

def get_network_gateway_dns():
    gateway = "—"
    dns_servers = []
    if IS_WIN:
        route = run_cmd("route print -4 | findstr 0.0.0.0")
        if route:
            parts = route.split()
            gateway = parts[-2] if len(parts) >= 3 else "—"
        dns_raw = run_cmd("nslookup google.com 2>nul | findstr Address")
        dns_servers = [line.split()[-1] for line in dns_raw.split("\n") if line and "Address:" in line][:2]
    elif IS_LIN:
        route = run_cmd("ip route show default | awk '{print $3}'")
        gateway = route if route else "—"
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns_servers.append(line.split()[1])
    return gateway, dns_servers[:2]

def get_gpu_deep():
    deep = {"pcie": "—", "vram_clock": "—", "power": "—", "fan": "—"}
    nvidia_cmd = "nvidia-smi --query-gpu=pcie.link.gen.current,pcie.link.width.current,clocks.sm,power.draw,fan.speed --format=csv,noheader"
    nvidia_out = run_cmd(nvidia_cmd)
    if nvidia_out and "N/A" not in nvidia_out:
        parts = [x.strip() for x in nvidia_out.split(",")]
        if len(parts) >= 5:
            deep["pcie"] = f"PCIe {parts[0]}.0 x{parts[1]}"
            deep["vram_clock"] = parts[2] + " MHz"
            deep["power"] = parts[3] + " W"
            deep["fan"] = parts[4]
    return deep

# ─────────────────────────────────────────────────────────────
# Live info: measure network & disk rates (two samples)
# ─────────────────────────────────────────────────────────────
def get_live_rates(sleep_sec=0.5):
    # Sample 1
    net1 = psutil.net_io_counters()
    disk1 = psutil.disk_io_counters()
    cpu_freq1 = psutil.cpu_freq().current if psutil.cpu_freq() else None
    time.sleep(sleep_sec)
    # Sample 2
    net2 = psutil.net_io_counters()
    disk2 = psutil.disk_io_counters()
    cpu_freq2 = psutil.cpu_freq().current if psutil.cpu_freq() else None

    net_sent_rate = (net2.bytes_sent - net1.bytes_sent) / sleep_sec
    net_recv_rate = (net2.bytes_recv - net1.bytes_recv) / sleep_sec
    disk_read_rate = (disk2.read_bytes - disk1.read_bytes) / sleep_sec
    disk_write_rate = (disk2.write_bytes - disk1.write_bytes) / sleep_sec
    cpu_freq_delta = (cpu_freq2 - cpu_freq1) if (cpu_freq1 and cpu_freq2) else None

    return {
        "upload": net_sent_rate,
        "download": net_recv_rate,
        "disk_read": disk_read_rate,
        "disk_write": disk_write_rate,
        "cpu_freq_change": cpu_freq_delta,
    }

# ─────────────────────────────────────────────────────────────
# Main report
# ─────────────────────────────────────────────────────────────
def aboutpc():
    console.print()
    # Gradient-like title using two colors
    title = Text()
    title.append("◢ ABOUT", style="bold bright_white")
    title.append("PC", style=f"bold {ACCENT}")
    title.append("  ✦  Deep System Analyzer", style=f"dim {DIM}")
    console.print(Align.center(title))
    console.print(Rule(style=DIM))
    console.print()

    t0 = time.perf_counter()

    # --- Live rates (measured over a short interval) ---
    live = get_live_rates(sleep_sec=0.5)

    # --- Basic hardware stats ---
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    cpu_pct = psutil.cpu_percent(interval=0.3)
    per_core = psutil.cpu_percent(percpu=True, interval=0.3)

    # Temperatures (safe for Windows)
    temps = {}
    if hasattr(psutil, 'sensors_temperatures'):
        temps = psutil.sensors_temperatures()

    # Disks
    disk_partitions = [d for d in psutil.disk_partitions(all=False) if psutil.disk_usage(d.mountpoint)]
    disk_io = psutil.disk_io_counters(perdisk=True) or {}
    disk_deep = get_disk_deep_attributes()

    # Network
    nics = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io_all = psutil.net_io_counters(pernic=True)
    gateway, dns_list = get_network_gateway_dns()

    # GPU
    gpu_basic = {"name": "—", "driver": "—", "mem_used": "—", "mem_total": "—", "load": None, "temp": None}
    try:
        import GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            g = gpus[0]
            gpu_basic = {"name": g.name, "driver": g.driver, "mem_used": f"{g.memoryUsed:.0f} MB",
                         "mem_total": f"{g.memoryTotal:.0f} MB", "load": g.load*100, "temp": g.temperature}
    except:
        if IS_WIN:
            gpu_basic["name"] = run_cmd("wmic path win32_VideoController get name").split("\n")[-1].strip()
            gpu_basic["driver"] = run_cmd("wmic path win32_VideoController get driverversion").split("\n")[-1].strip()
    gpu_deep = get_gpu_deep()

    # Battery
    battery = psutil.sensors_battery()

    # Motherboard & BIOS
    if IS_WIN:
        mb_mfr = run_cmd("wmic baseboard get manufacturer").split("\n")[-1].strip()
        mb_model = run_cmd("wmic baseboard get product").split("\n")[-1].strip()
        mb_sn = run_cmd("wmic baseboard get serialnumber").split("\n")[-1].strip()
        bios_vendor = run_cmd("wmic bios get manufacturer").split("\n")[-1].strip()
        bios_version = run_cmd("wmic bios get smbiosbiosversion").split("\n")[-1].strip()
        bios_date = run_cmd("wmic bios get releasedate").split("\n")[-1].strip()[:8]
        secure = run_cmd("powershell Confirm-SecureBootUEFI")
        secure_str = f"[{ACCENT}]Enabled[/]" if "True" in secure else f"[{DANGER}]Disabled[/]" if "False" in secure else f"[{DIM}]—[/]"
        tpm = run_cmd("powershell (Get-Tpm).TpmPresent")
        tpm_str = f"[{ACCENT}]Present[/]" if "True" in tpm else f"[{DANGER}]Not Found[/]" if "False" in tpm else f"[{DIM}]—[/]"
    else:
        mb_mfr = mb_model = mb_sn = bios_vendor = bios_version = bios_date = "—"
        secure_str = tpm_str = f"[{DIM}]—[/]"

    # ─────────────────────────────────────────────────────────
    # 1. SYSTEM panel
    # ─────────────────────────────────────────────────────────
    os_rows = [
        ("OS", f"{platform.system()} {platform.release()}"),
        ("Version", platform.version()[:52]),
        ("Machine", platform.machine()),
        ("Hostname", socket.gethostname()),
        ("Python", platform.python_version()),
        ("Virtualization", get_virtualization()),
    ]
    if IS_WIN:
        os_rows.append(("Edition", run_cmd("wmic os get caption").split("\n")[-1].strip()[:40]))
    if IS_LIN:
        try:
            for line in open("/etc/os-release"):
                if line.startswith("PRETTY_NAME"):
                    os_rows.append(("Distro", line.split("=")[1].strip().strip('"')))
                    break
        except: pass
    boot_dt = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M")
    os_rows += [
        ("Kernel", platform.version()[:52]),
        ("Boot", boot_dt),
        ("Uptime", f"[{ACCENT}]{ (lambda: (lambda d: f'{d.days}d {d.seconds//3600}h {(d.seconds%3600)//60}m')(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())) )() }[/]"),
    ]
    console.print(make_panel(kv_table(os_rows), "SYSTEM", icon=ICONS["system"]))

    # ─────────────────────────────────────────────────────────
    # 2. CPU panel + per-core + temperatures
    # ─────────────────────────────────────────────────────────
    cpu_name = "—"
    if IS_WIN:
        cpu_name = run_cmd("wmic cpu get name").split("\n")[-1].strip()
    elif IS_LIN:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line:
                    cpu_name = line.split(":")[1].strip()
                    break
    cpu_deep = get_cpu_deep()
    freq = psutil.cpu_freq()
    freq_str = f"{freq.current:.0f} MHz  [dim](max {freq.max:.0f} MHz)[/]" if freq else "—"

    cpu_rows = [
        ("Name", cpu_name),
        ("Architecture", platform.machine()),
        ("Socket", run_cmd("wmic cpu get socketdesignation").split("\n")[-1].strip() if IS_WIN else "—"),
        ("Cores", f"{psutil.cpu_count(logical=False)}  [dim]({psutil.cpu_count()} threads)[/]"),
        ("Frequency", freq_str),
        ("Family", cpu_deep["family"]),
        ("Model/Step", f"{cpu_deep['model']} / {cpu_deep['stepping']}"),
        ("Microcode", cpu_deep["microcode"]),
        ("Virtualization", cpu_deep["virt"]),
        ("Overall", color_pct(cpu_pct)),
    ]

    core_tbl = Table(box=box.SIMPLE, padding=(0, 1), show_header=False)
    core_tbl.add_column(style=LABEL, no_wrap=True)
    core_tbl.add_column()
    for i, pct in enumerate(per_core):
        c = ACCENT if pct < 60 else WARN if pct < 85 else DANGER
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        core_tbl.add_row(f"Core {i}", f"[{c}]{bar}[/] [{c}]{pct:.0f}%[/]")

    console.print(Columns([
        make_panel(kv_table(cpu_rows), "CPU", icon=ICONS["cpu"]),
        make_panel(core_tbl, "PER-CORE USAGE")
    ], equal=True, expand=True))

    if temps:
        temp_rows = []
        for name, entries in temps.items():
            for e in entries:
                c = ACCENT if e.current < 70 else WARN if e.current < 85 else DANGER
                temp_rows.append((f"{name} {e.label or ''}", f"[{c}]{e.current:.0f}°C[/]"))
        console.print(make_panel(kv_table(temp_rows[:8]), "CPU TEMPERATURES", icon="🌡️"))

    # ─────────────────────────────────────────────────────────
    # 3. MEMORY panel (deep slots)
    # ─────────────────────────────────────────────────────────
    mem_slots = get_memory_slots_deep()
    mem_rows = [
        ("RAM Used", f"[{ACCENT}]{fmt_bytes(ram.used)}[/] / {fmt_bytes(ram.total)}"),
        ("Available", fmt_bytes(ram.available)),
        ("Buffers", fmt_bytes(getattr(ram, "buffers", 0))),
        ("Cached", fmt_bytes(getattr(ram, "cached", 0))),
        ("Swap Used", f"{fmt_bytes(swap.used)} / {fmt_bytes(swap.total)}"),
    ]
    for i, slot in enumerate(mem_slots[:4]):
        mem_rows.append((f"Slot {i} ({slot['locator']})", f"{slot['size']}  {slot['type']} @ {slot['speed']}  [{slot['manufacturer']}] {slot['part']}"))
    console.print(make_panel(kv_table(mem_rows), "MEMORY", icon=ICONS["memory"]))

    # ─────────────────────────────────────────────────────────
    # 4. STORAGE panel (with deep disk attributes)
    # ─────────────────────────────────────────────────────────
    disk_tbl = Table(box=box.SIMPLE, padding=(0,1), show_header=True, header_style=f"bold {DIM}")
    for col in ("Device","Mount","FS","Total","Used","Free","Usage","Model/Serial"):
        disk_tbl.add_column(col, style=VALUE if col not in ("FS","Model/Serial") else DIM)
    for d in disk_partitions:
        try:
            usage = psutil.disk_usage(d.mountpoint)
            pct = usage.percent
            c = ACCENT if pct < 70 else WARN if pct < 90 else DANGER
            deep_match = next((disk for disk in disk_deep if disk["model"].lower() in d.device.lower() or d.device.endswith(disk["model"].split()[0])), None)
            model_serial = f"{deep_match['model']}\n{deep_match['serial']}" if deep_match else "—"
            disk_tbl.add_row(
                d.device.replace("/dev/","")[:16], d.mountpoint[:20], d.fstype,
                fmt_bytes(usage.total), fmt_bytes(usage.used), fmt_bytes(usage.free),
                f"[{c}]{pct:.1f}%[/]", model_serial[:40]
            )
        except:
            pass
    console.print(make_panel(disk_tbl, "STORAGE", icon=ICONS["storage"]))

    # ─────────────────────────────────────────────────────────
    # 5. NETWORK panel (interfaces + routing + live rates)
    # ─────────────────────────────────────────────────────────
    nic_list = []
    for name, addr_list in nics.items():
        ipv4 = next((a.address for a in addr_list if a.family == socket.AF_INET), "—")
        ipv6 = next((a.address for a in addr_list if a.family == socket.AF_INET6), "—")
        mac  = next((a.address for a in addr_list if a.family == psutil.AF_LINK), "—")
        st   = stats.get(name)
        io   = io_all.get(name)
        nic_list.append({
            "name": name, "ipv4": ipv4, "ipv6": ipv6, "mac": mac,
            "speed": f"{st.speed} Mbps" if st and st.speed else "—",
            "up": st.isup if st else False,
            "sent": fmt_bytes(io.bytes_sent) if io else "—",
            "recv": fmt_bytes(io.bytes_recv) if io else "—"
        })
    nic_tbl = Table(box=box.SIMPLE, padding=(0,1), show_header=True, header_style=f"bold {DIM}")
    for col in ("Interface","IPv4","IPv6","MAC","Speed","State","Sent","Recv"):
        nic_tbl.add_column(col, style=VALUE if col not in ("MAC","IPv6") else DIM)
    for n in nic_list[:6]:
        state = f"[{ACCENT}]UP[/]" if n["up"] else f"[{DANGER}]DOWN[/]"
        nic_tbl.add_row(n["name"][:14], n["ipv4"], n["ipv6"][:30], n["mac"], n["speed"], state, n["sent"], n["recv"])

    # Live rates panel
    live_rows = [
        ("⬆️ Upload", f"{fmt_bytes(live['upload'])}/s"),
        ("⬇️ Download", f"{fmt_bytes(live['download'])}/s"),
        ("📖 Disk Read", f"{fmt_bytes(live['disk_read'])}/s"),
        ("✍️ Disk Write", f"{fmt_bytes(live['disk_write'])}/s"),
    ]
    if live["cpu_freq_change"] is not None:
        delta = live["cpu_freq_change"]
        color = ACCENT if delta > 0 else DIM
        live_rows.append(("⚡ CPU Freq Δ", f"[{color}]{delta:+.1f} MHz[/]"))

    live_panel = make_panel(kv_table(live_rows), "LIVE THROUGHPUT", icon=ICONS["live"])
    routing_panel = make_panel(kv_table([("Gateway", gateway), ("DNS", ", ".join(dns_list))]), "ROUTING")

    console.print(Columns([
        make_panel(nic_tbl, "NETWORK INTERFACES", icon=ICONS["network"]),
        live_panel,
        routing_panel
    ], expand=True))

    # ─────────────────────────────────────────────────────────
    # 6. GRAPHICS panel (deep GPU)
    # ─────────────────────────────────────────────────────────
    gpu_rows = [
        ("Name", gpu_basic["name"]),
        ("Driver", gpu_basic["driver"]),
        ("VRAM", f"{gpu_basic['mem_used']} / {gpu_basic['mem_total']}" if gpu_basic["mem_total"]!="—" else "—"),
        ("Load", color_pct(gpu_basic["load"]) if gpu_basic["load"] is not None else "—"),
        ("Temp", f"{gpu_basic['temp']:.0f}°C" if gpu_basic["temp"] else "—"),
        ("PCIe Link", gpu_deep["pcie"]),
        ("VRAM Clock", gpu_deep["vram_clock"]),
        ("Power", gpu_deep["power"]),
        ("Fan", gpu_deep["fan"])
    ]
    console.print(make_panel(kv_table(gpu_rows), "GRAPHICS", icon=ICONS["gpu"]))

    # ─────────────────────────────────────────────────────────
    # 7. MOTHERBOARD / BIOS / SECURITY
    # ─────────────────────────────────────────────────────────
    mb_rows = [("Manufacturer", mb_mfr), ("Model", mb_model), ("Serial", mb_sn)]
    fw_rows = [("Vendor", bios_vendor), ("Version", bios_version), ("Date", bios_date)]
    sec_rows = [("Secure Boot", secure_str), ("TPM", tpm_str)]
    console.print(Columns([
        make_panel(kv_table(mb_rows), "MOTHERBOARD", icon=ICONS["motherboard"]),
        make_panel(kv_table(fw_rows), "FIRMWARE / BIOS"),
        make_panel(kv_table(sec_rows), "SECURITY", icon=ICONS["security"])
    ], equal=True, expand=True))

    # ─────────────────────────────────────────────────────────
    # 8. BATTERY (if present)
    # ─────────────────────────────────────────────────────────
    if battery:
        bc = ACCENT if battery.percent > 40 else WARN if battery.percent > 15 else DANGER
        remain = "—"
        if battery.secsleft not in (psutil.POWER_TIME_UNLIMITED, psutil.POWER_TIME_UNKNOWN):
            remain = f"{battery.secsleft//3600}h {(battery.secsleft%3600)//60}m"
        console.print(make_panel(kv_table([
            ("Charge", f"[{bc}]{battery.percent:.0f}%[/]"),
            ("Status", f"[{ACCENT if battery.power_plugged else WARN}]{'Charging' if battery.power_plugged else 'Discharging'}[/]"),
            ("Remaining", remain),
        ]), "BATTERY", icon=ICONS["battery"]))

    # ─────────────────────────────────────────────────────────
    # 9. USAGE BARS (system health)
    # ─────────────────────────────────────────────────────────
    bars_tbl = Table(box=None, padding=(0,2), show_header=False, expand=True)
    bars_tbl.add_column()
    bars_tbl.add_row(bar_panel("CPU ", cpu_pct))
    bars_tbl.add_row(bar_panel("RAM ", ram.percent))
    if disk_partitions:
        bars_tbl.add_row(bar_panel("DSK ", psutil.disk_usage(disk_partitions[0].mountpoint).percent, warn=70, danger=90))
    if swap.total > 0:
        bars_tbl.add_row(bar_panel("SWAP", swap.percent))
    console.print(make_panel(bars_tbl, "SYSTEM HEALTH GAUGE"))

    # ─────────────────────────────────────────────────────────
    # 10. TOP PROCESSES
    # ─────────────────────────────────────────────────────────
    top_procs = []
    for p in psutil.process_iter(["pid","name","cpu_percent","memory_percent","status"]):
        try:
            top_procs.append(p.info)
        except: pass
    top_procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)

    proc_tbl = Table(box=box.SIMPLE, padding=(0,1), show_header=True, header_style=f"bold {DIM}")
    proc_tbl.add_column("PID",    style=DIM,   width=8)
    proc_tbl.add_column("Name",   style=VALUE, width=24)
    proc_tbl.add_column("CPU%",   style=VALUE, width=8)
    proc_tbl.add_column("MEM%",   style=VALUE, width=8)
    proc_tbl.add_column("Status", style=DIM)
    for p in top_procs[:8]:
        cpu = p.get("cpu_percent") or 0
        mem = p.get("memory_percent") or 0
        cc  = ACCENT if cpu < 20 else WARN if cpu < 60 else DANGER
        mc  = ACCENT if mem < 10 else WARN if mem < 40 else DANGER
        proc_tbl.add_row(str(p["pid"]), (p["name"] or "—")[:22],
                         f"[{cc}]{cpu:.1f}[/]", f"[{mc}]{mem:.1f}[/]",
                         p.get("status", "—"))
    console.print(make_panel(proc_tbl, "TOP PROCESSES (by CPU)", icon=ICONS["processes"]))

    # ─────────────────────────────────────────────────────────
    # Footer with elapsed time
    # ─────────────────────────────────────────────────────────
    elapsed = time.perf_counter() - t0
    console.print(Rule(style=DIM))
    footer = Text()
    footer.append("✔ Deep scan complete", style=f"bold {ACCENT}")
    footer.append(f"  ·  {elapsed:.2f}s", style=DIM)
    footer.append("  ·  Live rates measured over 0.5s", style=f"dim {DIM}")
    console.print(Align.center(footer))
    console.print()

if __name__ == "__main__":
    aboutpc()