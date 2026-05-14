#!/usr/bin/env python3
"""
========================================
  Network Scanner - Main Entry Point
  Author  : Sachin Kumar
  Email   : sachinyadav2063@gmail.com
  Project : Basic Network Scanning & Port Analysis
========================================
"""

import socket
import subprocess
import platform
import threading
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────
MAX_THREADS   = 100        # Threads for parallel port scanning
TIMEOUT       = 1.0        # Socket timeout in seconds
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306,
    3389, 5900, 8080, 8443
]

# Well-known port → service name mapping
SERVICE_MAP = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MS-RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


# ─────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────
def print_banner():
    print("=" * 55)
    print("       NETWORK SCANNER — Sachin Kumar")
    print("       sachinyadav2063@gmail.com")
    print("=" * 55)
    print(f"  Scan started at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)


# ─────────────────────────────────────────
#  HOST DISCOVERY — Ping Sweep
# ─────────────────────────────────────────
def ping_host(ip: str) -> bool:
    """Ping a single host. Returns True if alive."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-W", "1", str(ip)]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def host_discovery(network_cidr: str) -> list:
    """
    Scan an entire subnet for live hosts using ping sweep.
    Example input: '192.168.1.0/24'
    """
    print(f"\n[*] Starting host discovery on {network_cidr} ...")
    live_hosts = []

    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network: {e}")
        return []

    hosts = list(network.hosts())
    print(f"[*] Pinging {len(hosts)} hosts — please wait...\n")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(ping_host, str(host)): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            if future.result():
                print(f"  [+] Host UP  →  {host}")
                live_hosts.append(str(host))

    print(f"\n[*] Discovery complete. {len(live_hosts)} host(s) found.")
    return live_hosts


# ─────────────────────────────────────────
#  PORT SCANNER
# ─────────────────────────────────────────
def scan_port(ip: str, port: int) -> dict | None:
    """
    Attempt a TCP connection to a specific port.
    Returns a result dict if open, else None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = SERVICE_MAP.get(port, "Unknown")
            # Try banner grab for more info
            banner = grab_banner(ip, port)
            return {
                "port":    port,
                "state":   "OPEN",
                "service": service,
                "banner":  banner,
            }
    except (socket.timeout, socket.error):
        pass
    return None


def grab_banner(ip: str, port: int) -> str:
    """Attempt to grab service banner for version info."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        # Return only the first meaningful line
        first_line = banner.split("\n")[0][:60]
        return first_line if first_line else "N/A"
    except Exception:
        return "N/A"


def port_scan(ip: str, ports: list = None) -> list:
    """
    Scan a list of ports on a target IP using multithreading.
    Returns a list of open port result dicts.
    """
    if ports is None:
        ports = DEFAULT_PORTS

    print(f"\n[*] Scanning {ip} — {len(ports)} port(s) ...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# ─────────────────────────────────────────
#  OS FINGERPRINTING (basic TTL method)
# ─────────────────────────────────────────
def guess_os(ip: str) -> str:
    """
    Guess OS from TTL value in ping response.
    TTL ~128 → Windows | TTL ~64 → Linux/macOS | TTL ~255 → Cisco/network
    """
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", str(ip)],
            capture_output=True, text=True
        )
        output = result.stdout.lower()
        if "ttl=128" in output or "ttl=127" in output:
            return "Windows (TTL ~128)"
        elif "ttl=64" in output or "ttl=63" in output:
            return "Linux / macOS (TTL ~64)"
        elif "ttl=255" in output or "ttl=254" in output:
            return "Cisco / Network Device (TTL ~255)"
        else:
            return "Unknown"
    except Exception:
        return "Could not determine"


# ─────────────────────────────────────────
#  HOSTNAME RESOLUTION
# ─────────────────────────────────────────
def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"


# ─────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────
def print_report(ip: str, open_ports: list, hostname: str, os_guess: str):
    print("\n" + "=" * 55)
    print(f"  SCAN REPORT FOR: {ip}")
    print("=" * 55)
    print(f"  Hostname  : {hostname}")
    print(f"  OS Guess  : {os_guess}")
    print(f"  Open Ports: {len(open_ports)}")
    print("-" * 55)

    if open_ports:
        print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<12} {'BANNER'}")
        print(f"  {'-'*6:<8} {'-'*8:<10} {'-'*10:<12} {'-'*20}")
        for p in open_ports:
            print(f"  {p['port']:<8} {p['state']:<10} {p['service']:<12} {p['banner']}")
    else:
        print("  No open ports found in the scanned range.")

    print("=" * 55)


def save_report(ip: str, open_ports: list, hostname: str, os_guess: str):
    """Save the scan report to a text file."""
    filename = f"scan_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"Network Scan Report\n")
        f.write(f"Author  : Sachin Kumar | sachinyadav2063@gmail.com\n")
        f.write(f"Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target  : {ip}\n")
        f.write(f"Hostname: {hostname}\n")
        f.write(f"OS Guess: {os_guess}\n\n")
        f.write(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<12} BANNER\n")
        f.write("-" * 55 + "\n")
        for p in open_ports:
            f.write(f"{p['port']:<8} {p['state']:<10} {p['service']:<12} {p['banner']}\n")
    print(f"\n[+] Report saved to: {filename}")


# ─────────────────────────────────────────
#  MAIN — MENU
# ─────────────────────────────────────────
def main():
    print_banner()
    print("\nSelect scan mode:")
    print("  [1] Single host — Port scan")
    print("  [2] Network — Host discovery")
    print("  [3] Full scan — Discover + Port scan all live hosts")
    print("  [0] Exit")

    choice = input("\nEnter choice: ").strip()

    if choice == "1":
        target = input("Enter target IP (e.g. 192.168.1.1): ").strip()
        port_input = input("Enter ports (comma-separated) or press Enter for defaults: ").strip()
        ports = [int(p) for p in port_input.split(",")] if port_input else DEFAULT_PORTS

        hostname = resolve_hostname(target)
        os_guess = guess_os(target)
        open_ports = port_scan(target, ports)
        print_report(target, open_ports, hostname, os_guess)
        save_report(target, open_ports, hostname, os_guess)

    elif choice == "2":
        network = input("Enter network CIDR (e.g. 192.168.1.0/24): ").strip()
        host_discovery(network)

    elif choice == "3":
        network = input("Enter network CIDR (e.g. 192.168.1.0/24): ").strip()
        live_hosts = host_discovery(network)
        if live_hosts:
            for host in live_hosts:
                hostname = resolve_hostname(host)
                os_guess = guess_os(host)
                open_ports = port_scan(host)
                print_report(host, open_ports, hostname, os_guess)
                save_report(host, open_ports, hostname, os_guess)

    elif choice == "0":
        print("\n[*] Exiting. Stay ethical!")
    else:
        print("[!] Invalid choice.")

    print(f"\n[*] Scan finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
