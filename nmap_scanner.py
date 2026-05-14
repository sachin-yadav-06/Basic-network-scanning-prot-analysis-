#!/usr/bin/env python3
"""
========================================
  Nmap Wrapper — Service & Version Scan
  Author  : Sachin Kumar
  Email   : sachinyadav2063@gmail.com
  Project : Basic Network Scanning & Port Analysis
========================================

Requires: pip install python-nmap
          nmap installed on your OS
"""

import nmap
import json
from datetime import datetime


def nmap_scan(target: str, scan_type: str = "basic") -> dict:
    """
    Perform Nmap scan using python-nmap library.

    Scan types:
      basic     → Fast scan of common ports (-F)
      service   → Service + version detection (-sV)
      os        → OS detection + service (-O -sV)
      full      → Full aggressive scan (-A)
      stealth   → SYN stealth scan (-sS)  ← Requires root/admin
      udp       → UDP scan (-sU)          ← Requires root/admin
    """
    nm = nmap.PortScanner()

    scan_args = {
        "basic":   "-F",
        "service": "-sV --version-intensity 5",
        "os":      "-O -sV",
        "full":    "-A -T4",
        "stealth": "-sS -T2",
        "udp":     "-sU --top-ports 20",
    }

    args = scan_args.get(scan_type, "-F")
    print(f"\n[*] Running Nmap {scan_type} scan on {target}")
    print(f"[*] Arguments: nmap {args} {target}")
    print("[*] Please wait...\n")

    try:
        nm.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        print("[!] Try running as root/admin for this scan type.")
        return {}
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return {}

    results = {}

    for host in nm.all_hosts():
        results[host] = {
            "hostname":  nm[host].hostname(),
            "state":     nm[host].state(),
            "protocols": {}
        }

        for proto in nm[host].all_protocols():
            results[host]["protocols"][proto] = []
            ports = nm[host][proto].keys()

            for port in sorted(ports):
                port_info = nm[host][proto][port]
                results[host]["protocols"][proto].append({
                    "port":    port,
                    "state":   port_info["state"],
                    "name":    port_info["name"],
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                })

    return results


def print_nmap_results(results: dict):
    """Pretty-print Nmap scan results."""
    if not results:
        print("[!] No results to display.")
        return

    for host, data in results.items():
        print("\n" + "=" * 60)
        print(f"  HOST     : {host}")
        print(f"  HOSTNAME : {data['hostname'] or 'N/A'}")
        print(f"  STATE    : {data['state']}")
        print("=" * 60)

        for proto, ports in data["protocols"].items():
            print(f"\n  Protocol: {proto.upper()}")
            print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'VERSION'}")
            print(f"  {'-'*6:<8} {'-'*8:<10} {'-'*13:<15} {'-'*20}")

            for p in ports:
                version_str = f"{p['product']} {p['version']} {p['extrainfo']}".strip()
                version_str = version_str if version_str else "N/A"
                print(f"  {p['port']:<8} {p['state']:<10} {p['name']:<15} {version_str}")

        print("=" * 60)


def save_json(results: dict, filename: str = None):
    """Save scan results as a JSON file."""
    if not filename:
        filename = f"nmap_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Results saved to: {filename}")


# ─────────────────────────────────────────
#  COMMON NMAP COMMANDS (Reference Sheet)
# ─────────────────────────────────────────
NMAP_CHEATSHEET = """
╔══════════════════════════════════════════════════════╗
║         NMAP CHEAT SHEET — Sachin Kumar              ║
╠══════════════════════════════════════════════════════╣
║  HOST DISCOVERY                                      ║
║   nmap -sn 192.168.1.0/24       # Ping sweep        ║
║   nmap -Pn 192.168.1.1          # Skip ping         ║
║                                                      ║
║  PORT SCANNING                                       ║
║   nmap 192.168.1.1              # Top 1000 ports    ║
║   nmap -F 192.168.1.1           # Fast (top 100)    ║
║   nmap -p 1-65535 192.168.1.1   # All ports         ║
║   nmap -p 22,80,443 192.168.1.1 # Specific ports    ║
║                                                      ║
║  SCAN TECHNIQUES                                     ║
║   nmap -sS 192.168.1.1          # SYN stealth       ║
║   nmap -sT 192.168.1.1          # TCP connect       ║
║   nmap -sU 192.168.1.1          # UDP scan          ║
║   nmap -sA 192.168.1.1          # ACK scan          ║
║                                                      ║
║  SERVICE & OS DETECTION                              ║
║   nmap -sV 192.168.1.1          # Version detect    ║
║   nmap -O  192.168.1.1          # OS detect         ║
║   nmap -A  192.168.1.1          # All (aggressive)  ║
║                                                      ║
║  OUTPUT                                              ║
║   nmap -oN result.txt 192.168.1.1   # Normal        ║
║   nmap -oX result.xml 192.168.1.1   # XML           ║
║   nmap -oA result    192.168.1.1    # All formats   ║
╚══════════════════════════════════════════════════════╝
"""


def main():
    print("=" * 60)
    print("       NMAP SCANNER WRAPPER — Sachin Kumar")
    print("       sachinyadav2063@gmail.com")
    print("=" * 60)
    print(NMAP_CHEATSHEET)

    target = input("Enter target IP or range (e.g. 192.168.1.1): ").strip()
    print("\nScan type options:")
    print("  [1] basic   — Fast common port scan")
    print("  [2] service — Service & version detection")
    print("  [3] os      — OS + service detection (root)")
    print("  [4] full    — Full aggressive scan (root)")
    print("  [5] stealth — SYN stealth scan (root)")
    print("  [6] udp     — UDP scan (root)")

    scan_map = {
        "1": "basic", "2": "service",
        "3": "os",    "4": "full",
        "5": "stealth","6": "udp"
    }

    choice = input("\nEnter choice [1-6]: ").strip()
    scan_type = scan_map.get(choice, "basic")

    results = nmap_scan(target, scan_type)
    print_nmap_results(results)

    if results:
        save = input("\nSave results to JSON? (y/n): ").strip().lower()
        if save == "y":
            save_json(results)


if __name__ == "__main__":
    main()
