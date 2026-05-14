# 📋 Nmap Command Reference Sheet
**Author:** Sachin Kumar | sachinyadav2063@gmail.com

---

## 🔍 Host Discovery

```bash
# Ping sweep — find live hosts in subnet
nmap -sn 192.168.1.0/24

# Skip ping (treat host as online)
nmap -Pn 192.168.1.1

# ARP scan (faster on local networks)
nmap -PR 192.168.1.0/24
```

---

## 🔌 Port Scanning

```bash
# Default scan (top 1000 ports)
nmap 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1

# Scan all 65535 ports
nmap -p- 192.168.1.1

# Scan specific ports
nmap -p 22,80,443,3306 192.168.1.1

# Scan a port range
nmap -p 1-1024 192.168.1.1
```

---

## 🎯 Scan Techniques

| Command | Technique | Notes |
|---------|-----------|-------|
| `nmap -sS` | SYN Stealth | Requires root/admin |
| `nmap -sT` | TCP Connect | Default (no root needed) |
| `nmap -sU` | UDP Scan | Slow, requires root |
| `nmap -sA` | ACK Scan | Firewall mapping |
| `nmap -sN` | NULL Scan | Evades some firewalls |
| `nmap -sX` | Xmas Scan | Evades some firewalls |

---

## 🔬 Service & Version Detection

```bash
# Service version detection
nmap -sV 192.168.1.1

# Aggressive version intensity (0-9)
nmap -sV --version-intensity 9 192.168.1.1

# OS detection (requires root)
nmap -O 192.168.1.1

# Full aggressive scan (OS + version + scripts + traceroute)
nmap -A 192.168.1.1
```

---

## 📜 NSE Scripts (Nmap Scripting Engine)

```bash
# Run default safe scripts
nmap -sC 192.168.1.1

# Vulnerability scanning scripts
nmap --script vuln 192.168.1.1

# Specific script
nmap --script http-title 192.168.1.1
nmap --script ssh-auth-methods 192.168.1.1

# Brute force (educational only!)
nmap --script ftp-brute 192.168.1.1
```

---

## 🕒 Timing & Performance

| Template | Flag | Speed | Use Case |
|----------|------|-------|----------|
| Paranoid | `-T0` | Very slow | IDS evasion |
| Sneaky | `-T1` | Slow | IDS evasion |
| Polite | `-T2` | Slow | Low bandwidth |
| Normal | `-T3` | Default | Default |
| Aggressive | `-T4` | Fast | Fast network |
| Insane | `-T5` | Very fast | May miss results |

```bash
# Fast aggressive scan
nmap -T4 -F 192.168.1.1
```

---

## 💾 Output Formats

```bash
# Normal output to file
nmap -oN results.txt 192.168.1.1

# XML output (parseable)
nmap -oX results.xml 192.168.1.1

# Grepable output
nmap -oG results.gnmap 192.168.1.1

# All formats at once
nmap -oA results 192.168.1.1
```

---

## 🎭 Evasion Techniques (Educational)

```bash
# Fragment packets to evade IDS
nmap -f 192.168.1.1

# Spoof source IP (requires root)
nmap -S 10.10.10.1 192.168.1.1

# Use decoys
nmap -D RND:10 192.168.1.1

# Randomize scan order
nmap --randomize-hosts 192.168.1.0/24
```

---

## 🔥 Common Full Scan Examples

```bash
# Quick recon
nmap -sV -F -T4 192.168.1.1

# Thorough scan
nmap -sV -sC -O -p- -T4 192.168.1.1

# Save and scan
nmap -A -oA full_scan 192.168.1.1

# Scan entire subnet, save results
nmap -sn -oN alive_hosts.txt 192.168.1.0/24
```

---

## ⚠️ Legal Reminder

> Only scan systems you **own** or have **explicit written permission** to test.
> Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (USA),
> the IT Act 2000 (India), and equivalent laws in all countries.

---

*Sachin Kumar | sachinyadav2063@gmail.com*
