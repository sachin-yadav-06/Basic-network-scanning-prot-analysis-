# 🔍 Basic Network Scanning & Port Analysis

> A hands-on project exploring network reconnaissance and enumeration techniques using Nmap on local lab environments.

---

## 📌 Project Overview

This project covers the fundamentals of **network scanning** and **port analysis** using industry-standard tools. The goal was to understand how security professionals perform reconnaissance — the first phase of any penetration test or security audit — in a safe, controlled, local lab environment.

---

## 🛠️ Tools & Technologies

| Tool | Purpose |
|------|---------|
| **Nmap** | Network scanning & port discovery |
| **Linux Terminal** | Command execution environment |
| **Local Lab / VM** | Safe testing environment |

---

## 🎯 Objectives

- Perform host discovery on a local network
- Identify open ports and running services on target systems
- Understand service versioning and OS fingerprinting
- Learn the basics of network enumeration used in ethical hacking

---

## 📋 Key Concepts Covered

### 1. Host Discovery
Identifying live hosts on the network before performing a deeper scan.

```bash
# Ping scan to find live hosts
nmap -sn 192.168.1.0/24
```

### 2. Port Scanning
Scanning for open, closed, and filtered TCP/UDP ports.

```bash
# Default SYN scan on a target
nmap -sS 192.168.1.1

# Scan specific port range
nmap -p 1-1000 192.168.1.1

# Scan all 65535 ports
nmap -p- 192.168.1.1
```

### 3. Service & Version Detection
Identifying what services and versions are running on open ports.

```bash
# Service version detection
nmap -sV 192.168.1.1

# Aggressive scan (OS + version + scripts)
nmap -A 192.168.1.1
```

### 4. OS Fingerprinting
Detecting the operating system of a remote host.

```bash
# OS detection
nmap -O 192.168.1.1
```

### 5. Output & Reporting
Saving scan results in different formats for documentation.

```bash
# Save output in all formats
nmap -oA scan_results 192.168.1.1

# Save as XML
nmap -oX scan_results.xml 192.168.1.1
```

---

## 📊 Sample Findings (Local Lab)

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22 | Open | SSH | OpenSSH 8.4 |
| 80 | Open | HTTP | Apache 2.4.51 |
| 443 | Open | HTTPS | Apache 2.4.51 |
| 3306 | Open | MySQL | MySQL 8.0 |
| 8080 | Filtered | HTTP-Proxy | — |

> ⚠️ **Note:** All scans were performed strictly on local virtual machines in a personal lab environment. No external or unauthorized systems were scanned.

---

## 🧠 What I Learned

- How TCP/IP communication works at a low level (SYN, SYN-ACK, ACK handshake)
- The difference between **open**, **closed**, and **filtered** ports
- How attackers use reconnaissance to map targets before exploitation
- The importance of minimizing the attack surface by closing unnecessary ports
- How defenders can use Nmap themselves to audit their own network exposure

---

## 📁 Repository Structure

```
network-scanning-project/
│
├── README.md               # Project documentation (this file)
├── scan-commands.md        # Reference sheet of useful Nmap commands
├── sample-outputs/
│   ├── host_discovery.txt  # Sample host discovery results
│   ├── port_scan.txt       # Sample port scan results
│   └── service_scan.xml    # Sample XML output
└── notes/
    └── learning-notes.md   # Personal notes and observations
```

---

## ⚖️ Legal & Ethical Disclaimer

> All activities in this project were performed **only on systems I own or have explicit written permission to test**. Unauthorized network scanning is **illegal** under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide. This project is strictly for **educational purposes** in a controlled lab environment.

---

## 📚 References & Resources

- [Nmap Official Documentation](https://nmap.org/docs.html)
- [Nmap Cheat Sheet – StationX](https://www.stationx.net/nmap-cheat-sheet/)
- [TCP/IP Guide](http://www.tcpipguide.com/)
- [TryHackMe – Network Fundamentals](https://tryhackme.com/)

---

## 👤 Author

**Sachin Kumar**  
Cybersecurity Enthusiast | BCA/B.Sc. Student  
📧 sachinyadav2063@gmail.com  
🔗 [LinkedIn](https://linkedin.com) | [GitHub](https://github.com)

---

⭐ *If you found this helpful, feel free to star the repo!*
