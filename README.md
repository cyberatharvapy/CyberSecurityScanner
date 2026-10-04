# 🔐 CyberSecurityScanner

A Python-based cybersecurity vulnerability assessment tool that performs network scanning, service detection, vulnerability analysis, HTTP security checks, CVE intelligence, risk assessment, and automated HTML security report generation.

> ⚠️ **For Educational & Authorized Security Testing Only**

---

## 📌 Overview

**CyberSecurityScanner** is a modular cybersecurity assessment tool developed using Python and Nmap.

The project is designed to help security students and defenders understand how automated vulnerability assessment works by combining multiple security-analysis techniques into a single command-line application.

The scanner can:

- 🔎 Discover open ports and services
- 🧩 Identify service products and versions
- 🛡️ Perform Nmap NSE vulnerability scanning
- 🌐 Analyze HTTP security headers
- 🐞 Search the NVD database for potential CVE matches
- ⚠️ Identify basic security risks
- 📊 Calculate a heuristic security risk score
- 📄 Generate a professional HTML security report

---

## ✨ Features

### 🔎 1. Port & Service Scanning

Uses **Nmap** with service/version detection to identify:

- Open ports
- Network protocols
- Running services
- Service products
- Service versions

Example:

```text
Port 80   | open | http | Apache
Port 22   | open | ssh  | OpenSSH

⚠️ 2. Risk Analysis

The scanner performs basic risk classification based on detected services and ports.

Current risk rules include:

Port	Service	Risk
21	FTP	Medium
23	Telnet	High
135	MSRPC	Medium
139	NetBIOS	Medium
445	SMB	High
3306	MySQL	High
3389	RDP	High

These are heuristic rules intended for initial assessment and do not represent a complete vulnerability determination.

3. Nmap NSE Vulnerability Scanning

The project uses Nmap's vulnerability-oriented NSE scripts to perform additional security checks.

Command concept:

nmap -sV --script vuln <target>

The scanner collects available NSE findings and includes them in the final report.

🌐 4. HTTP Security Analysis

For detected HTTP services, the scanner checks commonly recommended security headers.

Currently analyzed headers:

Content-Security-Policy
X-Frame-Options
X-Content-Type-Options
Strict-Transport-Security
Referrer-Policy
Permissions-Policy

Example:

[+] Content-Security-Policy: PRESENT
[-] X-Frame-Options: MISSING
[-] Strict-Transport-Security: MISSING

This helps identify potentially weak web-security configurations.

🐞 5. CVE Intelligence

The scanner integrates with the National Vulnerability Database (NVD) to search for potential CVE matches based on detected products and versions.

Information collected includes:

CVE ID
Severity
CVSS score
Vulnerability description

Example:

CVE-XXXX-XXXXX
Severity: HIGH
CVSS: 8.1

⚠️ A CVE returned by keyword matching is a potential match, not proof that the target is vulnerable. Manual/version-specific verification is required.

📊 6. Risk Score

The scanner generates a heuristic risk score from 0–100 based on findings from:

Risky services/ports
NSE vulnerability findings
Potential CVE matches
Missing HTTP security headers

Risk levels:

Score	Risk Level
0–19	🟢 Low
20–39	🟡 Moderate
40–69	🟠 High
70–100	🔴 Critical

The score is a project-specific heuristic and should not be confused with CVSS.

📄 7. Automated HTML Report

After scanning, the project generates a professional HTML security report.

The report contains:

Target information
Scan timestamp
Detected ports
Services and versions
Risk findings
NSE vulnerability findings
CVE intelligence
HTTP security analysis
Missing security headers
Risk score
Risk level
Security recommendations
Assessment limitations
