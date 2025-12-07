# Nmap Commands and Their Security Relevance

## Educational Guide: Understanding Reconnaissance in Information Security

This document explains how each Nmap command used in this tool relates to the reconnaissance phase of information security assessments and penetration testing.

---

## 🎯 The Reconnaissance Phase

Reconnaissance (or "recon") is the **first phase** of any security assessment or cyber attack. The goal is to gather as much information as possible about the target without actually exploiting vulnerabilities.

### The Cyber Kill Chain

1. **Reconnaissance** ← This tool focuses here
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives

**Why Reconnaissance Matters:**
- Identifies potential attack vectors
- Reveals exposed services and software versions
- Helps attackers (or security testers) plan their approach
- Minimal risk of detection compared to active exploitation
- Legal and necessary for authorized security assessments

---

## 📡 Host Discovery: Finding Active Targets

### Command: `nmap -sn [target]`

**What it does:**
- Sends ICMP echo requests (ping) to determine if hosts are alive
- Does NOT scan ports - just checks if the host responds
- Fast way to map out a network

**Security Relevance:**

**From an Attacker's Perspective:**
- First step to identify potential targets in a network
- Helps create a "map" of the network topology
- Reduces time wasted scanning dead hosts
- Like walking around a building to see which offices have lights on

**From a Defender's Perspective:**
- Shows what an attacker would see as "available targets"
- Helps identify unauthorized devices on the network
- Reveals network visibility to external threats
- Can detect systems that shouldn't be publicly accessible

**Real-World Example:**
An attacker targets a company's network range (e.g., 203.0.113.0/24). Rather than scanning all 256 addresses for ports, they first run a ping scan to find which 20 hosts are actually online. This saves time and reduces detection risk.

**Defense Measures:**
- Configure firewalls to block ICMP from untrusted sources
- Use network segmentation to hide internal hosts
- Implement intrusion detection systems (IDS) to alert on ping sweeps
- Note: Blocking ping doesn't prevent port scanning (attackers can use `-Pn`)

---

## 🔍 TCP Connect Scan: The Basic Port Scanner

### Command: `nmap -sT -p [ports] [target]`

**What it does:**
- Attempts to establish a full TCP connection to each port
- Completes the three-way handshake (SYN, SYN-ACK, ACK)
- Most basic and reliable form of port scanning
- Doesn't require special privileges

**Security Relevance:**

**From an Attacker's Perspective:**
- Identifies which services are accessible (open ports)
- Each open port is a potential attack vector
- Helps determine what the target system is running (web server, SSH, database, etc.)
- Like trying every door and window to see which ones are unlocked

**From a Defender's Perspective:**
- Shows exactly what ports an attacker can see and access
- Helps identify unnecessary open services (attack surface reduction)
- Easily detected and logged by firewalls and IDS
- Good for authorized assessments where stealth isn't a concern

**The Three-Way Handshake:**
```
Scanner          Target
   |               |
   |---> SYN ----->|  (Scanner: "Can I connect?")
   |               |
   |<-- SYN-ACK ---|  (Target: "Yes, I'm open!")
   |               |
   |---> ACK ----->|  (Scanner: "Connection established")
   |               |
   |---> RST ----->|  (Scanner: "Just kidding, goodbye!")
```

**Real-World Example:**
A security consultant performs an authorized assessment of a web server. The TCP connect scan reveals ports 22 (SSH), 80 (HTTP), and 3306 (MySQL) are open. Port 3306 shouldn't be accessible from the internet - this is a security finding. The MySQL database should only be accessible internally.

**Defense Measures:**
- Close unnecessary ports
- Use firewalls to restrict access by source IP
- Implement fail2ban or similar tools to block repeated scan attempts
- Log and monitor for port scanning activities
- Use port knocking for sensitive services

---

## 🕵️ TCP SYN Scan: The Stealth Scanner

### Command: `nmap -sS -p [ports] [target]`

**What it does:**
- Sends SYN packets but doesn't complete the handshake
- If port is open: receives SYN-ACK, sends RST (reset) to abort
- If port is closed: receives RST
- Known as "half-open" or "stealth" scan

**Security Relevance:**

**From an Attacker's Perspective:**
- Less likely to be logged than TCP connect scans
- Many older systems only log completed connections
- Faster than TCP connect scan
- Considered "stealthier" (though modern IDS detect it easily)
- Preferred method for most attackers

**From a Defender's Perspective:**
- Common technique used by attackers and security testers
- Modern IDS/IPS systems easily detect SYN scans
- Indicates more sophisticated scanning activity
- Should trigger security alerts

**The Half-Open Handshake:**
```
Scanner          Target
   |               |
   |---> SYN ----->|  (Scanner: "Are you open?")
   |               |
   |<-- SYN-ACK ---|  (Target: "Yes!")
   |               |
   |---> RST ----->|  (Scanner: "Never mind!" - Connection NOT established)
```

**Why It's "Stealthy":**
- Connection never fully established
- Some old systems only log completed connections
- Leaves fewer traces in application logs
- But: Modern network security tools detect this easily

**Real-World Example:**
A penetration tester is assessing a company's external security. They use SYN scan to identify open ports without generating lots of connection logs on the application servers. This simulates how an attacker would approach the target. The security team's IDS should detect and alert on this activity.

**Defense Measures:**
- Modern firewalls and IDS (e.g., Snort, Suricata) detect SYN scans
- Configure IDS rules to alert on SYN scan patterns
- Use SYN cookies to prevent SYN flood attacks (related technique)
- Rate limit SYN packets from untrusted sources
- Monitor for incomplete connections

**Important Note:**
Despite being called "stealth," SYN scans are NOT invisible to modern security systems!

---

## 🏷️ Service Version Detection: Banner Grabbing

### Command: `nmap -sV -p [ports] [target]`

**What it does:**
- Probes open ports to determine exact service and version
- Sends various probes and analyzes responses
- Identifies software: "Apache 2.4.7" instead of just "http"
- Critical for vulnerability assessment

**Security Relevance:**

**From an Attacker's Perspective:**
- Reveals exact software versions
- Enables targeted exploitation (search for specific version vulnerabilities)
- Shows whether systems are patched or outdated
- Like reading the make, model, and serial number on every lock

**From a Defender's Perspective:**
- Shows exactly what information attackers can gather
- Helps prioritize patching (if old versions are exposed)
- Identifies systems with outdated software
- Demonstrates importance of hiding version information

**How It Works:**
1. Connects to open port
2. Sends service-specific probes
3. Analyzes banner responses
4. Matches against database of known signatures
5. Returns service name and version

**Example Output:**
```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS))
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS))
3306/tcp open mysql   MySQL 5.5.68
```

**Real-World Example:**
A security researcher scans a target and discovers it's running "Apache 2.4.7" on Ubuntu. A quick search reveals this version is vulnerable to CVE-2014-0226 (buffer overflow). Without version detection, the attacker would have to guess or try many different exploits. With version info, they know exactly which exploit to use.

**Defense Measures:**
- Keep all software up to date and patched
- Hide version information in banners (security through obscurity - not a primary defense!)
- Use Web Application Firewalls (WAF) to mask server versions
- Disable unnecessary verbose error messages
- Implement network segmentation (reduce what's accessible)

**Example of Banner Hiding:**
Before: `Server: Apache/2.4.7 (Ubuntu)`  
After: `Server: Apache` (version hidden)

**Important Note:**
Hiding version info is NOT a substitute for patching! Skilled attackers can still fingerprint services through behavior analysis.

---

## ⚡ Top Ports Scan: Quick Reconnaissance

### Command: `nmap --top-ports 20 [target]`

**What it does:**
- Scans only the most commonly used ports
- Based on Nmap's database of port frequency
- Provides quick results without scanning all 65,535 ports
- Default 20 ports include: 21, 22, 23, 25, 80, 110, 139, 443, 445, etc.

**Security Relevance:**

**From an Attacker's Perspective:**
- Quick initial reconnaissance
- Focuses on most likely vulnerable services
- Time-efficient for mass scanning
- Prioritizes high-value targets

**From a Defender's Perspective:**
- Shows most commonly targeted ports
- Highlights critical services to protect
- Demonstrates the 80/20 rule in security
- Good for quick vulnerability assessments

**Most Commonly Targeted Ports:**

| Port | Service | Why Attackers Target It |
|------|---------|------------------------|
| 21 | FTP | Often anonymous access enabled, unencrypted |
| 22 | SSH | Brute force target, remote access |
| 23 | Telnet | Unencrypted, legacy, weak authentication |
| 25 | SMTP | Email relay, spam, information gathering |
| 80 | HTTP | Web vulnerabilities (SQLi, XSS, etc.) |
| 443 | HTTPS | Web vulnerabilities, certificate issues |
| 445 | SMB | File sharing, ransomware (WannaCry, EternalBlue) |
| 3306 | MySQL | Database access, data theft |
| 3389 | RDP | Remote access, ransomware |
| 8080 | HTTP-alt | Alternative web services, often less secured |

**Real-World Example:**
During the WannaCry ransomware outbreak (2017), attackers mass-scanned the internet for port 445 (SMB) to find vulnerable Windows systems. A top ports scan would immediately reveal these vulnerable systems. Organizations that had proper port filtering and patching were protected.

**Defense Measures:**
- Focus hardening efforts on commonly targeted ports
- Close or firewall ports that don't need internet exposure
- Ensure critical services on common ports are fully patched
- Use non-standard ports for some services (security through obscurity - minor benefit)
- Monitor these ports more closely with IDS/IPS

---

## 🔗 Combining Techniques: Layered Reconnaissance

Skilled attackers and professional security testers don't use just one scan type - they layer multiple techniques to build a complete picture.

### Typical Reconnaissance Flow:

1. **Host Discovery** (`-sn`)
   - Find live targets
   - Map network topology
   - Identify IP ranges in use

2. **Port Scanning** (`-sT` or `-sS`)
   - Identify open ports on live hosts
   - Determine accessible services
   - Find potential attack vectors

3. **Service Detection** (`-sV`)
   - Identify exact software versions
   - Look up vulnerabilities
   - Plan exploitation strategy

4. **Advanced Enumeration** (Beyond this tool)
   - OS detection (`-O`)
   - Script scanning (`--script`)
   - Vulnerability scanning
   - Manual investigation

### Real Penetration Testing Scenario:

**Target:** E-commerce company with 203.0.113.0/24 network

**Phase 1 - Discovery:**
```bash
nmap -sn 203.0.113.0/24
```
Result: 47 hosts alive

**Phase 2 - Port Scanning:**
```bash
nmap -sS --top-ports 100 [discovered hosts]
```
Result: Find web servers, databases, admin panels

**Phase 3 - Service Detection:**
```bash
nmap -sV -p 80,443,3306,8080 [interesting hosts]
```
Result: Identify Apache 2.4.7, MySQL 5.5.0 (outdated!)

**Phase 4 - Vulnerability Research:**
- Search CVE databases for Apache 2.4.7
- Search exploit-db for MySQL 5.5.0
- Look for default credentials
- Check for common misconfigurations

**Phase 5 - Reporting:**
Generate professional report with findings and recommendations.

---

## 🛡️ The Defender's Perspective

### Detection Strategies

**Detecting Host Discovery:**
- Monitor for ICMP ping sweeps
- Alert on rapid sequential pings to network range
- Log and analyze ping patterns

**Detecting Port Scans:**
- IDS signatures for SYN scan patterns
- Alert on connections to multiple ports from single source
- Monitor for incomplete connections (SYN scans)
- Rate limiting and blacklisting aggressive scanners

**Detecting Service Enumeration:**
- Log all connection attempts to sensitive services
- Monitor for "weird" traffic patterns (Nmap probes)
- Alert on queries to multiple service ports rapidly

### Prevention Strategies

**Network Layer:**
- Firewall rules (whitelist known sources)
- Network segmentation (internal vs. external)
- Disable unnecessary services
- Use VPNs for remote access

**Service Layer:**
- Keep software updated and patched
- Disable verbose error messages
- Remove version information from banners
- Implement rate limiting

**Monitoring Layer:**
- Deploy IDS/IPS (Snort, Suricata)
- Centralized logging (SIEM)
- Regular security assessments
- Honeypots to detect scanning

---

## 📊 Security Risk Assessment Matrix

| Finding | Risk Level | Explanation |
|---------|-----------|-------------|
| Open port 22 (SSH) with old OpenSSH | HIGH | Known vulnerabilities, remote access risk |
| Open port 3306 (MySQL) to internet | CRITICAL | Database should not be public |
| Open port 80 (HTTP) with current Apache | MEDIUM | Web vulnerabilities possible, but patched |
| Open port 443 (HTTPS) with strong SSL | LOW | Expected and properly secured |
| Telnet (port 23) enabled | CRITICAL | Unencrypted, legacy protocol |
| Random high port open | MEDIUM | Unknown service, requires investigation |

---

## 🎓 Key Learning Takeaways

### For Security Students:

1. **Reconnaissance is the Foundation**
   - Attackers spend 90% of time on recon, 10% on exploitation
   - Good recon leads to successful attacks
   - Defenders must understand recon to detect it

2. **Every Open Port is a Risk**
   - Minimize attack surface by closing unnecessary services
   - "If you don't need it, turn it off"
   - Each service is a potential vulnerability

3. **Version Information is Critical**
   - Attackers use version info to target known vulnerabilities
   - Defenders use it to prioritize patching
   - Hiding versions helps but isn't sufficient

4. **Defense in Depth**
   - No single security measure is enough
   - Layer multiple defenses (firewall + IDS + patching + monitoring)
   - Assume attackers will get past some defenses

5. **Legal and Ethical Boundaries**
   - Reconnaissance without authorization is illegal
   - Even passive scanning can be prosecuted
   - Always get written permission

### For Defenders:

1. **Know Your Attack Surface**
   - Regularly scan your own networks
   - Find vulnerabilities before attackers do
   - Document and justify every open port

2. **Patch Management is Critical**
   - Outdated software is the #1 attack vector
   - Prioritize internet-facing services
   - Automate patching where possible

3. **Monitor for Reconnaissance**
   - Most attacks start with scanning
   - Early detection gives time to respond
   - Log everything, analyze patterns

4. **Test Your Defenses**
   - Regular penetration testing
   - Red team exercises
   - Continuous security assessments

---

## 🔍 Practical Exercises

### Exercise 1: Compare Scan Types
1. Scan scanme.nmap.org with `-sT` (TCP connect)
2. Scan the same target with `-sS` (SYN) - requires admin
3. Compare the results and timing
4. Question: Why might results differ?

### Exercise 2: Service Enumeration
1. Perform service detection scan (`-sV`)
2. For each identified service and version, research:
   - Is this the latest version?
   - Are there known vulnerabilities? (Check CVE)
   - What is the exploitability?
3. Write a brief risk assessment

### Exercise 3: Defense Simulation
1. Set up a VM with various services
2. Scan it from another machine
3. Review the VM's logs
4. Configure firewall rules
5. Scan again and observe the difference

### Exercise 4: Reconnaissance Report
1. Perform layered reconnaissance on an authorized target
2. Document each phase and findings
3. Create a professional report with:
   - Executive summary
   - Technical findings
   - Risk assessment
   - Remediation recommendations

---

## 📚 Additional Resources

**Books:**
- "Nmap Network Scanning" by Gordon Lyon (Nmap creator)
- "The Web Application Hacker's Handbook" by Stuttard & Pinto
- "Penetration Testing" by Georgia Weidman

**Online Resources:**
- Nmap Documentation: https://nmap.org/book/
- OWASP Testing Guide: https://owasp.org/
- CVE Database: https://cve.mitre.org/
- Exploit Database: https://www.exploit-db.com/

**Practice Platforms:**
- HackTheBox (https://hackthebox.eu)
- TryHackMe (https://tryhackme.com)
- PentesterLab (https://pentesterlab.com)
- OverTheWire (https://overthewire.org)

---

## ⚖️ Legal and Ethical Reminders

**Before scanning ANY network:**
1. ✅ Obtain explicit written permission
2. ✅ Define scope clearly (which systems, which tests)
3. ✅ Agree on timing and procedures
4. ✅ Have a communication plan for findings
5. ✅ Follow responsible disclosure practices

**Unauthorized scanning can result in:**
- Criminal prosecution
- Civil lawsuits
- Expulsion from school
- Job termination
- Banned from security industry

**"But I was just learning!" is NOT a valid defense.**

---

## 🎯 Conclusion

Network reconnaissance using Nmap is a fundamental skill in information security. Whether you're pursuing a career as a:
- **Penetration Tester**: You'll use these techniques to assess security
- **Security Analyst**: You'll detect and respond to these activities
- **System Administrator**: You'll harden systems against these techniques
- **Security Researcher**: You'll understand how attackers gather information

Understanding both the offensive and defensive aspects of network scanning is essential for any security professional.

**Remember:** 
> "With great power comes great responsibility. Use your knowledge ethically and legally!"

---

*This document is part of the Network Security Assessment Tool educational project.*  
*For questions, consult your course instructor.*
