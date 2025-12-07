# Network Security Assessment Tool

## Educational Security Project - Introduction to Security Course

A Python-based educational tool for learning network reconnaissance and security assessment techniques using Nmap. This project demonstrates fundamental security concepts covered in introductory cybersecurity courses.

---

## ⚠️ LEGAL DISCLAIMER

**IMPORTANT:** This tool is for **educational purposes only**. Unauthorized network scanning is **illegal** in most jurisdictions and may violate:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other countries

**You MUST:**
- Obtain explicit written permission before scanning any network or system
- Only use on networks and systems you own or have authorization to test
- Comply with all applicable laws and regulations
- Use the official Nmap test server (scanme.nmap.org) for practice

By using this tool, you acknowledge and agree to use it legally and responsibly.

---

## 📋 Project Overview

This tool automates basic network reconnaissance tasks to help students understand:
- How attackers gather information about networks (reconnaissance phase)
- Different types of network scanning techniques
- How to identify active hosts and open ports
- Service enumeration and version detection
- Professional security report generation

### Educational Learning Objectives

1. **Reconnaissance Fundamentals**: Understand the first phase of penetration testing
2. **Scan Techniques**: Learn differences between TCP Connect, SYN stealth, and other scans
3. **Service Enumeration**: Identify services and versions for vulnerability assessment
4. **Report Writing**: Practice documenting security findings professionally
5. **Legal/Ethical Awareness**: Understand the importance of authorization and responsible disclosure

---

## 🎯 Features

- **Multiple Scan Types** (from course materials):
  - Host Discovery (Ping Scan) - Identify active hosts
  - TCP Connect Scan - Full connection port scanning
  - TCP SYN Scan (Stealth) - Half-open stealthy scanning
  - Service Version Detection - Identify software versions
  - Top Ports Scan - Quick scan of most common ports

- **Flexible Target Input**:
  - Manual console entry
  - File-based target lists
  - Support for IP addresses, CIDR notation, and domains

- **Intelligent Parsing**:
  - Extracts ports, services, and versions from Nmap output
  - Organizes results by target and scan type

- **Professional PDF Reports**:
  - Executive summary with statistics
  - Methodology explanation with security context
  - Detailed findings per target
  - Educational takeaways and recommendations

- **Educational Comments**:
  - Each scan type includes security purpose explanation
  - Code is heavily commented for learning

---

## 📦 Installation

### Prerequisites

1. **Python 3.7+**
   - Download from: https://www.python.org/downloads/

2. **Nmap**
   - Download from: https://nmap.org/download.html
   - Ensure `nmap` is in your system PATH

### Step 1: Clone or Download

Download this project to your local machine.

### Step 2: Install Python Dependencies

```powershell
cd NetworkAssessmentTool
pip install -r requirements.txt
```

### Step 3: Verify Installation

```powershell
# Check Python
python --version

# Check Nmap
nmap --version

# Test the tool
python network_assessment_tool.py
```

---

## 🚀 Usage

### Interactive Mode (Recommended for Learning)

Simply run the tool without arguments for an interactive guided experience:

```powershell
python network_assessment_tool.py
```

The tool will guide you through:
1. Legal disclaimer and agreement
2. Target specification (manual or file-based)
3. Scan type selection
4. Port range configuration
5. Assessment execution
6. Report generation

### Automated Mode (For Scripting)

For automated assessments with pre-configured settings:

```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s ping,tcp_connect,service_version -p 1-1000
```

**Arguments:**
- `-f, --file`: Path to targets file
- `-s, --scans`: Comma-separated scan types
- `-p, --ports`: Port range (e.g., `1-1000`, `80,443,8080`)
- `-o, --output`: Output directory (default: `output`)

### Example Commands

**Quick scan of top ports:**
```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s ping,top_ports -o results
```

**Comprehensive scan:**
```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s ping,tcp_connect,service_version -p 1-5000 -o reports
```

**Specific ports only:**
```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s tcp_connect,service_version -p 22,80,443,3389,8080
```

---

## 📁 Project Structure

```
NetworkAssessmentTool/
│
├── network_assessment_tool.py    # Main application
│
├── modules/                       # Core functionality modules
│   ├── __init__.py
│   ├── input_handler.py          # Target input and validation
│   ├── nmap_executor.py          # Nmap command execution
│   ├── output_parser.py          # Result parsing and analysis
│   └── pdf_generator.py          # PDF report generation
│
├── examples/                      # Example files
│   ├── targets_example.txt       # Example targets file
│   └── targets_authorized.txt    # Authorized test targets
│
├── output/                        # Generated reports (created automatically)
│   └── network_assessment_report_YYYYMMDD_HHMMSS.pdf
│
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

---

## 🔍 Understanding Nmap Commands Used

This tool uses ONLY basic Nmap commands covered in introductory security courses:

### 1. Host Discovery (Ping Scan)
```bash
nmap -sn [target]
```
**Purpose**: Identifies which hosts are alive without port scanning  
**Security Context**: First step in reconnaissance to map the network  
**Course Section**: Host Discovery

### 2. TCP Connect Scan
```bash
nmap -sT -p [ports] -Pn [target]
```
**Purpose**: Full TCP connection to determine open ports  
**Security Context**: Most basic and detectable port scanning technique  
**Course Section**: Scan Techniques

### 3. TCP SYN Scan (Stealth)
```bash
nmap -sS -p [ports] -Pn [target]
```
**Purpose**: Half-open scan, doesn't complete TCP handshake  
**Security Context**: Stealthier, less likely to be logged  
**Course Section**: Scan Techniques  
**Note**: Requires root/administrator privileges

### 4. Service Version Detection
```bash
nmap -sV -p [ports] -Pn [target]
```
**Purpose**: Identifies software versions on open ports  
**Security Context**: Critical for vulnerability assessment  
**Course Section**: Service & Version Detection

### 5. Top Ports Scan
```bash
nmap --top-ports 20 -Pn [target]
```
**Purpose**: Quick scan of most commonly used ports  
**Security Context**: Efficient initial reconnaissance  
**Course Section**: Port Specification

**Common Options Used:**
- `-v`: Verbose output for better visibility
- `-Pn`: Skip ping (assume host is up) - useful when ICMP is blocked
- `-p [range]`: Specify port range

---

## 📊 Output and Reports

### Console Output

During execution, the tool provides real-time feedback:
- Scan progress and status
- Discovered hosts and ports
- Warnings and errors
- Quick summary of findings

### PDF Reports

Professional reports include:

1. **Cover Page**
   - Report metadata
   - Target count and scan statistics
   - Legal disclaimer

2. **Executive Summary**
   - High-level findings overview
   - Statistics table
   - Services discovered

3. **Methodology Section**
   - Explanation of each scan type used
   - Security purpose of each technique
   - Relevance to reconnaissance phase

4. **Detailed Findings**
   - Per-target analysis
   - Open ports table with services
   - Version information
   - Security implications

5. **Conclusions**
   - Educational takeaways
   - Security recommendations
   - Learning outcomes

Reports are saved to the `output/` directory with timestamps.

---

## 🎓 Educational Use Cases

### 1. Learning Network Reconnaissance

Practice the reconnaissance phase of penetration testing:
- Discover live hosts on a network
- Identify open ports and services
- Gather version information

### 2. Understanding Scan Types

Compare different scanning techniques:
- Speed vs. stealth tradeoffs
- Privilege requirements
- Detection likelihood

### 3. Security Report Writing

Learn professional security documentation:
- Organize findings clearly
- Explain security implications
- Provide actionable recommendations

### 4. Lab Exercises

Suggested exercises for students:

**Exercise 1: Basic Discovery**
- Scan scanme.nmap.org with all scan types
- Compare results and timing
- Analyze which scans are most informative

**Exercise 2: Port Analysis**
- Scan with different port ranges
- Document all discovered services
- Research vulnerabilities for found versions

**Exercise 3: Stealth vs. Detection**
- Compare TCP Connect vs. SYN scans
- Discuss detection mechanisms
- Explain why stealth matters

**Exercise 4: Report Analysis**
- Review generated PDF reports
- Identify critical findings
- Propose security hardening measures

---

## 🔧 Troubleshooting

### "Nmap is not installed or not in PATH"

**Solution**: Install Nmap and ensure it's accessible:
- Windows: Add Nmap installation directory to PATH
- Verify with: `nmap --version`

### "Permission denied" or scan failures

**Solution**: Some scans (like SYN scan) require administrator privileges:
- Windows: Run PowerShell as Administrator
- Linux/Mac: Use `sudo python network_assessment_tool.py`

### PDF generation fails

**Solution**: Ensure reportlab is installed:
```powershell
pip install reportlab
```

### Scan takes too long

**Solutions**:
- Reduce port range (use `-p 1-100` instead of `-p 1-5000`)
- Use top ports scan
- Scan fewer targets at once
- Check network connectivity

### Target appears down but you know it's up

**Solution**: The target may be blocking ping (ICMP):
- The tool already uses `-Pn` to skip ping for port scans
- Some firewalls still block all probes
- Try scanning specific ports: `-p 80,443`

---

## 🛡️ Security Considerations

### What This Tool Does

✅ Performs passive network reconnaissance  
✅ Identifies open ports and services  
✅ Detects software versions  
✅ Generates educational reports

### What This Tool Does NOT Do

❌ Exploit vulnerabilities  
❌ Attempt unauthorized access  
❌ Perform brute force attacks  
❌ Execute malicious code  
❌ Evade detection systems (intentionally)

### Defensive Perspective

This tool helps defenders understand:
- How attackers perform reconnaissance
- What information is publicly visible
- Which services are exposed
- How to detect scanning activities

### Responsible Use Guidelines

1. **Authorization**: Always get written permission
2. **Scope**: Stay within authorized targets
3. **Timing**: Avoid production systems during peak hours
4. **Disclosure**: Report findings to system owners
5. **Documentation**: Keep records of authorization

---

## 📚 Learning Resources

### Related Course Sections

This tool covers material from:
- Section 3: Target Specification
- Section 4: Scan Techniques  
- Section 5: Port Specification & Service Detection
- Section 6: Practical Application

### Additional Resources

- **Nmap Official Documentation**: https://nmap.org/book/
- **Nmap Network Scanning (Book)**: By Gordon "Fyodor" Lyon
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Ethical Hacking Courses**: Offensive Security, SANS Institute

### Practice Environments

Safe places to practice:
- **scanme.nmap.org**: Official Nmap test server
- **HackTheBox**: https://www.hackthebox.eu/
- **TryHackMe**: https://tryhackme.com/
- **Your own lab**: Virtual machines on isolated network

---

## 🤝 Contributing

This is an educational project for learning purposes. Students are encouraged to:
- Add comments explaining security concepts
- Implement additional basic scan types from course materials
- Improve error handling and user experience
- Enhance report formatting
- Add more educational content

**Note**: Do not add advanced exploitation features or aggressive scanning techniques.

---

## 📄 License

This project is provided for educational purposes only. Use at your own risk and responsibility.

---

## ✨ Credits

- **Nmap**: Created by Gordon "Fyodor" Lyon (https://nmap.org)
- **ReportLab**: PDF generation library (https://www.reportlab.com)
- **Course Materials**: Introduction to Security curriculum

---

## 📧 Contact

For questions about this educational project, consult your course instructor or teaching assistant.

---

## 🎯 Learning Outcomes

After completing this project, students should be able to:

1. ✅ Explain the reconnaissance phase of penetration testing
2. ✅ Execute various network scanning techniques using Nmap
3. ✅ Differentiate between scan types and their purposes
4. ✅ Interpret scan results and identify security exposures
5. ✅ Document findings in professional security reports
6. ✅ Understand legal and ethical considerations in security testing
7. ✅ Apply defensive thinking to detect and prevent reconnaissance

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally!** 🔒
