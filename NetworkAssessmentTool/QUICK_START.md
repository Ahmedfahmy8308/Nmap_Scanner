# Quick Start Guide

## Network Security Assessment Tool

### 🚀 5-Minute Setup

#### Step 1: Prerequisites
Ensure you have:
- ✅ Python 3.7+ installed
- ✅ Nmap installed (https://nmap.org/download.html)

#### Step 2: Install Dependencies
```powershell
cd NetworkAssessmentTool
pip install -r requirements.txt
```

#### Step 3: First Run
```powershell
python network_assessment_tool.py
```

Follow the interactive prompts!

---

## 📝 Quick Examples

### Example 1: Interactive Mode (Recommended for Beginners)
```powershell
python network_assessment_tool.py
```
Then follow the guided steps:
1. Accept legal disclaimer
2. Choose manual entry or file input
3. Enter target: `scanme.nmap.org`
4. Select scan types (or press Enter for defaults)
5. Wait for results
6. View PDF report in `output/` folder

### Example 2: Quick Automated Scan
```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s ping,tcp_connect -p 1-1000
```

### Example 3: Comprehensive Scan
```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s ping,tcp_connect,service_version -p 1-5000 -o reports
```

### Example 4: Fast Top Ports Scan
```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s top_ports
```

---

## 🎯 Typical Workflow

1. **Create Target File**
   ```
   Edit: examples/targets_authorized.txt
   Add your authorized targets (one per line)
   ```

2. **Run Scan**
   ```powershell
   python network_assessment_tool.py -f examples/targets_authorized.txt -s ping,tcp_connect,service_version
   ```

3. **Review Results**
   ```
   - Check console output for summary
   - Open PDF report in output/ folder
   - Review findings and security implications
   ```

4. **Take Action**
   ```
   - Document open ports
   - Research service versions
   - Propose security improvements
   ```

---

## ⚙️ Command-Line Options

```
-f, --file      Path to targets file
-s, --scans     Comma-separated scan types
                Options: ping, tcp_connect, syn_stealth, service_version, top_ports
-p, --ports     Port range (e.g., 1-1000, 80,443,8080)
-o, --output    Output directory (default: output)
```

---

## 🔍 Available Scan Types

| Type | Command | Description | Requires Admin? |
|------|---------|-------------|-----------------|
| `ping` | `-sn` | Host discovery only | No |
| `tcp_connect` | `-sT` | Full TCP connection | No |
| `syn_stealth` | `-sS` | Half-open scan | Yes |
| `service_version` | `-sV` | Detect service versions | No |
| `top_ports` | `--top-ports 20` | Scan common ports | No |

---

## 🎓 Learning Path

### Beginner
1. Run interactive mode on scanme.nmap.org
2. Use only `ping` and `tcp_connect` scans
3. Review generated PDF report
4. Read SECURITY_CONCEPTS.md

### Intermediate
1. Create custom target file with lab systems
2. Try all scan types
3. Compare results and timing
4. Practice report writing

### Advanced
1. Set up VM lab environment
2. Practice stealth vs. detection
3. Configure IDS to detect scans
4. Perform full security assessment

---

## 🛠️ Troubleshooting Quick Fixes

**Problem:** "Nmap not found"  
**Solution:** Install Nmap and add to PATH, or run from Nmap directory

**Problem:** "Permission denied"  
**Solution:** Run PowerShell as Administrator for SYN scans

**Problem:** "PDF error"  
**Solution:** `pip install reportlab`

**Problem:** Scan too slow  
**Solution:** Reduce port range: `-p 1-100`

---

## ⚠️ Important Reminders

1. **Always get authorization** before scanning any network
2. **scanme.nmap.org** is the official Nmap test server (authorized)
3. **Never scan** production systems without approval
4. **Review logs** in output folder for debugging
5. **Read SECURITY_CONCEPTS.md** to understand the security implications

---

## 📊 Expected Output

### Console Output:
- Real-time scan progress
- Discovered hosts and ports
- Warnings and errors
- Quick summary statistics

### PDF Report Contents:
- Cover page with metadata
- Executive summary
- Methodology explanation
- Detailed findings per target
- Security implications
- Recommendations

---

## 🔗 Next Steps

After completing your first scan:

1. ✅ Review the PDF report thoroughly
2. ✅ Read SECURITY_CONCEPTS.md for detailed explanations
3. ✅ Try different scan combinations
4. ✅ Practice on authorized lab environments
5. ✅ Document your learning and findings

---

## 📚 Essential Files

- `README.md` - Complete documentation
- `SECURITY_CONCEPTS.md` - In-depth security explanations
- `examples/targets_authorized.txt` - Safe test targets
- `requirements.txt` - Python dependencies

---

## 🎯 Quick Reference: Common Tasks

**Scan single target:**
```powershell
python network_assessment_tool.py
# Then enter: scanme.nmap.org
```

**Scan from file:**
```powershell
python network_assessment_tool.py -f examples/targets_authorized.txt -s tcp_connect
```

**Fast scan:**
```powershell
python network_assessment_tool.py -f targets.txt -s top_ports
```

**Complete assessment:**
```powershell
python network_assessment_tool.py -f targets.txt -s ping,tcp_connect,service_version -p 1-5000
```

---

## 💡 Tips for Success

1. **Start simple** - Use ping and tcp_connect first
2. **Use scanme.nmap.org** for practice
3. **Read the reports** - Don't just generate them
4. **Understand why** - Read SECURITY_CONCEPTS.md
5. **Practice ethically** - Only scan authorized targets
6. **Document everything** - Keep notes on findings
7. **Ask questions** - Consult your instructor

---

## 🆘 Getting Help

1. Check the error message carefully
2. Review README.md for detailed information
3. Verify Nmap is installed: `nmap --version`
4. Check Python version: `python --version`
5. Consult your course instructor

---

**Ready to start? Run:**
```powershell
python network_assessment_tool.py
```

**Good luck and scan responsibly! 🔒**
