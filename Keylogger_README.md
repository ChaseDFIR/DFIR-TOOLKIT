
# PowerShell Keylogger for DFIR Simulation & Malware Analysis

This PowerShell-based keylogger is designed for **Digital Forensics and Incident Response (DFIR)** training, malware reverse engineering, and detection engineering in **controlled environments**. It simulates real-world adversary behavior for blue team exercises, sandbox analysis, and behavioral detection testing.

> ⚠️ **Ethical Use Notice**  
> This tool is intended **strictly for educational, research, and authorized testing purposes**. Do not deploy on live systems or networks without explicit permission. Misuse may violate laws, organizational policies, or ethical standards.

---

## 🔍 Features

- Records all keystrokes using Windows API hooks
- Captures clipboard content at regular intervals
- Saves logs to `C:\Windows\System32\Content\` (simulating stealthy persistence)
- Automatically exfiltrates data to `http://192.168.0.1/uploads` every 12 hours
- Modular structure for integration into DFIR labs or malware simulation frameworks

---

## 🛠️ Usage

1. Open PowerShell with administrative privileges.
2. Run the script:
   ```powershell
   .\Keylogger.ps1
