# CyberNexsus Edge AI SOC: Local-First AI Security Investigation Platform

```
╔══════════════════════════════════════════════════════════════════════╗
║                    CYBERNEXSUS EDGE AI SOC                         ║
║             LOCAL-FIRST AI SECURITY INVESTIGATION                  ║
╚══════════════════════════════════════════════════════════════════════╝

                         SOC ANALYST
                              │
                              ▼
                ┌─────────────────────────┐
                │ CyberNexsus Dashboard   │
                │                         │
                │ Alerts                  │
                │ Threat Timeline         │
                │ MITRE ATT&CK            │
                │ AI Investigation        │
                │ Reports                 │
                └────────────┬────────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │ CyberNexsus API         │
                │                         │
                │ Event Manager           │
                │ AI Orchestrator         │
                │ Investigation Manager   │
                └────────────┬────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │       SECURITY DATA          │
              │                              │
              │ Windows Event Logs           │
              │ Sysmon                       │
              │ Linux auth.log / syslog      │
              │ Zeek                         │
              │ Suricata                     │
              │ Splunk                       │
              └──────────────┬───────────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │ Event Normalizer        │
                │                         │
                │ Parse                  │
                │ Normalize              │
                │ Deduplicate            │
                │ Correlate              │
                └────────────┬────────────┘
                             │
                   ┌─────────┴─────────┐
                   ▼                   ▼
          ┌─────────────────┐   ┌─────────────────┐
          │ Detection Engine│   │ Local AI Engine │
          │                 │   │                 │
          │ Rules           │   │ Security RAG    │
          │ IOC             │   │ Local LLM       │
          │ Correlation     │   │ AI Agent        │
          │ Risk Score      │   │ Investigation   │
          └────────┬────────┘   └────────┬────────┘
                   │                     │
                   │                     ▼
                   │          ╔══════════════════════╗
                   │          ║ SNAPDRAGON PC        ║
                   │          ║                      ║
                   │          ║ Local AI Model       ║
                   │          ║                      ║
                   │          ║ Qwen / Phi /         ║
                   │          ║ other supported     ║
                   │          ║ open-source model   ║
                   │          ║          │           ║
                   │          ║          ▼           ║
                   │          ║ ONNX Runtime / QNN   ║
                   │          ║          │           ║
                   │          ║    ┌─────┼─────┐     ║
                   │          ║    ▼     ▼     ▼     ║
                   │          ║   NPU   GPU   CPU    ║
                   │          ╚══════════╬═══════════╝
                   │                     │
                   └──────────┬──────────┘
                              ▼
                   ┌─────────────────────┐
                   │ Investigation Result│
                   │                     │
                   │ Attack hypothesis   │
                   │ IOC extraction      │
                   │ Event correlation   │
                   │ MITRE mapping       │
                   │ Explanation         │
                   │ Recommendations     │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ CyberNexsus Report  │
                   │                     │
                   │ Risk: 82/100        │
                   │ Severity: HIGH      │
                   │ MITRE: T1110        │
                   │ Evidence            │
                   │ AI Explanation      │
                   └──────────┬──────────┘
                              │
                    ┌─────────┼─────────┐
                    ▼         ▼         ▼
                 Dashboard  Timeline  Telegram
```

---

## 📑 Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [How to Connect with a Real PC](#2-how-to-connect-with-a-real-pc)
3. [How to Remove Mock Data](#3-how-to-remove-mock-data)
4. [How to Connect with Real Security Data](#4-how-to-connect-with-real-security-data)
   - [Windows Event Logs & Sysmon](#a-windows-event-logs--microsoft-sysmon)
   - [Linux auth.log & syslog](#b-linux-authlog--syslog)
   - [Zeek & Suricata Network Feeds](#c-zeek--suricata-network-feeds)
   - [Splunk Integration](#d-splunk-enterprise--cloud)
5. [How to Configure and Run Real AI Models Locally](#5-how-to-configure-and-run-real-ai-models-locally)
6. [How to Configure All Tools and Features Step-by-Step](#6-how-to-configure-all-tools-and-features-step-by-step)
   - [CVSS v3.1 Standards Calculator](#tool-1-cvss-v31-standards-calculator)
   - [Threat Timeline & Killchain](#tool-2-threat-timeline--killchain)
   - [MITRE ATT&CK Matrix Navigator](#tool-3-mitre-attck-matrix-navigator)
   - [AI Investigation Workbench & Copilot](#tool-4-ai-investigation-workbench--copilot)
   - [Event Normalizer & Ingestion Pipeline](#tool-5-event-normalizer--ingestion-pipeline)
   - [SOC Reports & DFIR Playbooks](#tool-6-soc-incident-reports--dfir-playbooks)
   - [Telegram SOC Alert Dispatcher](#tool-7-telegram-soc-alert-dispatcher)
7. [Production Deployment Guide](#7-production-deployment-guide)

---

## 1. Executive Overview

**CyberNexsus Edge AI SOC** is an autonomous, on-device security operations center platform designed to run 100% locally on endpoint hardware (specifically optimized for **Snapdragon PC** with Qualcomm Hexagon NPU, as well as Windows, Linux, and macOS workstations).

- **100% Local-First / Zero Cloud Egress**: Sensitive security logs, enterprise credentials, and host telemetry never leave the workstation.
- **Zero Third-Party API Keys**: Uses open-source Edge AI models (**Qwen 2.5 Coder**, **Phi-3.5-mini**, **Phi-4-mini**, **DeepSeek-R1-Distill**) via ONNX Runtime & Qualcomm QNN execution providers.
- **Official CVSS v3.1 Engine**: Computes exact Base Scores, Exploitability, Impact, and standard vector strings according to FIRST.org specifications.
- **Multi-Source CIM Normalizer**: Standardizes Windows Event Logs, Sysmon, Linux `auth.log`, Zeek, Suricata, and Splunk into a unified schema with semantic deduplication.

---

## 2. How to Connect with a Real PC

You can run CyberNexsus directly on your physical machine or edge hardware.

### Hardware Targets
- **Snapdragon PC (Qualcomm Snapdragon X Elite / Snapdragon X Plus)**:
  - NPU: 45 TOPS Qualcomm Hexagon NPU running via Qualcomm Neural Processing SDK (QNN) and ONNX Runtime DirectML / QNN EP.
  - Power: ~6–8 Watts operational draw under full AI inference.
- **Standard Windows 11 PC (Intel / AMD / NVIDIA)**:
  - Runs with DirectML GPU acceleration or CPU SIMD.
- **Linux Workstation (Ubuntu / Debian / RHEL / Fedora)**:
  - Runs natively via WebGPU / ONNX Runtime Web.

### Step-by-Step Installation on Real PC

#### Step 1: Install Node.js
Ensure Node.js 18.x or 20.x+ is installed:
```bash
node -v
npm -v
```

#### Step 2: Clone & Install Dependencies
Open PowerShell (on Windows) or Terminal (on Linux/macOS):
```bash
git clone https://github.com/cybernexsus/edge-ai-soc.git
cd edge-ai-soc
npm install
```

#### Step 3: Run Dev Server on Localhost
```bash
npm run dev
```
Open your browser to:
```
http://localhost:3000
```

#### Step 4: Configure Qualcomm Snapdragon NPU Drivers (Snapdragon PC Only)
If running on a Snapdragon X Elite / Plus laptop (e.g. Surface Laptop 7, Lenovo ThinkPad T14s Gen 6, Dell XPS 13 9345):
1. Verify Qualcomm NPU drivers in Windows Device Manager:
   `Device Manager` -> `Neural Processing Units` -> `Qualcomm Hexagon NPU`.
2. Windows Copilot+ PC automatically provides DirectML and ONNX Runtime QNN drivers.
3. In CyberNexsus, open the **Execution Target** selector in the top bar and ensure **NPU (Hexagon 45 TOPS)** is active.

---

## 3. How to Remove Mock Data

CyberNexsus includes pre-loaded sample incidents for demonstration purposes. Here is how to remove them and operate exclusively on live real PC data:

### Method A: One-Click UI Toggle (Instant Live Mode)
1. In the top navigation bar, locate the **`DEMO THREAT MODE`** button.
2. Click **`Purge Mock`** or click the badge.
3. The platform immediately transitions into **`LIVE REAL PC MODE`**:
   - All demo alerts, seed events, and mock IOCs are purged from memory (`alerts: []`, `events: []`).
   - The queue displays `0 Incidents` and enters passive listening mode waiting for your real security feeds.
4. *(Optional)* If you ever want to reload the demo threat scenarios for testing, click **`Reload Demo`**.

### Method B: Code-Level Permanent Removal (Production Build)
To permanently remove mock seed data from your codebase:

1. Open `src/App.tsx`.
2. Change the default state declarations from `INITIAL_ALERTS` and `INITIAL_EVENTS` to empty arrays:
   ```typescript
   // Change from:
   const [isLiveMode, setIsLiveMode] = useState<boolean>(false);
   const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_ALERTS);
   const [events, setEvents] = useState<NormalizedSecurityEvent[]>(INITIAL_EVENTS);
   const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(INITIAL_ALERTS[0]);

   // Change to:
   const [isLiveMode, setIsLiveMode] = useState<boolean>(true);
   const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
   const [events, setEvents] = useState<NormalizedSecurityEvent[]>([]);
   const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
   ```
3. Remove or comment out the imports from `src/data/mockData.ts`.
4. Rebuild the application:
   ```bash
   npm run build
   ```

---

## 4. How to Connect with Real Security Data

CyberNexsus features built-in parsers for heterogeneous log sources. You can feed real logs via:
1. **Interactive File Upload** (Drag-and-drop `.log`, `.xml`, `.json`, `.txt`).
2. **PowerShell / Bash Log Forwarder Scripts**.
3. **Automated Log Collectors (Winlogbeat, Rsyslog, Syslog-ng, Splunk HEC)**.

---

### A. Windows Event Logs & Microsoft Sysmon

#### Step 1: Install Sysmon on your Real Windows PC
1. Download Microsoft Sysmon from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Install with the SwiftOnSecurity detection configuration:
   ```powershell
   # Run in Administrator PowerShell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmon.xml"
   sysmon64.exe -accepteula -i "$env:TEMP\sysmon.xml"
   ```

#### Step 2: Enable Process Creation Command-Line Auditing
Enable Event ID 4688 to capture complete CLI arguments:
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

#### Step 3: Stream Live Logs into CyberNexsus
Open PowerShell as Administrator:
```powershell
# Export recent Sysmon (1, 3, 10) & Windows Security (4688) to an XML file:
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,10} -MaxEvents 50 | 
  ForEach-Object { $_.ToXml() } | Out-File -FilePath "$HOME\Desktop\real_sysmon.xml" -Encoding utf8

# Or copy 5 latest process executions directly to clipboard:
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5 | 
  ForEach-Object { $_.ToXml() } | Set-Clipboard
```
In CyberNexsus:
1. Go to **Log Normalizer**.
2. Click **Upload Real PC Log File** and select `real_sysmon.xml` (or paste clipboard content).
3. Click **Ingest & Run Detection**. The detection engine will correlate the events in real time.

---

### B. Linux auth.log & syslog

#### Step 1: Verify Authentication Logging
On Debian/Ubuntu, SSH logins are logged in `/var/log/auth.log`. On RHEL/CentOS/Fedora, they are in `/var/log/secure`.

#### Step 2: Export Live Logs
```bash
# Capture last 100 authentication events (SSH brute force, sudo abuse):
journalctl -u ssh -u sshd -n 100 --no-pager > ~/real_auth.log

# Or tail the active auth.log:
tail -n 100 /var/log/auth.log > ~/real_auth.log
```

#### Step 3: Stream via Curl / HTTP Ingestion
You can pipe raw logs directly into CyberNexsus:
```bash
cat ~/real_auth.log | pbcopy   # (macOS) or xclip (Linux)
```
Paste into the **Log Normalizer** input box and click **Ingest & Run Detection**.

---

### C. Zeek & Suricata Network Feeds

#### Real Suricata Setup
1. Configure Suricata to generate EVE JSON logs at `/var/log/suricata/eve.json`.
2. Extract real alert events:
   ```bash
   tail -n 50 /var/log/suricata/eve.json | grep '"event_type":"alert"' > ~/suricata_alerts.json
   ```
3. Upload `suricata_alerts.json` into the CyberNexsus **Log Normalizer**.

#### Real Zeek Setup
1. Zeek stores connection and DNS flows at `/opt/zeek/logs/current/conn.log` and `dns.log`.
2. Convert TSV or JSON log lines and ingest into the normalizer.

---

### D. Splunk Enterprise / Cloud

To forward real alerts from Splunk:
1. In Splunk Web, go to **Settings** -> **Searches, reports, and alerts**.
2. Open your alert rule -> **Trigger Actions** -> **Webhook** or **Export as JSON**.
3. Export raw CIM results as JSON.
4. Upload the JSON file in CyberNexsus under the **Splunk CIM JSON** parser.

---

## 5. How to Configure and Run Real AI Models Locally

CyberNexsus supports edge models optimized for Qualcomm Hexagon NPU, Adreno GPU, and Oryon CPU.

### Available Edge Models:
1. **Qwen2.5-Coder-1.5B-Instruct (INT4)**:
   - Size: 980 MB
   - Primary Use: Rapid incident triage, malicious PowerShell/bash script deobfuscation.
   - Recommended Hardware: **Snapdragon NPU** (42+ tok/s).
2. **Phi-3.5-mini-instruct (3.8B INT4)**:
   - Size: 2.1 GB
   - Primary Use: High-order chain-of-thought killchain correlation and MITRE ATT&CK synthesis.
   - Recommended Hardware: **Snapdragon NPU** or **DirectML GPU**.
3. **Qwen2.5-7B-Security-Instruct (INT4)**:
   - Size: 4.2 GB
   - Primary Use: Deep adversary attribution and enterprise forensics.
   - Recommended Hardware: **Snapdragon GPU / Adreno**.
4. **Phi-4-mini (3.8B Next-Gen)** & **DeepSeek-R1-Distill-Qwen (1.5B)**:
   - Compact high-density reasoning models.

### Step-by-Step Model Download & Activation:
1. Click the **Model Hub** button in the header (e.g., `Qwen2.5 (INT4)`).
2. Browse the model list.
3. Click **Download Weights** next to your chosen model.
   - Progress bar displays download speed (MB/s) and caches weights persistently in the browser's local OPFS / CacheStorage.
4. Once downloaded, click **Load Into Engine**.
5. Click **Benchmark NPU** to measure your PC's real inference speed (tokens/sec and latency).

---

## 6. How to Configure All Tools and Features Step-by-Step

### TOOL 1: CVSS v3.1 Standards Calculator
CyberNexsus implements the exact FIRST.org specification.

#### How to Use:
1. Click **CVSS v3.1** in the top navigation bar (or click any alert's CVSS score box).
2. The calculator modal opens with the 8 Base Metrics:
   - **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P).
   - **Attack Complexity (AC)**: Low (L), High (H).
   - **Privileges Required (PR)**: None (N), Low (L), High (H).
   - **User Interaction (UI)**: None (N), Required (R).
   - **Scope (S)**: Unchanged (U), Changed (C).
   - **Confidentiality Impact (C)**: None (N), Low (L), High (H).
   - **Integrity Impact (I)**: None (N), Low (L), High (H).
   - **Availability Impact (A)**: None (N), Low (L), High (H).
3. The Base Score, Exploitability, Impact, and Vector String update dynamically.
4. Click **Apply Score to Alert** to bind the calibrated score directly to your incident.

---

### TOOL 2: Threat Timeline & Killchain
Visualizes the chronological sequence of chained events across endpoints and networks.

#### How to Use:
1. Open the **Threat Timeline** tab.
2. Select an **Incident Scope** from the dropdown (or view all aggregated feeds).
3. Click any event node along the chronological path to inspect:
   - Source Parser (Sysmon, Windows Event, Linux, Zeek, Suricata).
   - Normalized timestamp.
   - Process binary image & CLI execution arguments.
   - Raw unparsed log text with a one-click copy button.

---

### TOOL 3: MITRE ATT&CK Matrix Navigator
Interactive enterprise matrix mapped across 12 tactics.

#### How to Use:
1. Open the **MITRE ATT&CK** tab.
2. Techniques detected in your active incident queue are highlighted with glowing red `ALERT` badges.
3. Click any technique tile (e.g., `T1110` Brute Force, `T1059.001` PowerShell, `T1003.001` LSASS Dump, `T1490` Inhibit Recovery) to inspect:
   - Adversary behavior details.
   - Detection telemetry recommendations.
   - Correlated incident links.

---

### TOOL 4: AI Investigation Workbench & Copilot
The primary investigation suite running local edge inference.

#### How to Use:
1. Open the **AI Investigation** tab.
2. Select an incident from the left queue.
3. Select your model and target execution provider (Snapdragon NPU, GPU, or CPU).
4. Click **Execute Edge AI Investigation**:
   - The on-device model synthesizes:
     1. **Attack Hypothesis**: Concise deduction of adversary intentions.
     2. **Extracted IOCs Table**: Structured list of malicious IPs, hashes, and domains with recommended actions.
     3. **Correlation Narrative**: Step-by-step killchain analysis.
     4. **MITRE Mapping**: Evidence found for each technique.
     5. **Root Cause & Blast Radius**: Architectural vulnerability assessment.
     6. **Remediation Playbooks**: Executable bash/PowerShell scripts for endpoint isolation, firewall blocking, and credential revocation.
5. Click the **Analyst Copilot** tab to ask the edge model ad-hoc questions:
   - *"Generate an iptables command to block the external C2"*
   - *"Explain the obfuscated base64 PowerShell payload"*
   - *"What Windows Event IDs confirm if lateral movement occurred?"*

---

### TOOL 5: Event Normalizer & Ingestion Pipeline
Central engine for normalizing multi-source data.

#### How to Use:
1. Open the **Log Normalizer** tab.
2. Either click **Upload Real PC Log File**, click a preset, or paste raw log text.
3. Click **Preview Normalization** to inspect the parsed ECS/CIM record.
4. Click **Ingest & Run Detection** to feed the event into the detection engine and automatically trigger Sigma correlation rules.

---

### TOOL 6: SOC Incident Reports & DFIR Playbooks
Formal incident reporting suite.

#### How to Use:
1. Open the **SOC Reports** tab.
2. Select the incident from the dropdown.
3. Review the executive briefing: Risk Score (e.g., `82/100`), Severity (`HIGH`), MITRE TTPs, Forensic Evidence Table, and Remediation Scripts.
4. Export options:
   - **Export Markdown**: Downloads `CyberNexsus_Report_<ID>.md`.
   - **Export JSON**: Downloads full incident structure.
   - **Print Report**: Opens formatted browser print dialog for PDF generation.

---

### TOOL 7: Telegram SOC Alert Dispatcher
Real-time alerting forwarder for mobile/desktop Telegram notifications.

#### How to Configure with Real Telegram Bot:
1. Open Telegram and search for `@BotFather`.
2. Send `/newbot`, choose a name and username for your bot.
3. Copy the HTTP API token provided by BotFather (e.g. `7192837482:AAHdk28dks...`).
4. Create a Telegram channel or group for your SOC team, add your bot as an Administrator.
5. To get your Chat ID:
   - Forward a message from your channel to `@userinfobot`, or invite `@RawDataBot` to your group.
   - The Chat ID looks like `-1001928374928` (channels) or `98273645` (personal).
6. In CyberNexsus, click **Telegram** in the top navigation bar.
7. Paste your **Bot Token** and **Chat ID**.
8. Check **Include CVSS v3.1 details** and **Include MITRE tags**.
9. Click **Save Settings**.
10. Click **Dispatch Alert** to verify live message delivery.

*(Note: If no bot token is provided, CyberNexsus operates in high-fidelity local simulator mode).*

---

## 7. Production Deployment Guide

### Building the Production Bundle
```bash
npm run build
```
This produces an optimized production bundle in `/dist`.

### Running in Full-Stack Node.js Mode
For production headless servers:
```bash
npm run build
npm run preview
```

### Air-Gapped Network Verification
To verify that zero network packets egress to the public internet during local AI investigation:
```bash
# On Linux / Windows with Wireshark or tcpdump:
sudo tcpdump -i any host not 127.0.0.1 and not 192.168.0.0/16
```
You will observe **zero external HTTP/HTTPS calls** during model loading and AI investigations. All inference is processed locally on the Snapdragon NPU/GPU/CPU.

---

## 🛡️ License & Trademarks
CyberNexsus Edge AI SOC is distributed under the Apache-2.0 License. Designed for privacy-first enterprise security operations.
