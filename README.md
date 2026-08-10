# VirusTotal Tutorial Project: Basic Malware Analysis Using File Hashes

**Student:** Eleftheria Katsani  
**Tool:** VirusTotal  
**Project Type:** Cybersecurity tool tutorial and practical incident response scenario  
**Main Methods Demonstrated:** VirusTotal website, VirusTotal API, Python hash lookup, and basic static malware analysis  

---

## 1. Overview

This project demonstrates how **VirusTotal** can support a basic malware analysis of a suspicious file, using both the **VirusTotal website** and the **VirusTotal API with Python**. The project also compares the advantages and limitations of the web interface and the API while introducing basic threat intelligence concepts.

This project focuses on **basic static analysis**, which means reviewing information about a suspicious file without running it. No malware was executed during this project.

---

## 2. Project Objectives

By completing this tutorial, you will learn how to:

- Understand the purpose of VirusTotal.
- How VirusTotal can help identify possible malware types and behaviors.
- Navigate the VirusTotal web interface.
- Investigate files, URLs, domains, and IP addresses.
- Obtain and use a VirusTotal API key.
- Perform automated lookups using Python.
- Interpret VirusTotal scan results.
- Compare the VirusTotal website and API.
- Understand the strengths and limitations of VirusTotal.

---

## 5. What Is VirusTotal?

**VirusTotal** is an online threat intelligence and malware analysis platform. It allows analysts to search indicators such as:

- File hashes
- Files
- URLs
- Domains
- IP addresses

VirusTotal collects results from many antivirus engines and security vendors. This helps analysts compare multiple detections instead of relying on only one security product.

In this project, VirusTotal is used mainly for **file hash analysis**.

A file hash is like a digital fingerprint of a file. If two files have the same hash, they are usually the same file. This allows an analyst to check whether a suspicious file is already known without opening it.


## 3. How to Use VirusTotal to Help Solve Cybersecurity Problems

The project focuses on a safe and realistic incident response workflow:

1. A user receives a suspicious file.
2. The analyst does **not** open, run, or execute the file.
3. The analyst collects safe indicators of compromise, also called **IOCs**.
4. The file hash is checked with a Python script using the VirusTotal API.
5. The file hash is also reviewed manually using the VirusTotal website.
6. The analyst reviews detections, metadata, relationships, and indicators.
7. The analyst recommends response actions such as blocking, investigating, or escalating.

This scenario shows how analysts can investigate suspicious files safely before deciding whether deeper dynamic analysis is needed.

---

## 4. What Is Malware?

**Malware** is software or code designed to perform unwanted, unauthorized, or harmful actions on a computer system.

<img width="519" height="591" alt="Image" src="https://github.com/user-attachments/assets/b1c063f7-a615-4a75-b0da-dbf83ed9c948" />



Malware may be used to steal information, encrypt files, install backdoors, communicate with attacker-controlled servers, or download additional malware.

Understanding malware is important because analysts need to answer questions such as:

- Is this file known to be malicious?
- What type of malware might it be?
- What systems could be affected?
- What indicators should defenders search for?
- What response actions should be taken?

---

## 6. Why Use Static Analysis First?

**Static analysis** means analyzing a file without running it. 

This is usually the safest first step because malware can cause harm if executed. Static analysis helps an analyst collect evidence before deciding what to do next.

VirusTotal is one of the tools used in static-analysis because it can help answer important questions such as:

- Does the file match existing antivirus signatures?
- How many vendors detect it as malicious?
- What type of file is it?
- When was it first seen or last analyzed?
- When was it compiled, if that information is available?
- Are there signs of packing or obfuscation?
- Do imports suggest suspicious behavior?
- Are there host-based indicators?
- Are there network-based indicators?
- Are there MITRE ATT&CK mappings?

Static analysis is useful, but it does not show everything. If an analyst needs to observe what a file does while running, they would use **dynamic analysis** inside a controlled sandbox or virtual machine.

---

## 7. Static Analysis vs. Dynamic Analysis

| Analysis Type | What It Means | Examples | Safety Level |
|---|---|---|---|
| Static analysis | Reviews a file without running it | Hash lookup, metadata, imports, strings, vendor detections | Safer first step |
| Dynamic analysis | Runs the file in an isolated lab to observe behavior | Processes, files written, registry changes, network traffic | More detailed but riskier |

This project uses **static analysis** only.

---

## 8. Tools and Technologies Used

- Kali Linux virtual machine
- Python 3
- VirusTotal website
- VirusTotal API v3
- `requests`
- `python-dotenv`
- `rich`
- Visual Studio Code / Geany
- GitHub
- QuickTime screen recording for the backup demo video

---

## 9. Data Source and Safety

The hashes and indicators used in this project came from **TryHackMe Lab Material** and safe educational examples.

No private company files were uploaded.  
No malware was executed.  
The project uses hashes and screenshots for safe analysis.

Example safe test hash:

```text
44d88612fea8a8f36de82e1278abb02f
```

This is the EICAR test file hash. EICAR is used for safe antivirus testing and is not real malware.

---

## 10. Project Setup

### Create the project folder

```bash
mkdir VirusTotal-Tutorial-Project
cd VirusTotal-Tutorial-Project
```

### Create and activate a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install required packages

```bash
pip install requests python-dotenv rich
```

<img width="1470" height="956" alt="Image" src="https://github.com/user-attachments/assets/a883c440-4838-4a3f-802f-21b15cac4ed1" />

### Verify installed packages

```bash
pip show requests python-dotenv rich
```

### API key setup

The Python script requires a VirusTotal API key.

A `.env.example` file can show the expected format:

```text
VT_API_KEY=your_api_key_here
```

The real `.env` file should **not** be uploaded to GitHub because it contains a private API key.

---

## 11. Project Files

```text
VirusTotal/
│
├── README.md
├── threat_intelligence_tool.py
├── API_Demo.mov
├── API_screenshots/
│   └── screenshots from the Python/API demo
└── Website_screenshots/
    ├── 00_Upload Hash.png
    ├── 01_Detection_65 out of 67.png
    ├── 02_Hash & File Details.png
    ├── 03_Contacted Domains.png
    ├── 04_Network Based Indicators.png
    ├── 05_Graph Summary.png
    ├── 06_Mitre ATT&CK.png
    ├── 07_Malware Behavior.png
    ├── 08_Network Communication.png
    ├── 09_Files Activity.png
    ├── 10_Registry Keys.png
    ├── 11_Process and Service Actions.png
    └── 12_Highlighted Actions.png
```

The screenshots support the API demo, VirusTotal website analysis, and final analyst findings.

---

## 12. Workflow

```text
Suspicious file received
        |
        v
Do not open or execute the file
        |
        v
Collect safe IOCs, especially the file hash
        |
        v
Run the Python script using the VirusTotal API
        |
        v
Review the hash manually on the VirusTotal website
        |
        v
Review detections, metadata, relationships, behavior clues, and MITRE mappings
        |
        v
Recommend response actions
```

---

## 13. Using the VirusTotal Website for Hash Analysis

The **VirusTotal website** is the manual and visual part of this project. VirusTotal gives different options for checking suspicious items. An analyst can upload a file directly, search by a file hash, or check a URL, domain, or IP address.

For this project, I did **not** open or execute the suspicious file. Instead, I used a file hash as the safer option. The hash used in this project came from the sample indicators provided in the TryHackMe lab.

A file hash is like a fingerprint for a file. If an analyst has the actual suspicious file and needs to get its hash, they can use a tool such as **HashCalc**. HashCalc can generate hash values such as MD5, SHA-1, and SHA-256.

After collecting the hash, the analyst can paste it into the **Search** tab on VirusTotal. The website then shows the detection results, file details, relationships, behavior, and other indicators that help with malware triage.


### Website workflow followed

1. Open VirusTotal.
2. For a direct file submission, choose **File**, select the file, and upload it.
3. For a safer hash-based workflow, choose **Search** and paste the file hash.
4. Review the **Detection** tab for vendor results.
5. Review the **Details** tab for hashes, file type, size, names, and history.
6. Review the **Relations** tab for related domains, IP addresses, parent files, dropped files, and graph relationships.
7. Review the **Behavior** tab for sandbox activity such as processes, file activity, registry activity, and network communication.
8. Review **MITRE ATT&CK** mappings to describe the behavior using standard attacker techniques.
9. Document useful indicators and recommended response actions.

For this project, the safer approach was preferred: the suspicious file was not executed locally, and the hash was used for lookup.

### Website findings and screenshots

| Screenshot | What it shows | Why it matters |
|---|---|---|
| `00_Upload Hash.png` | The hash search process | Shows that the file was investigated safely by hash instead of being opened |
| `01_Detection_65 out of 67.png` | Vendor detection score and names | Shows that many engines recognized the file as suspicious or malicious |
| `02_Hash & File Details.png` | MD5, SHA-1, SHA-256, file type, size, names, and history | Helps identify and document the exact file |
| `03_Contacted Domains.png` | Domains related to the file | Helps identify network indicators to search in DNS, proxy, firewall, and SIEM logs |
| `04_Network Based Indicators.png` | Contacted IP addresses and related network artifacts | Helps defenders look for possible communication from infected systems |
| `05_Graph Summary.png` | Relationships between the file, dropped files, domains, IPs, and parents | Helps pivot from one hash to related indicators |
| `06_Mitre ATT&CK.png` | ATT&CK tactics and techniques | Helps explain possible attacker behavior using a standard framework |
| `07_Malware Behavior.png` | Behavior categories such as defense evasion, impact, persistence, file system, memory, and communication | Summarizes what sandbox or enrichment results observed |
| `08_Network Communication.png` | DNS, IP traffic, TLS/SNI, and JA3 information | Provides network-based indicators for detection and investigation |
| `09_Files Activity.png` | Files opened, written, deleted, modified, or dropped | Provides host-based indicators to search on endpoints |
| `10_Registry Keys.png` | Registry keys opened or set | Helps identify possible persistence, configuration, or Windows system changes |
| `11_Process and Service Actions.png` | Processes created, terminated, service activity, and shell commands | Shows how the file may execute commands or interact with Windows processes |
| `12_Highlighted Actions.png` | Notable calls such as `IsDebuggerPresent`, `Sleep`, `GetTickCount`, and PowerShell/cmd references | Highlights possible anti-analysis, delay, discovery, or scripting behavior |

### Important behavior notes

Some VirusTotal behavior results need analyst interpretation. A single item does not prove malware by itself, but several suspicious items together can strengthen the case.

- **Deleted files** may show cleanup activity, temporary files, or attempts to remove evidence.
- **Dropped files** may show additional payloads created by the original file.
- **Registry keys** may show configuration changes, persistence attempts, or file-association activity.
- **PowerShell, cmd.exe, and cscript.exe** are legitimate Windows tools, but attackers often abuse them for script execution.
- **`IsDebuggerPresent`** checks whether the program is being debugged. Malware may use this to detect analysis tools.
- **`Sleep`** pauses execution. Malware may delay activity to avoid short sandbox runs.
- **`GetTickCount`** checks system uptime and can be used for timing or sandbox-detection logic.
- **`GetSystemMetrics`** collects system information and can help malware recognize virtual or analysis environments.

### Import or Function | Possible Meaning |
|---|---|
| `CreateProcessA` | May start another process |
| `VirtualProtect` | May change memory permissions |
| `CreateFileA` / `WriteFile` | May create or modify files |
| `RegCreateKeyW` | May modify the Windows Registry |
| `CreateServiceA` / `StartServiceA` | May create or start a Windows service |
| `connect` / `WSAStartup` | May communicate over the network |

### Analyst interpretation

The website analysis showed that the hash had strong detection results and useful context beyond the detection score. The most useful findings were the file details, vendor detections, related indicators, behavior activity, and MITRE ATT&CK mappings.

Because this project uses a safe educational sample and hash-based analysis, the investigation demonstrates the workflow without executing malware locally.

---

## 14. VirusTotal API and Python Demo

The Python script demonstrates how VirusTotal lookups can be automated.

Instead of manually searching one hash at a time on the website, the API allows an analyst to build a repeatable workflow.

Example command:

```bash
python threat_intelligence_tool.py
```

Example hash input:

```text
5ff465afaabcbf015@d1a3ab2c2e74f3a4426467
```

Example output:

<img width="1108" height="798" alt="Image" src="https://github.com/user-attachments/assets/690b8e32-4f58-49c8-9d38-f66554747c30" />

The API script helps show:

- Automated hash lookup
- Detection count extraction
- Vendor detection names
- Basic file metadata
- Repeatable command-line analysis
- Structured results that can be saved or documented

---

## 15. Important Analysis Features

### Antivirus detections

Antivirus detections show whether security vendors already recognize the file. Many detections usually increase confidence that the file is malicious.

### File metadata

Metadata can include file name, type, size, hashes, first submission date, and last analysis date.

### Compile timestamp

The compile timestamp may show when the file was built. This can help with timeline analysis, but timestamps can be changed by attackers.

### Packing and obfuscation

Packing and obfuscation are techniques used to hide a program's real code or behavior. Indicators may include high entropy, suspicious sections, or limited visible imports.

### Imports

Imports are functions used by a program. They can give clues about behavior.

Imports are clues, not proof. They help the analyst form a hypothesis.

### Host-based indicators

Host-based indicators are artifacts that may appear on an infected computer, such as:

- Dropped files
- Suspicious file paths
- Registry keys
- New services
- Suspicious processes
- Persistence mechanisms

### Network-based indicators

Network-based indicators are signs of suspicious network activity, such as:

- Domains
- IP addresses
- URLs
- DNS lookups
- HTTP requests
- TLS certificates

These indicators can be searched in firewall logs, DNS logs, proxy logs, EDR tools, and SIEM platforms.

---

## 16. MITRE ATT&CK Mapping

VirusTotal and sandbox enrichment may show behaviors mapped to **MITRE ATT&CK**.

MITRE ATT&CK is a framework used to describe attacker behaviors. It helps analysts explain what malware or an attacker may be trying to do.

Example techniques seen in the project screenshots include:

| MITRE Technique | Meaning |
|---|---|
| `T1027 - Obfuscated Files or Information` | The file may try to hide its code or intent |
| `T1543 - Create or Modify System Process` | The file may attempt persistence or system process modification |
| `T1543.003 - Windows Service` | The file may create or modify a Windows service |
| `T1569 - System Services` | The file may abuse services for execution |
| `T1083 - File and Directory Discovery` | The file may search files or folders |
| `T1082 - System Information Discovery` | The file may collect system information |

These mappings should be treated as investigation clues. They should be validated with additional evidence.

---

## 17. Demo Video 

A short backup demo video is included in this repository:

Upload Demo

[Watch API_Demo.mov](https://github.com/user-attachments/assets/100207e4-20a9-4198-81c6-a204204be24b)
```

The video shows the Python script using the VirusTotal API to perform a safe file-hash lookup. This is the automated part of the project. It shows how an analyst can check a hash, receive a status code, and review detection results from the command line.

---

## 18. Analyst Findings

Based on the VirusTotal results, the suspicious file hash matched known detections from multiple vendors.

Key findings included:

- The file matched antivirus detections.
- VirusTotal provided file metadata and detection names.
- Static-analysis clues suggested suspicious behavior.
- Host-based and network-based indicators were available for further investigation.
- MITRE ATT&CK mappings helped describe possible attacker behavior.

The findings support treating the file as suspicious or malicious and escalating for further analysis if needed.

---

## 19. Recommended Response Actions

An analyst should:

- Do not open or execute the suspicious file.
- Preserve the file hash as evidence.
- Search endpoint, EDR, SIEM, DNS, proxy, and firewall logs for related indicators.
- Block confirmed malicious hashes or network indicators where appropriate.
- Investigate any system that interacted with the file.
- Escalate for dynamic analysis in a controlled sandbox if more behavior details are needed.
- Document findings in an incident ticket.

---

## 20. Strengths of VirusTotal

- Easy for beginners to use
- Supports file hashes, files, URLs, domains, and IP addresses
- Aggregates detections from many vendors
- Helps analysts avoid opening suspicious files
- Useful for quick triage
- Provides website and API access
- Supports pivoting between related indicators
- Can provide behavior, relationship, and MITRE information
- API supports automation and repeatable analysis

---

## 21. Limitations of VirusTotal

VirusTotal is useful, but it is not perfect.

### It depends on existing data

VirusTotal is strongest when the indicator is already known. New malware may not be detected yet because there may be no signature or previous submission.

### Low detections do not always mean safe

A file with few detections may still be malicious. It may be new, packed, obfuscated, or designed to avoid detection.

### Vendor labels may disagree

Different vendors may use different names for the same malware.

### Context is still required

VirusTotal results must be compared with other evidence, such as email reports, endpoint activity, DNS logs, firewall logs, proxy logs, and SIEM alerts.

### Public submission risk

Uploading sensitive files to VirusTotal may expose them to third parties. For this project, hashes and lab indicators were used instead of private files.

### Static analysis is incomplete

Static analysis gives useful clues, but dynamic analysis may be needed to observe runtime behavior.

### API limitations

The public API may have rate limits and may not expose every feature available in the web interface.

---

## 22. Website vs. API Comparison

| Feature | VirusTotal Website | VirusTotal API + Python |
|---|---|---|
| Best for | Manual review and screenshots | Automation and repeatable lookups |
| Easy for beginners | Yes | Requires basic Python/API knowledge |
| Good for presentations | Yes | Yes, especially for demos |
| Handles many hashes quickly | Limited | Better |
| Requires API key | Not for basic web search | Yes |
| Output format | Visual report | JSON / terminal output |
| Main use in this project | Deep file-hash review | Automated hash lookup |

---

## 23. Final Summary

This project shows how VirusTotal can be used as a safe first step in malware triage.

The main lesson is:

> Do not open or execute suspicious files. Collect the file hash and investigate it safely first.

The VirusTotal website helps analysts review detailed file information visually. The VirusTotal API and Python script show how the same type of lookup can be automated.

VirusTotal is not a replacement for full malware analysis, but it is a valuable starting point for investigation, documentation, and incident response.

---

## 24. References

- VirusTotal. Official Website and Documentation. Retrieved from https://www.virustotal.com/ 
- SentinelOne Labs. "Exploring the VirusTotal Dataset: An Analyst's Guide to Effective Threat Research."
- TryHackMe lab materials used for educational indicators. Retrived from https://tryhackme.com/room/intromalwareanalysis
- BFOR/BFORE 418/618. Malware Reverse Engineering course materials.
- Sikorski, Michael, and Andrew Honig. *Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software.*

