
<img width="300" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>
# Threat Hunt Report: Unauthorized TOR Usage

## Table of Contents

- [Project Overview](#project-overview)
- [Platforms and Tools](#platforms-and-tools)
- [Scenario Description](#scenario-description)
- [Threat Hunt Steps Taken](#threat-hunt-steps-taken)
- [Chronological Event Timeline](#chronological-event-timeline)
- [MITRE ATT&CK Techniques Mapped](#mitre-att&ck-techniques-mapped)
- [Detection Gaps & Recommendations](#detection-gaps-&-recommendations)
- [Summary](#summary)
- [Response Taken](#response-taken)


## Project Overview

This project simulates a real-world **threat hunting engagement** focused on detecting unauthorized TOR browser usage within a corporate environment using Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL).

The project walks through the full detection and response lifecycle: identifying indicators of compromise (IoCs), querying telemetry for suspicious file, process, and network events, validating TOR browser execution, and documenting investigative findings in a clear, actionable report.

_**Inception State:**_ Management suspects potential TOR usage on the network but lacks evidence or confirmed IoCs.

_**Completion State:**_ Unauthorized TOR usage is confirmed through forensic analysis; a timeline of malicious activity is constructed; response actions are taken, including device isolation and escalation to management.

### Impact Summary
- **TOR usage confirmed** through correlated evidence across file, process, and network activity
- **6 key forensic artifacts identified%** including installer execution, browser launch, and outbound connections to known TOR ports/IPs
- **Suspicious file%** `tor-shopping-list.txt` found post-browsing session
- **Response executed:** Device was isolated and employee's manager was alerted 
- **Report documented** for security awareness, auditability, and policy reinforcement

---

## Platforms and Tools
- **OS:** Windows 10 Virtual Machine (Microsoft Azure)
- **EDR Platform:** Microsoft Defender for Endpoint (MDE)
- **Query Language:** Kusto Query Language (KQL)
- **Browser Detected:** Tor Browser

##  Scenario Description

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

- [Scenario Creation](https://github.com/malaya-m/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Threat Hunt Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "malaya-mde-test"
| where InitiatingProcessAccountName == "labmalaya"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-19T20:11:40.5750705Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="2378" height="1138" alt="threat hunt lab screenshot 1" src="https://github.com/user-attachments/assets/2517252c-fe90-4cb2-a317-009036645be5" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "malaya-mde-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="2878" height="870" alt="threat hunt lab screenshot 2" src="https://github.com/user-attachments/assets/c3ead645-dd9b-45db-aa35-ad2ebc800f8f" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "malaya-mde-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1417" height="751" alt="threat hunt lab screenshot 3" src="https://github.com/user-attachments/assets/89d65091-70f1-47a1-ab71-6b15c6ce3a1c" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "malaya-mde-test"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="2866" height="906" alt="threat hunt lab screenshot 4" src="https://github.com/user-attachments/assets/4bfae8c3-9470-4996-8245-1ce3ae705b4a" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-19T20:11:40.5750705Z`
- **Event:** The user "labmalaya" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labmalaya\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-19T20:14:39.0730011Z`
- **Event:** The user "labmalaya" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\labmalaya\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-19T20:15:44.4799651Z`
- **Event:** User "labmalaya" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labmalaya\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-07-19T20:16:25.7559734Z`
- **Event:** A network connection to IP `103.147.153.180` on port `9001` by user "labmalaya" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\labmalaya\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-07-19T20:15:59.8805962Z` - Connected to `185.246.128.157` on port `443`.
  - `2025-07-19T20:16:13.2667277Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labmalaya" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-19T20:32:37.6064424Z`
- **Event:** The user "labmalaya" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labmalaya\Desktop\tor-shopping-list.txt`

---

## MITRE ATT&CK Techniques Mapped



---
## Detection Gaps & Recommendations

### Detection Gaps
- TOR was installed using a silent switch (`/S`), which may evade basic user alerts.
- Executables were named similarly to benign programs (e.g., `firefox.exe`).
- Network detection required correlation with non-standard ports.

### Recommendations
- Implement custom MDE alerts for high-risk `.exe` in user download directories.
- Block known TOR ports (`9001`, `9050`, `9150`) at the firewall unless business need is documented.
- Monitor user profile folders for portable applications with anonymizing features.
- Create detection rules based on directory structure (e.g., `TorBrowser\Tor\tor.exe` path pattern).

---

## Summary

The user "labmalaya" on the "malaya-mde-test" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `malaya-mde-test` by the user `labmalaya`. The device was isolated, and the user's direct manager was notified.

---
