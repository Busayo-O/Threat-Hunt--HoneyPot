# Building the incident Report

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  **Post-Incident Activity**

This was the final phase of the Cyber Defense project. I pulled together everything from the earlier phases, including the exported logs, my notes, and the before-and-after investigation packages. I then used AI to produce a professional incident report and a forensic comparison of the VM, and polished both into a portfolio-ready PDF.

**Where this fit in the incident response life cycle**

By the end of the project, I had worked through every stage:

1. **Preparation:** I onboarded the VM, set up logging, and wrote detections.
2. **Detection and analysis:** I spotted the breach and confirmed it was a true positive.
3. **Containment, eradication, and recovery:** I isolated the VM, cleaned up the database, restored the data, and hardened the VM.
4. **Post-incident activity:** I wrote the report, which served as a post-mortem of the incident.

---

## Steps Taken

### 1: Exported the logs for the incident window
(A)   I set the time window in Advanced hunting, using the two timestamps I had recorded(i.e Time when Virtual Machine was Vulnerable;  "2026-11-17T19:14:14.7056265Z" and time when the Virtual Machine was isolated; "2026-11-21T14:56:09.1638924Z").
   
**Query used to locate events:**

```kql

let StartTime = todatetime("<time made vulnerable>");
let EndTime = todatetime("<time isolated>");
```

(B) I adjusted the helper queries from Phase 6, replacing each query's time filter with where TimeGenerated between (StartTime .. EndTime) and verifying the device name. The MySQL queries used the full VM name(CORP-NA02-FE456BU), and the MDE tables used the truncated name(CORP-NA02-FE456). Exported each table as csv. Note: the MySQL queries use the full VM name, and the MDE tables use the truncated name.


(C) I exported each table as CSV:
    - MySQL authentication
    - MySQL queries
    - DeviceLogonEvents
    - DeviceProcessEvents
    - DeviceRegistryEvents, DeviceNetworkEvents, and DeviceFileEvents, as relevant to what happened in my environment
    
Because each table has different columns, I adjusted the project line for each one. For DeviceProcessEvents, I included columns such as FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountName, and DeviceName.

### MySQL Authentication Table

**Query used to locate events:**

```kql

let StartTime = todatetime("2026-11-17T19:14:14.7056265Z");
let EndTime = todatetime("2026-11-21T14:56:09.1638924Z");
// SQL Server
let MyDevice = "corp-na02-fe456bu";
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;
MySQLAudit_CL
| where TimeGenerated between (StartTime .. EndTime)
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend RawData = replace_string(RawData, "\t", " ")
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```
<img width="1212" alt="image" src="https://i.imgur.com/5rCzW2S.png">

---

### MySQL Queries

**Query used to locate events:**

```kql

let StartTime = todatetime("2026-11-17T19:14:14.7056265Z");
let EndTime = todatetime("2026-11-21T14:56:09.1638924Z");
// SQL Server
let MyDevice = "corp-na02-fe456bu";
MySQLAudit_CL
| where TimeGenerated between (StartTime .. EndTime)
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| extend ActionType = "Query"
| extend Query = split(RawData, "Query")[1]
| project TimeGenerated, DeviceName, ActionType, Query, RawData
| order by TimeGenerated desc
```
<img width="1212" alt="image" src="https://i.imgur.com/fZ744Jn.png">

---

### DeviceLogonEvents

**Query used to locate events:**

```kql

let StartTime = todatetime("2026-11-17T19:14:14.7056265Z");
let EndTime = todatetime("2026-11-21T14:56:09.1638924Z");
// SQL Server
let MyDevice = "corp-na02-fe456";
DeviceLogonEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```
<img width="1212" alt="image" src="https://i.imgur.com/74mkPoH.png">

----

### DeviceProcessEvents

**Query used to locate events:**

```kql

let StartTime = todatetime("2026-11-17T19:14:14.7056265Z");
let EndTime = todatetime("2026-11-21T14:56:09.1638924Z");
// SQL Server
let MyDevice = "corp-na02-fe456";
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName == MyDevice
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountName, DeviceName, ActionType
```
<img width="1212" alt="image" src="https://i.imgur.com/nflgWqE.png">

---

### DeviceRegistryEvents

**Query used to locate events:**

```kql

let StartTime = todatetime("2026-11-17T19:14:14.7056265Z");
let EndTime = todatetime("2026-11-21T14:56:09.1638924Z");
// SQL Server
let MyDevice = "corp-na02-fe456";
DeviceRegistryEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName == MyDevice
| project TimeGenerated, InitiatingProcessCommandLine, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName 
```

<img width="1212" alt="image" src="https://i.imgur.com/Vq7bWK5.png">

---

### DeviceNetworkEvents

**Query used to locate events:**

```kql

let StartTime = todatetime("2026-11-17T19:14:14.7056265Z");
let EndTime = todatetime("2026-11-21T14:56:09.1638924Z");
// SQL Server
let MyDevice = "corp-na02-fe456";
DeviceNetworkEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName == MyDevice
| project TimeGenerated, InitiatingProcessCommandLine, DeviceName, ActionType, InitiatingProcessFileName, RemoteIP, RemotePort
```
<img width="1212" alt="image" src="https://i.imgur.com/1c5NywH.png">

---

### DeviceFileEvents

**Query used to locate events:**

```kql

let StartTime = todatetime("2026-11-17T19:14:14.7056265Z");
let EndTime = todatetime("2026-11-21T14:56:09.1638924Z");
// SQL Server
let MyDevice = "corp-na02-fe456";
DeviceFileEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName == MyDevice
| project TimeGenerated, InitiatingProcessCommandLine, DeviceName, ActionType, InitiatingProcessFileName,FolderPath,FileName
```
<img width="1212" alt="image" src="https://i.imgur.com/BmnCBOB.png">

---

### 2. Generated the incident report with AI

- Uploaded the exported CSVs to an LLM along with the incident report prompt from the checklist.
- The prompt asks for:



**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

- 

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
