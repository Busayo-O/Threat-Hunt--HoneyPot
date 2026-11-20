# Security Breach Investigation and Analysis 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint


##  Scenario

After the honeypot had been exposed to the internet long enough to collect meaningful attacker activity, I gathered the evidence and analyzed what happened. Using Microsoft Defender Advanced Hunting, I queried the honeypot VM’s telemetry, starting with logon events (DeviceLogonEvents), to establish who authenticated, from where, and when. I filtered out routine system accounts such as dwm-* and umfd-* to isolate meaningful logon activity. This included remote interactive (RDP) and network logons, which I correlated by account, source IP, and timestamp. From there, I pivoted to process and network telemetry to determine what the attacker did after gaining access. Outcomes in a honeypot environment vary widely, from data destruction or ransomware to cryptomining or minimal activity. This phase documents a repeatable process that can be adapted to different environments rather than a fixed set of steps.

### Setting Up Notes and Evidence Handling

Before analysis began, I set up a documentation workflow to keep the investigation organized and repeatable.

- Helper queries document: I made my own copy of the helper queries document from the project checklist. I used it to save every KQL query I ran and every AI analysis I received.
- Time of exposure: I recorded the weakened-at timestamp, 2026-11-17T19:14:14.7056265Z (UTC), at the top of the document, and used it as the baseline filter in every query.
- Log folder: I created a dedicated folder on my computer to store all CSV files exported from Defender.

---

## Steps Taken

### 1. MySQL authentication activity

Ran the Phase 4 MySQL login query against the honeypot VM, corp-na02-fe456, using the exposure timestamp 2026-11-17T19:14:14.7056265Z as the baseline filter. I exported the results from Defender using Export → Download as CSV and saved the file to my log folder as mysqlaudit-cl-auth.csv. I also saved the query and its output in my helper queries document so the analysis can be repeated.

**Query used to locate events:**

```kql
// SQL Server
let MyDevice = "corp-na02-fe456bu";
let MyTimeframe = todatetime("2026-11-17T19:14:14.7056265Z");
let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;
MySQLAudit_CL
| where TimeGenerated > MyTimeframe
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
<img width="1212" alt="image" src="https://i.imgur.com/dc6ZOKW.png">

---

### 2. MySQL queries

Ran the MySQL query-activity query against the honeypot VM, corp-na02-fe456, using the exposure timestamp 2026-11-17T19:14:14.7056265Z as the baseline filter. This showed what SQL activity occurred on the database after exposure. I exported the results from Defender using Export → Download as CSV and saved the file to my log folder as mysqlaudit-cl-queries.csv. I also saved the query and its output in my helper queries document.

A quick read showed that the database had been ransomed within about 72 hours. The attacker:

- Dropped Databases :
  - a)There are four DROP DATABASE statements, all at 16:40 on Nov 18: cr_corp_01, recover_your_data, sakila and world. In SQL, DROP means delete.
  - b) At 05:29–05:30 on Nov 18, before the drops, the attacker renamed every table with an x_ prefix. 


**Query used to locate event:**

```kql


// Filtering Queries
let MyDevice = "corp-na02-fe456bu"; // set your own device name
let ServerVulnerableDateTime = todatetime("2026-11-17T19:14:14.7056265Z");
MySQLAudit_CL
| where TimeGenerated > ServerVulnerableDateTime
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| extend ActionType = "Query"
| extend Query = split(RawData, "Query")[1]
| project TimeGenerated, DeviceName, ActionType, Query, RawData
| order by TimeGenerated desc

```
<img width="1212" alt="image" src="https://i.imgur.com/rOdzr5r.png">

---

### 3a. VM logon activity

Queried DeviceLogonEvents with the truncated device name and exposured timestamp. Filtered for successful logons to see who got in, then remove the filter and exported all the logon events.

**Query used to locate events:**

```kql
let MyDevice = "corp-na02-fe456";
let ServerVulnerableDateTime = datetime(2026-11-17T19:14:14.7056265Z);
DeviceLogonEvents
| where Timestamp > ServerVulnerableDateTime
| where DeviceName startswith MyDevice
//| where AccountName in~ ("administrator", "guest")
| project Timestamp, RemoteIP, AccountName, DeviceName, ActionType, LogonType
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://i.imgur.com/zi6cEvt.png">

---

### 3b. Noted the first successful logon time and store it in a variable for the queries that followed

**Query used to locate events:**

```kql
let MyDevice = "corp-na02-fe456";
let ExposureTime = datetime(2026-11-17T19:14:14.7056265Z);
let FirstSuccessfulLogonTime = toscalar(
    DeviceLogonEvents
    | where Timestamp > ExposureTime
    | where DeviceName startswith MyDevice
    | where ActionType == "LogonSuccess"
    | where AccountName !startswith "dwm-" and AccountName !startswith "umfd-"
    | summarize min(Timestamp)
);
DeviceProcessEvents
| where Timestamp >= FirstSuccessfulLogonTime
| where DeviceName startswith MyDevice
| project Timestamp, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp asc
```
<img width="1212" alt="image" src="https://i.imgur.com/1X4yOqy.png">



### 4. Activity on the VM after the first logon

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
