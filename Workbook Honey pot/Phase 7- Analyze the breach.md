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

---

### 4. Activity on the VM after the first logon

From the first successful logon (administrator, 80.94.95.83, 2026-11-18T05:08:52ZUTC) onward, I queried four tables for corp-na02-fe456 and exported each as a CSV to my log folder.

I queried DeviceProcessEvents from the first successful logon (administrator from 80.94.95.83 at 2026-11-18T05:08:52Z) onward. There was no process activity under administrator. The only non-system account with activity was greenview, my own account. The compromise was carried out over the network through MySQL rather than on the host.

**Query used to locate events:**

```kql
let FirstSuccessfulLogonTime = datetime(2026-11-17T10:08:52Z);
let MyDevice = "corp-na02-fe456";
DeviceProcessEvents
| where Timestamp >= FirstSuccessfulLogonTime
| where AccountName == "administrator"
| where DeviceName startswith MyDevice
| project Timestamp, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://i.imgur.com/gfTFJBz.png">

---

### 4a. DeviceProcessEvents: 

- Projected the time, account name, file name, folder path, process command line, and initiating process command line. Sort by newest first and skim the folder paths and command lines for anything unusual.
- Filtering on AccountName == "administrator" is a useful starting point, because you never logged in as Administrator yourself. Any activity under that account is an attacker.
- Processes running as SYSTEM can still be attacker activity, such as a scheduled task that keeps recreating a backdoor account.
  
**Query used to locate events:**

```kql
let FirstSuccessfulLogonTime = datetime(2026-11-17T10:08:52Z);
let MyDevice = "corp-na02-fe456";
DeviceProcessEvents
| where Timestamp >= FirstSuccessfulLogonTime
| where DeviceName startswith MyDevice
| project Timestamp, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc 
```
<img width="1212" alt="image" src="https://i.imgur.com/IexLYUK.png">

---

### 4b. DeviceFileEvents: sort by folder path and look for unusual locations.

**Query used to locate events:**

```kql
let FirstSuccessfulLogonTime = datetime(2026-11-17T10:08:52Z);
let MyDevice = "corp-na02-fe456";
DeviceProcessEvents
| where Timestamp >= FirstSuccessfulLogonTime
| where DeviceName startswith MyDevice
| project Timestamp, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc 
```
<img width="1212" alt="image" src="https://i.imgur.com/lx27tOz.png">

---

### 5: AI-assisted analysis


---


---
