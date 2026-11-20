# Monitoring Honeypot Activity and Detecting Security Breaches


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
  

##  Scenario

Following the successful exposure of the honeypot to the public internet, periodic monitoring was conducted using Microsoft Defender Advanced Hunting to identify potential attacker activity. Three predefined queries were entered to monitor incoming security events, verified that detection rules were functioning and identify signs of a possible security breach. This Phase focused on confirming attacker activity and detecting potential security incidents, providing a foundation for further investigation and detailed post-breach analysis.

---

## Steps Taken

### 1. MySQL login activity Monitoring

Executed the MySQL login activity query developed in Phase 4 using Microsoft Defender Advanced Hunting. The query was used to monitor and identify successful and failed login attempts, including associated usernames and source IP addresses. This helped track unauthorized access attempts, identify suspicious login patterns, and detect potential security breaches involving the MySQL server.

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
<img width="1212" alt="image" src="https://i.imgur.com/2mZYkDh.png">

---

### 2. Monitoring SQL Queries Executed on the MySQL Database

Executed the MySQL query monitoring search using Microsoft Defender Advanced Hunting to review SQL statements executed on the database following its exposure to the public internet. The investigation focused on identifying suspicious database activities, including unauthorized queries, modifications, and attempts to delete database schemas or entire databases. This monitoring helped assess potential database tampering and identify activities requring further investigation during the post-breach analysis phase

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
<img width="1212" alt="image" src="https://i.imgur.com/cqe9uYO.png">

---

### 3. Monitoring Virtual Machine (VM) Login Activity

Executed a VM login activity query using Microsoft Defender Advanced Hunting to examine DeviceLogonEvents recorded after the Virtual machine's security settings were weakened. The query focused on monitoring login attempts involving the Administrator and Guest accounts, which were intentionally configured with weak security settings for the environment. The account filter was also adjusted to allow broader monitoring of login attempts, and the results were organized to display the most recent activities first. This investigation helped monitor potential unauthorized access attempts, identify suspicious login patterns, and support further security analysis of the virtual machine.

**Query used to locate events:**

```kql
// Virtual Machine Logons
let MyDevice = "corp-na02-fe456"; // MDE Truncates/cuts off the device name
let ServerVulnerableDateTime = todatetime("2026-06-25T00:45:27.1820312Z");
DeviceLogonEvents
| where TimeGenerated > ServerVulnerableDateTime
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType

```
<img width="1212" alt="image" src="https://i.imgur.com/iGLuLcu.png">
---

## Summary


---


