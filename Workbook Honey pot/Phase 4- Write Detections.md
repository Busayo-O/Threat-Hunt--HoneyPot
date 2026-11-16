# Created Analytical Rules that detects when logged either into Virtual Machine or MySQL Server


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


##  Scenario

Creation of analytical rule in sentinel that will run a query every 10 minutes and then create an incident. For a record to be recorded, a login would have been initiated successfully into the VM.

## Steps Taken

### 1a. Setting up Analytical Rule with the name "Cyber-Defense-Final-CORP-NA02-FE456BU" in MDE and under the "Incident Navigation, select create analytical rule, Using the "Mitre Att&ck" - Brute force-passwords Guessing and Credential access. This will help create the alerts


<img width="1212" alt="image" src="https://i.imgur.com/rfFKTrC.png">


### 1b. **Query used to locate event:**

```

// Virtual Machine Logons
let MyDevice = "CORP-NA02-FE456BU"; // MDE Truncates/cuts off the device name
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```
<img width="1212" alt="image" src="https://i.imgur.com/EW0O8dl.png">

---


### 1c. **Analytic Query Successfully made

<img width="1212" alt="image" src="https://i.imgur.com/Up5rVBK.png">


### 2. created two different Sentinel Analytical Rules for successful logins on vms detection rules using 2 different queries - Analytics Rule to be named Cyber-Defense-Final-MySQL

This is when someone authenticates and logs into the MySQL Server


### 2a. Setting up an Analytical Rule

<img width="1212" alt="image" src="https://i.imgur.com/sCLeg2h.png">

### 2b. Query 1

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://i.imgur.com/EW0O8dl.png">

---

### 2c. Query 2

**Query used to locate event:**

```kql

// SQL Server - Failed Login → Successful Login Detection
let MyDevice = "<YOUR-DEVICE-NAME-HERE>";
let MyTimeframe = ago(7d);
let FailedConnections =
    MySQLAudit_CL
    | where TimeGenerated > MyTimeframe
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
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc

```
<img width="1212" alt="image" src="https://i.imgur.com/EW0O8dl.png">

---







