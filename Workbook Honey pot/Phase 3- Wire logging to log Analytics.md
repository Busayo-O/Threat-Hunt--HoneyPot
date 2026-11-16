# Wire logging to log Analytics

# Steps
* Turned on the Virtual Machine
* Confirmed device telemetry is flowing to LAW-Cyber-Range(environment)-i.e to confirm it is logged to MDE
  
  **Query used to locate events:**

```kql
  DeviceInfo
| where DeviceName startswith "CORP-NA02-"
| order by TimeGenerated desc
```
<img width="1212" alt="image" src="https://i.imgur.com/qSvTPk8.png">

**Created a custom-text-log Data Collection Rule (DCR) that points the Azure monitoring agent to the MySQL log file, sending the log file to a custom table** 
  
   (i)  Where the logs will be coming from-- The Virtual Machine
  
  <img width="1212" alt="image" src="https://i.imgur.com/pWXqOwI.png">
  

   (ii) The actual logs to be collected using this variables:

- a) File pattern:		C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
- b) Table name:		MySQLAudit_CL
- c) Record delimiter:	TimeStamp
- d) Timestamps format:	ISO 8601
  
  <img width="1212" alt="image" src="https://i.imgur.com/8tXbUwz.png">

   (iii) Where logs were kept once collected

  <img width="1212" alt="image" src="https://i.imgur.com/3jyVwxU.png">

   (iv) "Azure Monitor Windows Agent" successfully installed on the Virtual Machine after successful creation of the DCR

  <img width="1212" alt="image" src="https://i.imgur.com/SKydllM.png">
  
  
(v) Verified ingestion query MySQLAudit_CL to confirm test connections and if queries appeared
 **Query used to locate events:**

```kql
  MySQLAudit_CL
| project TimeGenerated, RawData, _ResourceId
| where _ResourceId endswith "CORP-NA02-FE456BU"

```
<img width="1212" alt="image" src="https://i.imgur.com/z7vwQYq.png" />

  (v) Verify core device tables are populating.
 **Query used to locate events:**

```kql
  MySQLAudit_CL
| project TimeGenerated, RawData, _ResourceId
| where _ResourceId endswith "CORP-NA02-FE456BU"

```
<img width="1212" alt="image" src="https://i.imgur.com/ffpxISL.png">

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


## Summary



---
