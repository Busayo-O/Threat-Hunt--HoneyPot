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
-You are a SOC analyst writing an incident report for an incident. Produce a concise report (not a padded one) covering the full
incident response lifecycle. Use only what the data supports; flag gaps as "Not
determined from available logs" rather than guessing.

DATA SOURCES POTENTIALLY AVAILABLE (See attached, MS Defender Advanced Hunting + MySQL audit). For example:
- DeviceLogonEvents      (interactive/remote logons, account context)
- DeviceProcessEvents    (process execution, command lines, parent/child)
- DeviceRegistryEvents   (persistence, config changes)
- DeviceNetworkEvents    (outbound C2, exfil destinations)
- DeviceFileEvents       (file creation/deletion/encryption activity)
- MySQLAudit_CL_Auth.csv         (DB auth w/ source IPs)
- MySQLAuth_CL_Query.csv (DB query activity DROP/RENAME/SELECT)
- NTANetAnalytics        (network flow/traffic analytics)

Discovered IOCs. For example:
- BTC address: bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99
- Contact email: ak+28t2@onionmail.org
- Reference URL: hxxps://2no[.]co/2mysql
- DATAID: 28T2
- Any IP addresses

REPORT STRUCTURE:
1. Executive Summary — 3-4 sentences, plain language.
2. Incident Details — detection date/time, reporter, classification (type + severity),
   affected systems/assets.
3. Impact Assessment — data CIA effects, scope, business impact.
4. Indicators of Compromise — table the IOCs above plus any found in logs.
5. Timeline — chronological, initial access → DB compromise → ransom note → detection.
   Cite the source table for each entry.
6. Root Cause / Attack Vector — how access was gained; mark unknowns explicitly.
7. Response Actions — containment, eradication, recovery taken or recommended.
8. Evidence — list relevant log queries/artifacts referenced.
9. Lessons Learned / Recommendations — 4-6 concrete, prioritized items.

For each section, suggest the specific KQL hunt(s) against the tables above that an
analyst would run to populate it (e.g., MySQLAudit_CLC filtered for DROP/RENAME
statements around the incident window). Keep KQL realistic and minimal. Leave spaces for the human analyst to paste images of returned logs


### Step 3: Generate the forensic comparison with AI

In a separate chat, upload both investigation packages, pre-breach and post-breach, with the DFIR prompt from the checklist. The AI acts as a digital forensics analyst:

It identifies the baseline and the compromised package.

It compares standard MDE package artifacts, such as processes, autoruns, scheduled tasks, users, event logs, SMB sessions, and network data.

For each artifact, it classifies findings as added, removed, changed, or unchanged.

It assesses each finding and flags indicators of compromise

You are a DFIR analyst. You have been given two or more Microsoft Defender for
Endpoint (MDE) live-response investigation packages collected from the same host at
different times. Your job is to determine whether the host shows signs of compromise
by comparing the packages — without assuming any particular incident type.

STEP 1 — IDENTIFY THE PACKAGES
Locate the provided MDE package archives (names will vary). Determine the collection
order using internal timestamps (one will be pre-breach capture, post-breach capture), embedded collection metadata, or filenames if
informative. Treat the earliest package as the baseline and later ones as the
comparison set. State explicitly which package you are treating as the baseline and why.

STEP 2 — COMPARE ACROSS STANDARD MDE PACKAGE ARTIFACTS, INCLUDING:
- Autoruns / persistence (registry Run keys, scheduled tasks, services, startup folders)
- Running processes and loaded modules
- Installed services and drivers
- Scheduled tasks
- Network connections and listening ports
- Local users and group membership (esp. new privileged accounts)
- Security/System/Application event logs (new or cleared entries)
- File system metadata / prefetch / recently created or modified executables
- Hosts file, DNS cache, firewall rules
- Browser/credential artifacts if present

FOR EACH ARTIFACT CATEGORY, REPORT:
- ADDED     — present later, absent in baseline
- REMOVED   — present in baseline, absent later (note: log clearing is itself a signal)
- CHANGED   — present in both but modified (note what changed)
- UNCHANGED — note briefly

STEP 3 — ASSESS
For anything ADDED, REMOVED, or CHANGED, classify it as:
  (a) benign/expected — normal OS, patching, or user activity, or
  (b) suspicious — and if so, map it to the likely ATT&CK tactic (initial access,
      execution, persistence, privilege escalation, defense evasion, credential
      access, discovery, lateral movement, collection, C2, exfiltration, impact)
      and cite the specific file/line in the package as evidence.

Do not assume a specific attack class (ransomware, data theft, etc.). Let the evidence
indicate what kind of activity, if any, occurred. If indicators point to a particular
incident type, say so and explain why; if they're ambiguous, say that too.

STEP 4 — DERIVE AND HUNT FOR IOCs
Build an IOC list from anything suspicious found in the later package(s) — IPs,
domains, file hashes, filenames, account names, scheduled task names, etc. Then grep
both/all packages for those indicators to confirm presence/absence in the baseline.

OUTPUT:
1. Baseline determination — which package, and the basis for that decision.
2. Summary verdict — compromise indicators found: yes / no / inconclusive, with a
   confidence level and one-line justification.
3. Table of notable deltas (category | item | change type | benign vs suspicious | evidence).
4. Prioritized list of the strongest compromise indicators, mapped to ATT&CK.
5. Probable incident type, if the evidence supports one (else "undetermined").
6. Gaps — anything that couldn't be compared due to missing/incomplete artifacts.

Be concise. Don't flag routine OS churn (temp files, log rotation, normal timestamp
updates) as suspicious. Prioritize deltas that materially change the compromise picture.


### Lessons Learned / Recommendations (prioritized)
- Remove RDP and MySQL from direct internet exposure; require VPN/bastion + IP allow-listing. (Highest — this was the entry path.)
- Enforce account lockout, MFA, and strong unique passwords for administrator and DB accounts; the brute-force succeeded against weak/guessable credentials.
- Lock down MySQL privileges: no root'@'%', no wildcard-host superusers; alert on CREATE USER/GRANT ALL/DROP DATABASE.
- Deploy real-time detection for mass DROP/ransom-note table creation and for SQL_NO_CACHE bulk reads (exfil signature).
- Verify offline, tested backups for all production databases with regular restore drills.
- Tune detection/alerting and IR runbook so this class of event is caught at brute-force stage, not post-destruction (current logs show no evidence of timely detection).


---

## Summary

A large-scale brute-force and password-spray attack. The Administrator account locked out many times. The firewall disabled. No confirmed signs of deeper compromise on the host itself. If the VM stays exposed longer, attackers may install crypto miners or cause other damage on the host.


---

## Response Taken

- The incident was contained by isolation, eradicated by undoing each Phase 5 weakness, and recovered from the Phase 2 backup.
- Containment: the post-breach investigation package was collected first, giving a before-and-after pair. The VM was then isolated in Defender at [analyst to fill: isolation timestamp].
- Eradication: the VM's own NSG allow-all inbound rule was deleted before release from isolation. The Administrator account was deleted, the guest account disabled, the firewall turned back on, remote MySQL access removed and the remote root account secured. The ransom database was cleared and a full malware scan was run.
- Recovery: the data was restored from the Phase 2 backup (a dummy database). Rebuilding the VM from scratch is the safer choice in a real incident.
- Recommended follow-up: confirm dbmaint_fca2c6@% no longer exists, rotate all database and Windows credentials, and review root@% grants.


---
