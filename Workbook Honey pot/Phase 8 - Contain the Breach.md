# Post-Breach Collection and Containment

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

In this phase, I moved into the containment stage of the incident response life cycle. I captured a post-breach investigation package, took an optional look around the compromised VM, and then isolated the VM in Defender so attackers could no longer interact with it. I also recorded the exact time of isolation for the event timeline.

Where this fits in the incident response life cycle. By this point, I had completed these stages:

- Preparation: Built the environment and wrote the detection rules and also weakened the environment(a controlled environment)
- Detection: Watched for the breach.
- Analysis: Confirmed the breach was a true positive.
---

## Steps Taken

### 1. Capturing the post-breach investigation package

- Confirmed the VM was running in the Azure portal, since collection fails if it's off.
- Found the device in Defender by going to Assets → Devices and searching for it by the truncated name(CORP-NA02-FE456).
- Collected the package by clicking the three dots → Collect investigation package and adding the comment "post-breach collection."
- After a few minutes, did a hard refresh, opened the three dots → Action center, downloaded the package and saved as a post-breach-investigation-package.
- This gave a before-and-after pair, which will be compared with AI when building the final report.

<img width="1212" alt="image" src="https://i.imgur.com/vHzQDh5.png">

---

### 2. Isolating the VM

- In the Defender Portal, the VM was Isolated.
- Added the comment "post-breach isolation," which appears in the device's history.
- Isolation took effect almost immediately. For example, the VM stopped responding to ping.
- Captured the exact time of isolation: 2026-11-21T14:56:09.1638924Z

**Query used to locate event:**

```kql

print now()

```
<img width="1212" alt="image" src="https://i.imgur.com/qMSadZx.png">

---

## Summary

I captured the post-breach investigation package before isolating the device, which gave me a matching before-and-after pair of forensic snapshots. I then isolated the device to contain the breach and recorded the exact isolation time. Eradication and recovery come next.
---




