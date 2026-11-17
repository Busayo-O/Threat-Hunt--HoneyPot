# Weakened both the Virtual Machine & Sequel Servers to be discovered over the internet, to enable people logging into it from the public internet.

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## Steps Taken

### 1a.  Administrator Account Configuration
- Created the "local Administrator account using Computer Management(compmgmt.msc).
- Confirmed membership in the Administrators group(Ensured it is located in the Administrative group).
- Configured a weak password for security testing.

<img width="1212" alt="image" src="https://i.imgur.com/WXfuTVI.png"> local adminstrator account was created and added to the local admin group


### 1b. Guest Account Configuration
- Enabled the guest account through Computer managemen.
- Configured the account with a blank password.
- Added the Guest account to the Users group.

 <img width="1212" alt="image" src="https://i.imgur.com/W2qApuj.png">weak password set for the guest account
 

 <img width="1212" alt="image" src="https://i.imgur.com/ffkr630.png">


### 1c. Remote Access Permissions
- Opened local Security Policy(secpol.msc), go to local policies, User Rights and select "Deny log on locally".
- Removed the Guest account from the policy deny log on through Remote Desktop services(it is ther by default).
- Configured the Remote Desktop logon policy to permit Guest access.
- Removed Guest from the Deny log on locally.
- Disabled the security policy preventing blank-password accounts to console logon only(Password Security Settings).
- Added the Guest account to the Remote Desktop Users group(Remote Desktop User Configuration).
- Executed gpupdate /force to apply the updated security policies(Group Policy Update).

<img width="1212" alt="image" src="https://i.imgur.com/ieKv8AE.png">

---

<img width="1216" height="777" alt="image" src="https://i.imgur.com/BlflRdZ.png" />

---

<img width="1212" alt="image" src="https://i.imgur.com/kGcg601.png">

---

<img width="1212" alt="image" src="https://i.imgur.com/2Csj6uC.png">

---

<img width="1212" alt="image" src="https://i.imgur.com/emTbson.png">

---

### 2a.  MySQL Account 
- Enabled MySQL authentication over the network.
- Configured a remote root account using "root" as the password.
- Granted the account full database privileges and applied the changes.

---

<img width="1212" alt="image" src="https://i.imgur.com/ybOQ9E1.png">

---

### 2b. Microsoft Defender Investigation
- Captured an investigation package using Microsoft Defender for post-breach analysis.

  ---
  
<img width="1212" alt="image" src="https://i.imgur.com/yF8Xb6z.png">

---

### 2c. Windows Firewall Configuration
- Disabled Windows Firewall to allow network traffic during the exercise

---

<img width="1212" alt="image" src="https://i.imgur.com/iilq36O.png">

---

### 2d. Network Security Group(NSG) Configuration
- Modified(weakened) the NSG rules to allow all inbound traffic and increase the Virtual Machine's network visibility

---

<img width="1212" alt="image" src="https://i.imgur.com/sRc8xf7.png">

---

### 2e. Exposure Time Documentation
- Recorded the exact time the virtual machine was exposed to the network to support breach timeline analysis

**Query used to locate event:**

```kql

let MyDevice = "corp-na02-fe456";
DeviceInfo
| where DeviceName == MyDevice
| order by TimeGenerated desc
```
<img width="1212" alt="image" src="https://i.imgur.com/Uu0Dqo3.png">

---

### 2f. Security Monitoring
- Confirmed that security detections and monitoring were enabled before leaving the Virtual Machine running.

 ```kql

let MyDevice = "CORP-NA02-FE456";
DeviceLogonEvents
| where DeviceName == MyDevice
| where LogonType == "Network"
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| order by TimeGenerated desc
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
``` 

<img width="1212" alt="image" src="https://i.imgur.com/f3UU5n5.png">

---

---

## Summary

The Windows Virtual machine was configured with intentionally weakened account security, modified permissions and reduced network security restrictions as part of a controlled cybersecurity environment. These changes were implemented to support vulnerability assessment, security testing and breach detection. Investigation data and exposure timestamps were also documented to facilitate post-breach analysis and evaluate the effectiveness of security monitoring and detection systems.



---
