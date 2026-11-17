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

#


<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

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
