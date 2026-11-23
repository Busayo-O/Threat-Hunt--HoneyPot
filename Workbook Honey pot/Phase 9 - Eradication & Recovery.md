# Eradication & Recovery

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

This phase covered eradication and recovery from the NIST SP 800-61 incident response life cycle. The goal was to remove the attacker's access and restore the system to a normal, secure state, bringing back availability in CIA triad terms.

## Scope of the compromise

The environment was a virtual machine running MySQL Server, hosting databases that contained customer data. All of these were compromised. A database backup had been created in Phase 2 (a dummy database), which made recovery possible. For this project, I followed the clean-up-and-harden approach by undoing each weakness introduced in Phase 5.


## Two recovery approaches

- Rebuild (the safest option): To destroy the compromised VM entirely, build a new hardened VM, reinstall MySQL, and restore the data from backup. When there is no way to be fully certain the VM itself was not tampered with, rebuilding is the safest choice, and it would have been the preferred approach had a clean backup and the ability to destroy the VM been available.
- Clean up and harden: If there are no clear signs that the VM itself was compromised, or if rebuilding is not an option, the existing machine can be cleaned up. This means hardening the Network Security Group (NSG), the VM, and the MySQL installation, and then restoring the data from backup.

---

## Steps Taken

### 1. Closed the network

These steps was completed before releasing the VM from isolation, so that no one could reach it from the internet in the meantime.
- In the Azure portal, On the VM's Networking → Network settings.
- On the VM's own NSG, the allow-all inbound rule was deleted, with only the default rules remaining, internet traffic was blocked again.
- Turned on the VM, which had been off, and waited about 30 seconds.
- In Defender, I opened the device and selected the three dots to release the VM from isolation.

<img width="1212" alt="image" src="https://i.imgur.com/Y0LfJvx.png">

---

### 2. **Step 2: Clean up the Windows accounts**

 - Through compmgmt.msc on the VM` → Local Users and Groups → Users, and made the following changes:

- Deleted the `Administrator` account, which should not have existed in the first place.

  <img width="1212" alt="image" src="https://i.imgur.com/eMGeT0c.png">

  ---

- Removed the guest account from the two groups they were added during Phase 5.

 <img width="1212" alt="image" src="https://i.imgur.com/VqzrH2r.png">

 ---

 <img width="1212" alt="image" src="https://i.imgur.com/dbyLzE7.png">

 ---

 - Had the "Guest account" disabled.

 <img width="1212" alt="image" src="https://i.imgur.com/JQvgTbZ.png">

 ---

- Set a strong password on my own local account.

- With the guest account disabled and the Administrator account removed, the weakened security policies from Phase 5 no longer had any effect

### Step 3 : Blocked remote MySQL logins (Not to allow logon to the MySQL Server from the public internet)

- Opened C:\ProgramData\MySQL\MySQL Server 8.x\my.ini.
- Searched for the bind-address = 0.0.0.0 line and deleted it. This makes MySQL listen on all network interfaces, so it accepts connections from any IP address(local and remote). Without it, MySQL accepts only local connections and reject remote ones.

<img width="1212" alt="image" src="https://i.imgur.com/YqSrMJI.png">

---

- Saved the file.

### Step 4 : Secured the MySQL root accounts

- Connected in MySQL Workbench with the local root account. Changed the password to a strong one for the root account that logs in over the network.

**Query used to locate events:**

```sql

ALTER USER 'root'@'%' IDENTIFIED BY '<strong-password>';
```  

<img width="1212" alt="image" src="https://i.imgur.com/e0Ca97D.png">

---

  
### Step 5 : Restored the data by running the Script from Phase 2

- Searched for the ransomware databased table on MySQL Workbench.
  ```
 <img width="1212" alt="image" src="https://i.imgur.com/dT0WCJr.png">
 
---


- Removed the ransomware database table by dropping it. Dropping only the table leaves the schema behind, so drop the whole schema:

sql

DROP SCHEMA recover_your_data;





Restore the data. The instructor reran the Phase 2 population script. Click without highlighting anything, then click the lightning bolt.



Bonus practice: if you took a real backup in Phase 2, restore from that backup instead.

  <img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

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
