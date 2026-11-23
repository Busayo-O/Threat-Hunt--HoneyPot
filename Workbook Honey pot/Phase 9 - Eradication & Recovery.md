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

### Step 3: Turned the Windows Firewall back on
- Open Run on VM → wf.msc → Properties and set the firewall to On for the Domain, Private, and Public profiles.

---

<img width="1212" alt="image" src="https://i.imgur.com/n7gm2Vp.png">

---

### Step 4 : Blocked remote MySQL logins (Not to allow logon to the MySQL Server from the public internet)

- Opened C:\ProgramData\MySQL\MySQL Server 8.x\my.ini.
- Searched for the bind-address = 0.0.0.0 line and deleted it. This makes MySQL listen on all network interfaces, so it accepts connections from any IP address(local and remote). Without it, MySQL accepts only local connections and reject remote ones.

<img width="1212" alt="image" src="https://i.imgur.com/YqSrMJI.png">

---

- Saved the file.

### Step 5 : Secured the MySQL root accounts

- Connected in MySQL Workbench with the local root account. Changed the password to a strong one for the root account that logs in over the network.

**Query used to locate events:**

```sql

ALTER USER 'root'@'%' IDENTIFIED BY '<strong-password>';
```  

<img width="1212" alt="image" src="https://i.imgur.com/e0Ca97D.png">

---

### Step 6 : Restored the data by running the Script from Phase 2

- Searched for the ransomware databased table on MySQL Workbench.
  ```
 <img width="1212" alt="image" src="https://i.imgur.com/dT0WCJr.png">
 
---

- Removed the ransomware database table by dropping both the "Schema(database) & Table". 
  
  **Query used to locate events:**

```
sql

DROP SCHEMA recover_your_data;
```
<img width="1212" alt="image" src="https://i.imgur.com/CCcFQ9G.png">

---

- Restored the data by rerunning the Phase 2 population script(this was used to create the Schema, i.e the dummy database). Once it’s done, the tables are back, including the clear-text passwords

  <img width="1212" alt="image" src="https://i.imgur.com/v8bxmu7.png">

---

### Step 7 : Run a full malware scan using Windows Defender on the VM

Open Windows Security → Virus & threat protection and run a Full scan. Defender usually catches malware in real time, but running a full scan after a compromise is good practice.

---

<img width="1212" alt="image" src="https://i.imgur.com/dciniob.png">

---

## Summary

**Summary**

I closed the network before releasing the VM from isolation. I then reversed every weakness introduced earlier: I deleted the Administrator account, disabled the guest account, turned the firewall back on, removed remote MySQL access, and secured the remote root account. Finally, I cleared out the ransom database, restored the data from backup, and ran a full malware scan. In a real incident, rebuilding from scratch is often the safer choice. The final incident report comes next.

---



