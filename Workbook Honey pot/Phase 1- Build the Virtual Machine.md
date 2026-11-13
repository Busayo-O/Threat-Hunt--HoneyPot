## 1. To Build a Virtual Machine
To deploy a Windows 11 Virtual Machine within the Lognpacific CyberRange Azure environment using a dedicated Microsoft Azure Resource Group, configured secure administrator credentials and assigned a public IP address to enable remote connectivity.

  ## Actions Performed
* Signed in to the Microsoft Azure Portal and selected the LognPacific CyberRange Subscription.
* Created a dedicated Resource Group within the Lognpacific cyber Range subscription to organize and manage the lab resources.
* Navigated to Virtual Machines and selected Create → Azure Virtual Machine in the Resource Group.
* Configured the Virtual machine with the Virtual Machine Name, Operating system - Windows 11, Resource Group, Authentication - Username and password, Administrator Username & Password, Public Ip Address(Enabled) and Network Security- Azure Network SE curity Group (NSG).
* Configured a strong administrator username and password to protect the virtual machine against unauthorized access.
* Assigned a public IP address with the VM's network interface to enable remote connectivity.
* Configured the Network Security Group(NSG) to deny all inbound traffic originating from the internet, including RDP traffic on port 3389.
* Reviewed the virtual machine configuration and selected Review + Create, followed by Create to initiate deployment.
* Verified the deployment status and confirmed that the virtual machine had been provisioned successfully.

  ## Outcome
  A Windows 11 virtual machine is deployed within a dedicated Azure Resource Group with administrator authentication, an assigned public IP address, and controlled remote access.

<img width="400" src="https://i.imgur.com/ojri910.png" alt="Virtual Machine Deployment"/>


## 2. Denied all inbound traffic from the internet

<img width="400" src="https://i.imgur.com/J2jdJOP.png" alt="Deny all inbound traffic"/>


## 3. Onboarded the VM to Microsoft Defender for Endpoint (MDE), ensure it showed up in the DeviceInfo table

    ## Actions Performed

* Logged into the MDE Portal
* Browsed to the Onboarding Page: System → Settings --> Endpoints --> Device Management --> Onboarding
   Windows 10/11 MDE Package
   Windows Server 2019/2022 Package
   Linux (Ubuntu) Server (Python) Package
* Logged into the virtual machine and download and installed the MDE package, Right-click, run as Administrator.
* Logged back into the MDE Portal, ensured onboarding was successful: Assets --> Devices


```Kql
DeviceInfo

| where DeviceName startswith "CORP-NA02-"

DeviceProcessEvents
| where DeviceName startswith "CORP-NA02-"
```


<img width="400" src="https://i.imgur.com/Bf390Qm.png" alt="Virtual Machine onboarded for MDE"/>


















