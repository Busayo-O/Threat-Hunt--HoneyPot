# Threat-Hunt--Honey-Pot


# Project Overview: 

This project focused on understanding the architecture, deployment requirements, and security monitoring capabilities of a Microsoft Azure-based honeypot environment.
The honeypot is designed to simulate an exposed computer system that will attract unauthorized access attempts from external attackers.
The purpose of the project is to study how suspicious activities can be collected, monitored, analyzed, and investigated using cloud-based cybersecurity tools.

## Platforms and Languages Leveraged
- Microsoft Azure Virtual Machine
- Windows 11 Operating System
- Azure Network Security Group (NSG)
- MySQL Database
- Azure Monitor Agent
- Log Analytics Workspace
- Microsoft Defender for Endpoint
  
##  Project Objectives

The objectives of this project were to:

1. Understand the purpose and operation of a cybersecurity honeypot.
2. Review the architecture of an Azure-based honeypot environment.
3. Identify the major cloud resources required for deployment.
4. Understand how network traffic reaches the honeypot.
5. Examine the role of security monitoring and log collection.
6. Understand how Microsoft Defender for Endpoint supports endpoint detection.
7. Establish a foundation for future threat-hunting investigations.
8. Document the architecture and training activities in a GitHub repository.

###  What Is a Honeypot?

A honeypot is a deliberately deployed decoy system designed to attract suspicious or unauthorized activities.
It may resemble a legitimate computer, application, database, or network service.
The primary purpose of a honeypot is to observe attacker behavior rather than provide normal business services.
When an attacker interacts with the honeypot, the security monitoring environment potentially capture information such as:

- Source IP addresses
- Connection timestamps
- Targeted network ports
- Authentication attempts
- Failed login events
- Suspicious processes
- Unauthorized access attempts
- Potential malicious commands

---
These records are analyzed to identify patterns of malicious behavior.


## Why Honeypots Are Important?
Honeypots help cybersecurity analysts understand how attackers discover and target exposed systems.
They provide an opportunity to observe potentially malicious activities in a controlled environment without intentionally exposing critical production resources.
However, honeypots must be isolated and carefully monitored because attackers may attempt to misuse a compromised system.

## Architecture Components

 **Microsoft Azure**

Microsoft Azure is the cloud computing platform used to host the honeypot environment. Azure provides the infrastructure required to create virtual machines, configure networking, manage security controls, and collect system logs.

Role in the project:
- Hosted the honeypot virtual machine.
- Provided cloud networking capabilities.
- Supported security monitoring.
- Integrated with Microsoft security services.
- Provided centralized management of cloud resources.

**Windows 11 Virtual Machine**

The Windows 11 virtual machine represents the primary honeypot endpoint. It acts as a decoy computer system that can be monitored for suspicious activities. The virtual machine is an important component because many investigations focuses on activities that occurred within the endpoint.


Role in the project:

- Provided the operating system environment.
- Received permitted network connections.
- Generated operating system and security events.
- Supported endpoint monitoring.
- Provideed data for threat hunting.


**Azure Network Security Group (NSG)**

A Network Security Group is an Azure networking resource that controls inbound and outbound traffic using security rules.

NSG rules can permit or deny traffic based on parameters such as:

- Source IP address
- Destination IP address
- Source port
- Destination port
- Network protocol
- Rule priority

Role in the project:

The NSG determined which network connections can reach the honeypot. For example, a deliberately exposed service may receive unsolicited connection attempts from external systems. The interactions produced useful security telemetry.
An NSG should not be configured to allow unrestricted traffic without understanding the risks. Administrative access should remain restricted, and the honeypot should be isolated from production resources.
Outbound traffic should also be controlled to reduce the possibility of a compromised honeypot being used to attack other systems.

**MySQL Database**

MySQL is a relational database management system used to store and retrieve structured data.

Potential role in the project:

- Provided a database service for the lab.
- Supported database-related security observations.
- Generated connection and authentication logs.
- Provided additional data for investigation when logging is configured.

**Azure Monitor Agent**

Azure Monitor Agent is a monitoring agent used to collect configured telemetry from supported systems. Windows event logs and performance data can be collected according to Azure Data Collection Rules.

Role in the project:

- Collected selected operating system events.
- Supported centralized monitoring.
- Sent configured telemetry to supported Azure monitoring destinations.
- Helped make endpoint events available for investigation.

**Log Analytics Workspace**

A Log Analytics Workspace is a centralized location for storing and querying supported Azure Monitor log data. It allows security analysts to investigate collected telemetry using Kusto Query Language (KQL).

Role in the project:

- Stored collected security events.
- Supported log searches.
- Allowed event correlation.
- Helped identify suspicious activity.
- Provided a platform for threat-hunting queries.

**Microsoft Defender for Endpoint**

Microsoft Defender for Endpoint is an endpoint security platform that provides capabilities for detecting, investigating, and responding to endpoint threats.
Depending on licensing, onboarding, and configuration, it can provide endpoint alerts and detailed activity telemetry.

Role in the project:

- Monitored endpoint security activity.
- Detected certain suspicious behaviors.
- Provided investigation information.
- Supported endpoint threat hunting.
- Helped analysts investigate potentially malicious processes and activities.


## How the Honeypot Works

The following describes the intended security monitoring workflow.

## Step 1: An External System Attempts a Connection

An external computer attempts to communicate with the honeypot through the internet. The connection may be legitimate internet scanning, automated probing, or potentially malicious activity.

## Step 2: The Network Security Group Evaluates Traffic

The Azure NSG evaluates the connection against configured security rules. If the traffic is permitted, it may reach the honeypot VM. If the traffic is denied, the connection is blocked according to the applicable rule.

## Step 3: The Honeypot Generates Events

When an interaction reaches the VM, the operating system or an exposed application may generate events.

Examples include:

- Failed authentication attempts
- Successful logins
- Service connection activity
- Process execution
- Changes to security settings

## Step 4: Monitoring Components Collect Telemetry

Configured monitoring services collect relevant events from the environment. Azure Monitor Agent can collect selected Windows events. Microsoft Defender for Endpoint can independently collect and analyze endpoint security telemetry.

## Step 5: Security Logs Are Analyzed

Collected Azure Monitor data can be queried in Log Analytics. Defender telemetry can be investigated using the appropriate Microsoft Defender security interface.

## Step 6: Suspicious Activity Is Investigated

The analyst examines the available evidence to identify potentially malicious patterns. Examples include repeated login failures, unusual processes, and suspicious access attempts.

## Step 7: Findings Are Documented

The documentation records include:

- What happened
- When the activity occurred
- Which system was affected
- Which evidence supported the finding
- Why the behavior was suspicious
- What response or mitigation was recommended

This documentation forms part of the threat-hunting investigation.











