<div align="center">

<img src="assets/splunk-soc-banner.png" alt="Splunk Windows SOC Monitoring & Detection Lab" width="100%">

</div>



<div align="center">

<img src="https://img.shields.io/badge/Platform-Windows%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows 11">
<img src="https://img.shields.io/badge/SIEM-Splunk-FFB900?style=for-the-badge&logo=splunk&logoColor=black" alt="Splunk">
<img src="https://img.shields.io/badge/Language-SPL-000000?style=for-the-badge&logo=splunk&logoColor=white" alt="SPL">
<img src="https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell">
<img src="https://img.shields.io/badge/SOC-Investigation-111827?style=for-the-badge" alt="SOC Investigation">
<img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-EF4444?style=for-the-badge" alt="MITRE ATT&CK">

</div>


# Splunk Windows SOC Monitoring & Detection Lab

## Overview

This project demonstrates a Windows-based Security Operations Center (SOC) monitoring and detection workflow using **Splunk Enterprise**, **Splunk Universal Forwarder**, and **Windows Security Event Logs**.

The project focuses on:

* Windows security log collection
* SPL-based detection engineering
* Security alert creation
* Authentication investigation
* Account and security-group monitoring
* Process monitoring
* PowerShell parent-process analysis
* SOC dashboard development
* MITRE ATT&CK mapping
* Basic L1 SOC investigation and triage

All activities were performed in an **authorized personal cybersecurity laboratory environment**.

---

# 1. Lab Architecture

```text
Windows 11 Endpoint
        │
        │ Windows Security Events
        ▼
Splunk Universal Forwarder
        │
        │ TCP 9997
        ▼
Splunk Enterprise
        │
        ├── SPL Detection Searches
        ├── Scheduled Alerts
        ├── SOC Dashboard
        └── Incident Investigation
```

### Main Components

| Component                  | Purpose                           |
| -------------------------- | --------------------------------- |
| Windows 11                 | Monitored endpoint                |
| Splunk Universal Forwarder | Log collection and forwarding     |
| Splunk Enterprise          | SIEM, detection and investigation |
| Windows Security Log       | Primary telemetry source          |
| MITRE ATT&CK               | Behavioral technique mapping      |

---

# 2. Windows Security Log Collection

Windows Security Event Logs were configured for collection through the Splunk Universal Forwarder.

### Configuration

* **Index:** `windows`
* **Sourcetype:** `XmlWinEventLog:Security`
* **Log:** Windows Security
* **Event format:** XML

The Universal Forwarder connection to Splunk Enterprise was also verified.

### Evidence

**01 – Windows Security input configuration**

`evidence/01_Windows_Security_inputs.conf.png`

**02 – Universal Forwarder active connection**

`evidence/02_Splunk_Universal_Forwarder_Active_Forward.png`

**03 – Windows Security events in Splunk**

`evidence/03_Splunk_Windows_Security_Events.png`

---

# 3. Detection 1 – Multiple Failed Windows Logons

**Windows Event ID: 4625**

The first detection monitors repeated Windows authentication failures.

Relevant authentication fields were extracted and analyzed, including:

* Target username
* Source IP
* Logon type
* Status
* Failure reason

The detection identified **11 failed-logon events** during the observed lab activity.

### Evidence

`evidence/04_Splunk_4625_Failed_Logon_Detection.png`

### Investigation

A timeline search was used to identify bursts of failed authentication activity.

| Time      | Failed Events |
| --------- | ------------: |
| 16:13     |             4 |
| 16:27     |             3 |
| 16:38     |             4 |
| **Total** |        **11** |

### Timeline Evidence

`evidence/04.1_4625_Failed_Logon_Timeline.png`

The activity was reviewed using the username, source IP, logon type, status, and event timeline. The observed failures occurred in multiple bursts within the authorized lab environment.

**Disposition:** Closed – Lab Simulation

### MITRE ATT&CK

**T1110.001 – Password Guessing**

Repeated authentication failures can be relevant to password-guessing detection. The observed telemetry alone does not prove that a malicious attack occurred.

---

# 4. Detection 2 – New User Account Created

**Windows Event ID: 4720**

A controlled local account creation was performed in the lab to generate Windows Security telemetry.

The resulting event showed:

* **Target account:** `SplunkTestUser`
* **Subject user:** `prana`
* **Host:** `PRANAV`
* **Domain/security authority:** `PRANAV`

### Evidence

`evidence/05_Splunk_4720_New_User_Account_Detection.png`

### Investigation

Event ID 4720 was reviewed to identify the newly created account, the account that performed the action, and the affected host.

The event showed `SplunkTestUser` being created by `prana` on the local Windows system as part of authorized lab testing.

**Disposition:** Closed – Lab Simulation

### MITRE ATT&CK

**T1136.001 – Create Account: Local Account**

Local account creation can be monitored as a potential persistence-related behavior.

---

# 5. Detection 3 – Windows Security Group Modification

**Windows Event IDs: 4728 / 4732**

This detection monitors security-group membership modification events.

The observed events included:

* Event ID 4732
* Event ID 4728
* `Builtin\Users`
* Subject user: `prana`

The available event data did not identify a specific member account for every event. Therefore, the investigation does not claim an exact account was added where the relevant field was unavailable.

### Evidence

`evidence/06_Splunk_4728_4732_Group_Modification_Detection.png`

### Investigation

The group-modification events were reviewed using the group involved, initiating user, affected host, and available member information.

The observed activity was generated as part of authorized lab testing.

**Disposition:** Closed – Lab Simulation

### MITRE ATT&CK

**T1098.007 – Account Manipulation: Additional Local or Domain Groups**

Security-group membership changes can be monitored because unauthorized modifications may affect account access or privileges.

---

# 6. Detection 4 – PowerShell Parent-Process Activity

**Windows Event ID: 4688**

This detection identifies Windows process-creation events where PowerShell is the parent process.

The observed events showed:

* **User:** `prana`
* **Parent process:** `powershell.exe`
* **Child process:** `Notepad.exe`
* **Host:** `PRANAV`

### Evidence

`evidence/07_Splunk_PowerShell_Parent_Process_Detection.png`

### Investigation

The observed process relationship was:

```text
powershell.exe
      │
      ▼
Notepad.exe
```

The `CommandLine` field was empty in the observed events. Therefore, the investigation does **not** claim what command was typed into PowerShell.

The process activity was generated during authorized lab testing.

**Disposition:** Closed – Lab Simulation

### MITRE ATT&CK

**T1059.001 – PowerShell**

The observed PowerShell parent-process activity is mapped to the PowerShell sub-technique of Command and Scripting Interpreter.

---

# 7. Detection 5 – Windows Process Creation Detection

**Windows Event ID: 4688**

Windows Process Creation auditing was enabled to collect process-creation telemetry.

The detection extracts:

* User
* New process
* Parent process
* Command line
* Host

This provides basic process-lineage visibility for SOC investigation.

### Investigation

Event ID 4688 is general process-creation telemetry. A specific MITRE ATT&CK technique was not assigned to every process event because the appropriate technique depends on the actual process behavior and surrounding context.

The observed process activity was reviewed as part of the authorized lab environment.

**Disposition:** Closed – Lab Simulation

---

# 8. SOC Dashboard

A centralized Splunk SOC dashboard was created to provide an overview of the Windows security monitoring environment.

The dashboard includes:

* Failed Logons KPI
* New Accounts KPI
* Group Modifications KPI
* Process Events KPI
* Failed-logon visualization
* Group modification visualization
* Process creation visualization
* PowerShell parent-process activity
* Security event overview

### Evidence

`evidence/08_Windows_SOC_Security_Dashboard.png`

The dashboard provides a centralized view that can assist an analyst during initial alert triage.

---

# 9. Splunk Alerts

Five scheduled detections were created:

1. Multiple Failed Windows Logons
2. Splunk New User Account Created
3. Splunk Windows Security Group Modification
4. Windows Process Creation Detection
5. PowerShell Parent-Process Activity

The alerts were configured as scheduled searches using a **five-minute schedule** for the lab environment.

### Evidence

`evidence/09_Splunk_All_Detections_Alerts.png`

---

# 10. SOC Incident Investigation

The project follows a basic L1 SOC investigation workflow:

```text
Alert
  ↓
Identify Event
  ↓
Review Timestamp
  ↓
Identify User and Host
  ↓
Analyze Relevant Fields
  ↓
Correlate Related Events
  ↓
Determine Context
  ↓
Document Disposition
```

## Investigation Summary

| Detection                   | Event     | Key Finding                                        | Disposition             |
| --------------------------- | --------- | -------------------------------------------------- | ----------------------- |
| Multiple Failed Logons      | 4625      | 11 failed-logon events observed in multiple bursts | Closed – Lab Simulation |
| New User Account            | 4720      | `SplunkTestUser` created by `prana`                | Closed – Lab Simulation |
| Security Group Modification | 4728/4732 | Security-group modification events observed        | Closed – Lab Simulation |
| PowerShell Parent Process   | 4688      | PowerShell → Notepad process relationship observed | Closed – Lab Simulation |
| Windows Process Creation    | 4688      | Windows process-creation telemetry collected       | Closed – Lab Simulation |

The investigation demonstrates basic SOC analyst activities including:

* Alert review
* Event analysis
* Timeline analysis
* Event correlation
* Contextual assessment
* Incident disposition

---

# 11. MITRE ATT&CK Mapping

The observed lab behaviors were mapped to relevant MITRE ATT&CK techniques.

| Simulated Activity                  | Windows Event | Splunk Detection                    | MITRE ATT&CK                                                            |
| ----------------------------------- | ------------- | ----------------------------------- | ----------------------------------------------------------------------- |
| Repeated authentication failures    | 4625          | Multiple Failed Windows Logons      | **T1110.001 – Password Guessing**                                       |
| Local account creation              | 4720          | New User Account Created            | **T1136.001 – Create Account: Local Account**                           |
| Security-group modification         | 4728 / 4732   | Windows Security Group Modification | **T1098.007 – Account Manipulation: Additional Local or Domain Groups** |
| PowerShell launches another process | 4688          | PowerShell Parent-Process Activity  | **T1059.001 – PowerShell**                                              |
| Generic process creation            | 4688          | Windows Process Creation Detection  | **No direct technique assigned**                                        |

> MITRE ATT&CK mappings represent behavioral relationships between observed telemetry and ATT&CK techniques. They do not by themselves prove malicious activity.

---

# 12. Detection-to-Investigation Workflow

The completed workflow can be summarized as:

```text
Windows Activity
      ↓
Windows Security Event
      ↓
Splunk Collection
      ↓
SPL Detection
      ↓
Scheduled Alert
      ↓
SOC Investigation
      ↓
MITRE ATT&CK Mapping
      ↓
Incident Disposition
```

This demonstrates how raw Windows telemetry can be converted into actionable SOC detections and investigated using a SIEM workflow.

---

# 13. Evidence Files

The project evidence is organized in workflow order:

```text
evidence/
├── 01_Windows_Security_inputs.conf.png
├── 02_Splunk_Universal_Forwarder_Active_Forward.png
├── 03_Splunk_Windows_Security_Events.png
├── 04_Splunk_4625_Failed_Logon_Detection.png
├── 04.1_4625_Failed_Logon_Timeline.png
├── 05_Splunk_4720_New_User_Account_Detection.png
├── 06_Splunk_4728_4732_Group_Modification_Detection.png
├── 07_Splunk_PowerShell_Parent_Process_Detection.png
├── 08_Windows_SOC_Security_Dashboard.png
└── 09_Splunk_All_Detections_Alerts.png
```

**Total evidence images: 10**

No separate screenshots were created for the written SOC investigation or MITRE mapping because the existing detection screenshots provide the visual evidence required for the project.

---

# 14. Skills Demonstrated

### Splunk / SIEM

* Splunk data ingestion
* SPL query development
* Field extraction using `rex`
* Windows Security event analysis
* Event correlation
* Scheduled searches
* Alert creation
* Dashboard development

### Windows Security Monitoring

* Event ID 4625 analysis
* Event ID 4720 analysis
* Event IDs 4728/4732 analysis
* Event ID 4688 analysis
* Authentication monitoring
* Account monitoring
* Security-group monitoring
* Process lineage analysis

### SOC Operations

* Alert triage
* Log investigation
* Timeline analysis
* Event correlation
* Incident documentation
* Lab activity classification
* MITRE ATT&CK mapping
* Evidence organization

---

# 15. Key Learning Outcome

This project demonstrates a practical defensive SOC workflow:

```text
Collect → Detect → Alert → Investigate → Map → Document
```

The lab demonstrates how Windows Security telemetry can be collected in Splunk, converted into detection rules, monitored through scheduled alerts and dashboards, investigated using event context, and mapped to relevant MITRE ATT&CK techniques.

---

## Disclaimer

This project was conducted in an authorized personal cybersecurity laboratory for educational and defensive security training purposes.

The simulated activities were controlled and were not performed against unauthorized systems.

