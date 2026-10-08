# Microsoft Sentinel SOC Lab

## Overview

This repository documents my hands-on Microsoft Sentinel SOC lab built to develop practical skills in Security Operations Center monitoring, KQL, detection engineering, and incident investigation.

The lab uses a physical Windows 11 endpoint as the security event source.

## Lab Architecture

Windows 11 PC
      |
      v
 Azure Arc
      |
      v
Azure Monitor Agent (AMA)
      |
      v
Data Collection Rule (DCR)
      |
      v
Log Analytics Workspace
      |
      v
Microsoft Sentinel
      |
      v
       KQL
      |
      v
Detection / Alert / Incident


## Technologies Used

* Microsoft Sentinel
* Azure Log Analytics
* Azure Arc
* Azure Monitor Agent (AMA)
* Data Collection Rules (DCR)
* Windows Security Event Logs
* Kusto Query Language (KQL)

## Project 1 — Windows Failed Login Detection

### Objective

Detect repeated failed Windows logon attempts using Windows Security Event ID 4625 and KQL.

### Security Event Used

**Event ID 4625 — An account failed to log on**

### Implementation

1. Connected the Windows 11 physical machine to Azure Arc.
2. Configured Azure Monitor Agent.
3. Created and deployed a Data Collection Rule.
4. Associated the DCR with the Windows machine.
5. Collected Windows Security event logs.
6. Verified that events were reaching the Log Analytics Workspace.
7. Generated controlled failed login attempts on the test machine.
8. Queried the collected events using KQL.
9. Confirmed that 5 failed login attempts were detected within the configured time window.

### KQL Detection

```kusto
Event
| where EventLog == "Security"
| where EventID == 4625
| summarize FailedAttempts = count() by Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

### Detection Logic

The query identifies a potential brute-force attack when:

**5 or more failed login attempts occur within 5 minutes.**

## Results

The lab successfully collected Windows Security events from the physical Windows 11 endpoint.

Observed events include:

* Event ID 4624 — Successful logon
* Event ID 4625 — Failed logon

The brute-force detection query successfully returned:

**FailedAttempts = 5**

## Skills Demonstrated

* Windows Security Event monitoring
* Azure Arc onboarding
* Azure Monitor Agent deployment
* Data Collection Rule configuration
* Log Analytics
* KQL querying
* Failed-login detection
* Basic detection engineering
* SOC monitoring concepts

## Future Improvements

* Convert the detection query into a Microsoft Sentinel Analytics Rule
* Generate Sentinel alerts and incidents
* Investigate incidents using entity information
* Add process creation monitoring using Event ID 4688
* Build additional KQL detections
* Implement automated response using Sentinel playbooks
* Add MITRE ATT&CK mapping to detections
