# Automated Threat Detection and Incident Triage using Splunk SOAR

## Demo Video
Watch the full project demo: [Click here](https://1drv.ms/v/c/ca84ccba0e93da2d/IQCOaduqe4PkSbiTWT0drfRfAS1BpGq1HGq-RDu2ThfD-TA?e=G4TGam)

## Overview
Engineered a hybrid-cloud SOC automation pipeline to achieve zero-touch incident triage. Simulated MITRE ATT&CK techniques on a local endpoint and routed the detections to a cloud-hosted SOAR platform. The automated playbook deduplicated alerts, dynamically provisioned analyst tickets in a local IR platform via reverse tunnels, ran threat intel enrichment, and dispatched email notifications in seconds.

## Environment
- Windows VM (10.0.2.10) - attack target with Sysmon, Wazuh Agent, and Atomic Red Team
- Ubuntu VM 1 (10.0.2.15) - primary SOC node with Wazuh Manager, TheHive, Cortex, and ngrok
- Ubuntu VM 2 (10.0.2.12) - dedicated threat intelligence node with MISP
- AWS EC2 Instance (Cloud) - Splunk SOAR Community Edition

## Architecture Diagram
The architecture utilizes a "Cloud-to-Ground" reverse tunnel to securely route REST API payloads from the public AWS cloud directly into the locally hosted private NAT network.

```mermaid
graph LR
    subgraph "Local On-Premise Network (Home Lab)"
        
        subgraph "Windows 10 Target VM"
            ART[Atomic Red Team] -.->|Simulates Attacks| Sysmon[Sysmon]
            Sysmon -->|Generates Event Logs| WAgent[Wazuh Agent]
        end

        subgraph "Ubuntu VM 1 (Primary SOC: 10.0.2.15)"
            WAgent -->|Forwards Telemetry| WManager[Wazuh Manager]
            ngrok[ngrok Reverse Tunnel\nPort 9000] -->|Routes Traffic| TheHive[TheHive\nIncident Response]
            TheHive <-->|Internal API| Cortex[Cortex\nDFIR Analyzers]
        end

        subgraph "Ubuntu VM 2 (Threat Intel: 10.0.2.12)"
            MISP[MISP Platform]
            TheHive <-->|Export IOCs / Sync| MISP
        end
    end

    subgraph "AWS Public Cloud"
        SOAR[Splunk SOAR\nEC2 Instance]
        WManager -->|Custom Webhook\nJSON Payload| SOAR
        SOAR -->|REST API Request\nPlaybook Action| ngrok
    end

    classDef cloud fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000;
    classDef local fill:#e1f5fe,stroke:#01579b,stroke-width:2px,color:#000;
    classDef endpoint fill:#fce4ec,stroke:#880e4f,stroke-width:2px,color:#000;
    
    class SOAR cloud;
    class WManager,TheHive,Cortex,ngrok,MISP local;
    class ART,Sysmon,WAgent endpoint;
```
## Automated Pipeline + Attack Simulation

| Stage | Action | Tool | Result |
|---|---|---|---|
| Execution | T1053.005 / T1003.001 simulated | Atomic Red Team | Sysmon telemetry generated |
| Detection | Log correlation and alerting | Wazuh SIEM | Level 10+ High Severity Alert |
| Ingestion | JSON payload pushed via Webhook | Splunk SOAR + ngrok | Event container created in SOAR |
| Orchestration | Playbook logic evaluates duplicates | Splunk SOAR | Duplicate check passed |
| Response | Auto-create ticket & send email | TheHive + SMTP App | Case provisioned, Analyst emailed |
| Enrichment | Active observable analysis | Cortex + VirusTotal | Malicious hash (WannaCry) flagged |

## Key Results
- Bridged on-premise SOC tools with cloud-hosted automation using an `ngrok` reverse tunnel on port 9000.
- Engineered a Splunk SOAR playbook with conditional logic to query TheHive's API and deduplicate alerts before case creation.
- Reduced Tier-1 triage time from manual processing (minutes) to fully automated provisioning (seconds).
- Successfully detected and enriched T1053.005 (Scheduled Task Persistence) and identified signatures via Cortex.
- Exported confirmed IOCs directly to MISP, automatically mapping them to MITRE ATT&CK Galaxy tags.

## Tools Used
Splunk SOAR, Wazuh (SIEM/XDR), TheHive (Incident Management), Cortex (DFIR), MISP (Threat Intelligence Platform), Sysmon, Atomic Red Team, ngrok, AWS EC2, VirtualBox

## Files in This Repo
- [Capstone Project Report](Incident_Triage.pdf)
- [Wazuh Custom Integration Script](scripts/)
- [Screenshots](images/)

## Screenshots
- Splunk SOAR Playbook Canvas
![SOAR Playbook](images/16_Playbook.png)
- Auto-Created TheHive Case
![TheHive Case](images/21_Auto_Created_Case.png)
- Cortex Analyzer Identification
![Cortex Results](images/29_Results_Cortex_analyzer.png)
- Automated Analyst Email Notification
![SMTP Alert](images/27_Email_Notification.png)
