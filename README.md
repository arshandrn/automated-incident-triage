# Automated Threat Detection and Incident Triage using Splunk SOAR

## Demo Video
Watch the full project demo: [Click here](insert-your-link-here)

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
