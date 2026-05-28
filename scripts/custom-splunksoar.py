#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# write to Wazuh integration log
logging.basicConfig(filename='/var/ossec/logs/integrations.log', 
                    level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('splunksoar-integration')

def main():
    if len(sys.argv) < 4:
        logger.error("Missing arguments from Wazuh. Exiting.")
        sys.exit(1)

    alert_file_location = sys.argv[1]
    soar_api_key = sys.argv[2]
    soar_hook_url = sys.argv[3]

    try:
        with open(alert_file_location, 'r') as alert_file:
            wazuh_alert = json.load(alert_file)
    except Exception as e:
        logger.error(f"Error reading the Wazuh alert file: {e}")
        sys.exit(1)

    rule_desc = wazuh_alert.get('rule', {}).get('description', 'Unknown Wazuh Alert')
    agent_name = wazuh_alert.get('agent', {}).get('name', 'Unknown Agent')
    wazuh_level = int(wazuh_alert.get('rule', {}).get('level', 0))
    
    if wazuh_level >= 10:
        soar_severity = "high"
    elif wazuh_level >= 5:
        soar_severity = "medium"
    else:
        soar_severity = "low"

    src_ip = wazuh_alert.get('data', {}).get('srcip', '')
    if not src_ip:
        src_ip = wazuh_alert.get('data', {}).get('winlog', {}).get('event_data', {}).get('SourceIp', 'No IP Found')

    description_text = "### Wazuh Alert Details\n\n"
    description_text += "**🚨 Extracted Observables:**\n"
    description_text += f"- **Compromised Hostname:** {agent_name}\n"
    description_text += f"- **Attacker IP:** {src_ip}\n\n"
    
    if 'timestamp' in wazuh_alert:
        description_text += f"**Timestamp:** {wazuh_alert.get('timestamp')}\n"

    if 'rule' in wazuh_alert:
        description_text += "\n**Rule Information:**\n"
        for k, v in wazuh_alert['rule'].items():
            description_text += f"- {k}: {str(v)}\n"

    if 'agent' in wazuh_alert:
        description_text += "\n**Agent Information:**\n"
        for k, v in wazuh_alert['agent'].items():
            description_text += f"- {k}: {str(v)}\n"

    soar_payload = {
        "name": f"Wazuh: {rule_desc}",
        "label": "events", 
        "severity": soar_severity,
        "source_data_identifier": wazuh_alert.get('id', 'unknown'),
        "artifacts": [
            {
                "name": f"Level {wazuh_level} - {rule_desc}", 
                "label": "event",
                "severity": soar_severity,
                "cef": {
                    "name": rule_desc,
                    "deviceHostname": agent_name,
                    "sourceAddress": src_ip,
                    "deviceSeverity": soar_severity,
                    "message": description_text 
                },
                "data": wazuh_alert
            }
        ]
    }

    headers = {
        'ph-auth-token': soar_api_key,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(soar_hook_url, headers=headers, json=soar_payload, verify=False)
        if response.status_code in [200, 201]:
            logger.info(f"Successfully ingested alert. ID: {response.json().get('id')}")
        else:
            logger.error(f"Splunk SOAR rejected the payload. Code: {response.status_code}")
    except Exception as e:
        logger.error(f"HTTP Request failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
