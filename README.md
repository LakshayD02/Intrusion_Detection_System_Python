# Intrusion Detection System (IDS) Using Python and Scapy

The Intrusion Detection System (IDS) is designed to monitor network traffic for suspicious activities and potential threats. By analyzing the characteristics of packets flowing through the network, the IDS can identify abnormal patterns, such as unusually large packets or repetitive requests from a single source. Upon detecting such anomalies, the system can take preventive action, such as blocking the suspicious IP addresses.

# Key Features:

- Packet Monitoring:

The IDS uses Scapy, a powerful Python library for network packet manipulation and analysis, to capture and analyze network packets in real time.
The system processes packets as they traverse the network interface, enabling immediate detection of malicious or unusual behavior.

- Statistical Analysis:

The IDS maintains a record of packet sizes and counts to analyze network traffic statistics. This helps in identifying patterns that could indicate potential attacks or intrusions.
Packet sizes are stored in a list, allowing for historical analysis of packet characteristics.

- Anomaly Detection:

Large Packet Detection: The system flags packets larger than 1500 bytes as suspicious, as this may indicate attempts at data exfiltration or denial-of-service (DoS) attacks.
Repetitive Traffic Detection: If the same packet size is detected repeatedly (more than 100 times), the IDS considers it suspicious and may indicate a flood attack or a script generating continuous requests.

- Automated Response:

When suspicious activity is detected, the IDS can automatically block the offending IP address using Windows Firewall commands. This feature requires administrative privileges to execute.
The system logs all detected threats, including the time of detection and the nature of the anomaly, to a log file (ids_logs.log). This enables further analysis and review of security incidents.

- Logging:

The system logs various events, such as detected anomalies, to a log file with timestamps. This provides a history of network activities and potential threats for future analysis and reporting.
