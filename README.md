# NetShield – Network Traffic & Web Security Analyzer

NetShield is a Python-based network security project designed to analyze PCAP network traffic and identify suspicious activity using custom detection logic.

The project was built to strengthen practical skills in networking, packet analysis, Python, Wireshark, and SOC-style security monitoring.

NetShield analyzes captured network traffic, applies five detection rules, generates text-based security reports, and can send the generated reports through Gmail using OAuth 2.0 authentication.

---

## Features

NetShield currently contains five network security detections:

### Detection 1 – Repeated Failed TCP Connections

Identifies repeated TCP SYN connection attempts that do not receive a corresponding SYN-ACK response.

Alert condition:

- 6 unique failed SYN attempts
- Within 5 seconds

Protocol:
- TCP
- IPv4

---

### Detection 2 – Repeated Incomplete QUIC Connections

Analyzes QUIC traffic and identifies repeated QUIC Initial connections that do not successfully progress to Handshake or server 1-RTT traffic.

Alert condition:

- 6 unique incomplete QUIC connections
- Within 5 seconds

Protocol:
- QUIC over UDP
- UDP port 443
- IPv4

---

### Detection 3 – High-Volume SSDP Burst

Detects unusually rapid SSDP traffic originating from the same IPv4 source.

Alert condition:

- 5 SSDP packets
- From the same source
- Within 1 second

Protocol:
- SSDP over UDP
- UDP port 1900
- IPv4

---

### Detection 4 – Cleartext Sensitive Data Exposure

Inspects unencrypted HTTP traffic for sensitive information transmitted in plaintext.

Examples of monitored keywords include:

- password
- username
- email
- PIN
- token
- API key

The detected credential values themselves are not written to the security report.

Protocol:
- HTTP over TCP
- TCP port 80
- IPv4

---

### Detection 5 – Suspicious DNS Subdomains

Analyzes DNS queries and identifies unusually long first DNS labels that may indicate suspicious encoded or tunneled DNS traffic.

Alert condition:

- First DNS label longer than 25 characters

Protocol:
- DNS over UDP
- UDP port 53

---

## Detection Workflow

NetShield follows the following workflow:

PCAP Traffic  
↓  
Python + Scapy Packet Analysis  
↓  
Detection Logic  
↓  
Suspicious Activity Identified  
↓  
Security Alert Generated  
↓  
Text Report Created  
↓  
Gmail Alert with Reports Attached

---

## Technologies Used

- Python
- Scapy
- Wireshark
- PCAP / PCAPNG analysis
- TCP/IP
- UDP
- DNS
- HTTP
- SSDP
- QUIC
- Gmail API
- OAuth 2.0
- Git
- GitHub

---

## Project Files

| File | Purpose |
|---|---|
| `detection_1_tcp.py` | Detects repeated failed TCP connections |
| `detection_1_tcp.txt` | Example TCP detection report |
| `detection_2_quic.py` | Detects repeated incomplete QUIC connections |
| `detection_2_quic.txt` | Example QUIC detection report |
| `detection_3_ssdp.py` | Detects high-volume SSDP bursts |
| `detection_3_ssdp.txt` | Example SSDP detection report |
| `detection_4_http.py` | Detects sensitive information sent over cleartext HTTP |
| `detection_4_http.txt` | Example HTTP detection report |
| `detection_5_dns.py` | Detects suspicious DNS labels |
| `detection_5_dns.txt` | Example DNS detection report |
| `gmail_auth.py` | Handles Gmail OAuth authorization |
| `gmail_send.py` | Sends NetShield reports through Gmail |
| `.gitignore` | Prevents PCAP and OAuth credential files from being committed |

---

## Alert Reports

Each detection produces a text-based security report containing information such as:

- Detection rule
- Alert status
- Detection threshold
- Detection window
- Protocol
- Network layer
- Relevant detection statistics

Example:

```text
NETSHIELD SECURITY ALERT

Detection Rule: Repeated Failed TCP Connections
Status: Suspicious activity detected

Unique Failed SYNs: 37669
Detection Window: 0.002217 seconds
Threshold: 6 failed SYNs within 5 seconds
Protocol: TCP
Network Layer: IPv4

