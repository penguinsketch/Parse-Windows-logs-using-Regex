## 📝 Project Description
A lightweight security tool designed to parse raw text files from Windows Firewall logs. This proof of concept uses Regular Expressions (Regex) to automatically extract critical Indicators of Compromise (IOCs)—such as malicious IP addresses and target ports—making threat detection simple and easy to visualize.

## 📂 Repository Structure
- `Nmap_parser.py`: The main Python script containing the Regex search logic.
- `Nmap_parserV2.py`: The enhanced version with total connection traffic counting.
- `Nmap_parserV3.py`: The updated main Python automation script containing the field-parsing logic.
- `nmap_firewall_dump_log.txt`: A sample raw text log file exported from Windows Firewall during an active Nmap scan.

## 🚀 How to Run the Project
1. Clone or download this repository to your local machine.
2. Ensure you have Python 3 installed.
3. Place your raw log file in the same directory as the script.
4. Run the script via Command Prompt / Terminal:
   ```bash
   python -u "c:\YOUR_FILE_PATH\Nmap_parser.py"
   ```

---
# Windows Firewall Log Parser for Nmap Reconnaissance Detection (V1)

## 🔬 Regex Patterns Explanation

### 1. Attacker IP Address Extraction
- **Pattern:** `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
- **Purpose:** Identifies and extracts standard IPv4 addresses (e.g., `10.0.2.4`) from the text dump.

#### Breakdown:
- `\b` (Word Boundary): Prevents the pattern from matching unintended numbers embedded inside larger strings or hashes.
- `[0-9]{1,3}`: Matches any digit from 0 to 9 that is between 1 and 3 digits long (handling values from 0 to 255).
- `\.`: Matches a literal period (`.`). The backslash escapes the dot since a dot is a wildcard character in Regex.
- `(?:...){3}`: A non-capturing group that repeats the pattern of "1-3 digits followed by a period" exactly three times (matching `xxx.xxx.xxx.`).
- `[0-9]{1,3}`: Matches the final octet of the IP address, which consists of 1 to 3 digits without a trailing period.

### 2. Target Port Extraction (Destination Port)
- **Pattern:** `(?:ALLOW|DROP)\s+\w+\s+\S+\s+\S+\s+\d+\s+(\d+)`
- **Purpose:** Targets and extracts only the **Destination Ports** that Nmap scanned, while ignoring all other irrelevant numbers in the log file.

#### Breakdown:
- `(?:ALLOW|DROP)`: Anchors the search by matching the firewall actions—either `ALLOW` or `DROP`.
- `\s+`: Matches one or more spaces, used to transition between data columns in the log format.
- `\w+` and `\S+`: Skips past the protocol column (TCP/UDP) and the Source/Destination IP address columns by matching word and non-whitespace characters.
- `\d+`: Matches the Source Port numbers.
- `(\d+)` (Capturing Group): The core component of this project. The parentheses define a capturing group. It tells the Python script to specifically extract this final group of digits, which represents the targeted Destination Port.

Below is a live snapshot demonstrating the Python parser successfully processing the raw `nmap_firewall_dump_log.txt` file and extracting network artifacts using the Regex patterns defined above:

![Sample Output](output_nmap.png)

### 🔍 Key Findings from the Parse Result:
- **Attacker Profiling**: The Regex patterns effectively isolated multiple external source IP addresses involved in network probing activities, organizing them automatically into a clean list format.
- **Target Analysis**: A total of **11 distinct ports** were detected as actively targeted. Key security-sensitive ports discovered in the scan trace include:
  - `53` (DNS)
  - `135` (MSRPC Execution)
  - `139` (NetBIOS Session Service)
  - `445` (Microsoft-DS / SMB)
  - `443` (HTTPS Security)
- **Execution Metric**: The parsing logic successfully concluded by identifying all unique indicators and logging the exact count of probed ports at the terminal interface.

# Windows Firewall Log Parser for Nmap Reconnaissance Detection (V2)

Below is a live snapshot demonstrating the updated Python parser (V2) successfully processing the raw `nmap_firewall_dump_log.txt` file, providing a complete traffic overview, and logging all metrics in full English format:

![Sample Output V2](output_nmapV2.png)

### 🔍 Key Findings from the Parse Result (V2):
- **Traffic Overview**: The updated logic introduces comprehensive traffic tracking, calculating a total of **39 network log entries** across all firewall actions (DROP, ALLOW, and others) to provide better visibility into overall network volume.
- **Incident Attribution**: 
  - **Source IP (Attacker)**: Successfully isolated `10.0.2.8` as the sole source of the aggressive scanning activity.
  - **Destination IP (Impact)**: Confirmed that `10.0.2.5` was the primary target system receiving the scanning traffic.
- **Action-Based Segmentation**:
  - **Blocked Scans (DROP)**: Identified **7 distinct probing attempts** targeting critical Windows services (Ports 135, 139, 445) within a 1-second window.
  - **Allowed Services (ALLOW)**: Detected **6 active open ports** (`53`, `67`, `138`, `443`, `1900`, `5353`, `5355`) facilitating legitimate outbound and discovery traffic.
- **Execution Metric**: The parser successfully completed execution, verifying that all unique attacker profiles, impact zones, and port signatures were accurately categorized and sorted.

### 🧩 Regex Patterns Explanation (V2)

The V2 script optimizes the pattern matching logic to strictly focus on specific security events and capture structural relationships between network entities:

1. **Attacker & Target Pair Extraction**
   ```regex
   DROP\s+\w+\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})
   ```
   - `DROP\s+\w+`: Explicitly isolates entries where the firewall dropped traffic, followed by the protocol name (e.g., TCP/UDP). This filters out normal activity.
   - `([0-9]{1,3}\...)\s+([0-9]{1,3}\...)`: Uses two distinct capture groups to grab the **Source IP** and **Destination IP** simultaneously in a single line match. This guarantees exact mapping of who is attacking whom.

2. **Target Port Extraction**
   ```regex
   DROP\s+\w+\s+\S+\s+\S+\s+\d+\s+(\d+)
   ```
   - Skips past the action, protocol, source IP, destination IP, and source port fields to pinpoint the exact destination port.
   - `(\d+)`: Captures only the targeted service ports under attack, ignoring successful connections (`ALLOW`) to maintain a clean threat profile.
   
# Windows Firewall Log Parser for Nmap Reconnaissance Detection (V3)

A Python-based security tool designed for **SOC Tier 1 Analysts** to automatically parse, filter, and extract critical Indicators of Compromise (IoCs) from raw Microsoft Windows Firewall logs during an active internal network scan.

## 🚀 Key Features (V3 Updates)
- **Top-Level Timing Metrics**: Extracts the exact start and end timestamps of malicious scanning activities.
- **Unified Traffic Counter**: Tracks absolute connection volumes (`total scans`) across all firewall operations (DROP, ALLOW, DENY).
- **Target Profile Matrix**: Isolates malicious threat sources from internal victim destinations cleanly.
- **Defensive Auditing**: Extracts and tabulates all structural network service ports that are currently allowed (`ALLOW`) on the host system.

## 🖥️ Sample Execution & Output

Below is a live snapshot demonstrating the updated Python parser successfully processing a raw firewall log file and formatting the network artifacts:

![Sample Output V3](output_nmap(Final).png)

## 🔍 SOC Tier 1 Incident Triage & Analysis

This script delivers actionable metrics required for immediate ticket creation and classification in a Security Operations Center:

1. **Automation Verification**: The delta between the **First** and **Last Scan Timestamps** is exactly **1 second**. This compressed window proves high-speed automation tools (like an Nmap scan) are at play rather than human-speed manual probing.
2. **Threat Containment (Source IP)**: The IP address `10.0.2.8` is flagged as an active threat source attempting lateral movement. This endpoint should be isolated via the EDR or network switch immediately.
3. **Attack Surface Risk (Allow Ports)**: While the firewall successfully dropped multiple unauthorized connections, the output highlights critical system vectors—specifically **Port 445 (SMB)** and **Port 137 (NetBIOS)**—as actively allowed (`ALLOW`) on the host system. If the attacker targets these exposed services next, the risk of a successful breach or ransomware spread escalates significantly.
