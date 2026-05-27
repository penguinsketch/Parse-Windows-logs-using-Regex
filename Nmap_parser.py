import re
import os

def extract_nmap_iocs(log_file_path):
    # ตรวจสอบว่ามีไฟล์ Log อยู่จริงไหมก่อนเริ่มรัน
    if not os.path.exists(log_file_path):
        print(f"[❌] Error: The file was not found in the system. -> {log_file_path}")
        print("Please check that the file name and folder location are correct.")
        return

    # Regex set for extracting raw messages from Windows Firewall Logs
    # 1. Regex for extracting the IPv4 Address of the Kali machine
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    
    # 2. Regex for capturing destination ports in raw logs
    # Capturing ports located after the ALLOW or DROP state of the firewall.
    port_pattern = r"(?:ALLOW|DROP)\s+\w+\s+\S+\s+\S+\s+\d+\s+(\d+)"

    print("=" * 60)
    print(f"🔬 [Analyzing Log File]: {log_file_path}")
    print("=" * 60)

    try:
        # Open and read raw log files (supports basic Windows encoding).
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            log_data = file.read()

        # Use the Regex to scan and find information in the file.
        all_ips = re.findall(ip_pattern, log_data)
        all_ports = re.findall(port_pattern, log_data)

        # Filter out duplicate data for easier viewing using the `set` function.
        unique_ips = set(all_ips)
        unique_ports = set(all_ports)

        # The results are summarized as IOCs.
        print("\n[🚨] Indicators of Compromise (IOCs) Detected:")
        print("-" * 60)
        
        # Displays the IP addresses of the scanner.
        print(f"👉 Attacker IPs : {list(unique_ips) if unique_ips else 'No information found. IP'}")
        
        # Show a list of ports that have been scanned into the system (sorted from lowest to highest).
        sorted_ports = sorted(list(unique_ports), key=int) if unique_ports else []
        print(f"👉 Target Ports : {sorted_ports if sorted_ports else 'No information found. Port'}")
        print("-" * 60)
        print(f"[✅] Scan complete! All relevant ports detected. {len(sorted_ports)} Port")

    except Exception as e:
        print(f"[❌] An error occurred in the system.: {str(e)}")

# --- Execution Section (Specifying the Correct File Path) ---
# Use the / or r symbol to prevent the blank \ character from being visible in Windows file paths.
target_file = r"C:\Users\venke\Downloads\nmap_firewall_dump_log.txt"
extract_nmap_iocs(target_file)
