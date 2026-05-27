import re
import os

def extract_nmap_iocs(log_file_path):
    # Check if the log file exists before processing
    if not os.path.exists(log_file_path):
        print(f"[❌] Error: The file was not found in the system. -> {log_file_path}")
        return

    print("=" * 65)
    print(f"[Analyzing Log File]: {log_file_path}")
    print("=" * 65)

    try:
        # Initialize data structures
        attackers = set()
        targets = set()
        
        # Action-specific counters and sets
        scan_count = 0      # Counts blocked scans (DROP)
        allowed_ports = set()
        
        # Total connection counter for all states (DROP, ALLOW, DENY, etc.)
        total_connections = 0

        # Read the log file line by line
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                # Skip header lines and empty lines
                if line.startswith("#") or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 8:
                    continue
                
                # Increment total counter for every valid log entry detected
                total_connections += 1
                
                # Field mapping based on Microsoft Windows Firewall Log structure
                action = parts[2]
                src_ip = parts[4]
                dst_ip = parts[5]
                dst_port = parts[7]

                # 1. Identify scanned/attacked connections (DROP)
                if action == "DROP":
                    attackers.add(src_ip)
                    targets.add(dst_ip)
                    scan_count += 1
                
                # 2. Identify allowed connections and active ports (ALLOW)
                elif action == "ALLOW":
                    # Filter and grab only numeric destination ports
                    if dst_port.isdigit():
                        allowed_ports.add(dst_port)

        # Sort the allowed ports in ascending order
        sorted_allowed_ports = sorted(list(allowed_ports), key=int)

        # Summary Output Display
        print(f"\n Total Log Entries (DROP + ALLOW + Others): {total_connections} times")
        print("-" * 65)
        
        print(" Summary of Attack and Scan Analysis (DROP):")
        print(f" Attacker IP(s)           : {list(attackers) if attackers else 'No data found'}")
        print(f" Target / Impact IP(s)    : {list(targets) if targets else 'No data found'}")
        print(f" Total Blocked Scans      : {scan_count} times")
        
        print("\nSummary of Active Open Ports (ALLOW):")
        print(f" Number of Allowed Ports  : {len(sorted_allowed_ports)} port(s)")
        print(f" List of Allowed Ports    : {sorted_allowed_ports if sorted_allowed_ports else 'No data found'}")
        print("-" * 65)
        print(" Analysis complete! All firewall log entries categorized successfully.")

    except Exception as e:
        print(f"[❌] A system error occurred: {str(e)}")

# --- Execution Section ---
target_file = r"C:\Users\venke\Downloads\nmap_firewall_dump_log.txt"
extract_nmap_iocs(target_file)