import re
import os

def extract_nmap_iocs(log_file_path):
    # Check if the log file exists before processing
    if not os.path.exists(log_file_path):
        print(f"[❌] Error: The file was not found in the system. -> {log_file_path}")
        return

    try:
        source_ips = set()
        dest_ips = set()
        allowed_ports = set()
        scan_timestamps = []
        total_all_entries = 0

        # Process log file line by line
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if line.startswith("#") or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 8:
                    continue
                
                total_all_entries += 1
                
                log_date = parts[0]
                log_time = parts[1]
                action = parts[2]
                src_ip = parts[4]
                dst_ip = parts[5]
                dst_port = parts[7]

                # Track scanning artifacts and capture their specific timestamps
                if action in ["DROP", "DENY"]:
                    source_ips.add(src_ip)
                    dest_ips.add(dst_ip)
                    scan_timestamps.append(f"{log_date} {log_time}")
                
                # Track allowed service ports
                elif action == "ALLOW":
                    if dst_port.isdigit():
                        allowed_ports.add(dst_port)

        # Format and sort metrics
        real_source_ip = list(source_ips) if source_ips else "No data found"
        real_dest_ip = list(dest_ips) if dest_ips else "No data found"
        sorted_allowed_ports = sorted(list(allowed_ports), key=int)

        # Determine start and end times of the scanning activity
        first_scan = scan_timestamps[0] if scan_timestamps else "N/A"
        last_scan = scan_timestamps[-1] if scan_timestamps else "N/A"

        # 📊 Output Display with Timestamps at the top
        print(f"First Scan Timestamp: {first_scan}")
        print(f"Last Scan Timestamp: {last_scan}")
        print(f"Source IP: {real_source_ip}")
        print(f"Destination IP: {real_dest_ip}")
        print(f"total scans: {total_all_entries}")
        print(f"Allow port: {sorted_allowed_ports}")
        print(f"total allow port: {len(sorted_allowed_ports)}")

    except Exception as e:
        print(f"[❌] A system error occurred: {str(e)}")

# --- Execution Section ---
target_file = r"C:\Users\venke\Downloads\nmap_firewall_dump_log.txt"
extract_nmap_iocs(target_file)
