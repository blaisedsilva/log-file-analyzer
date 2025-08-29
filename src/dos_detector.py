import re
from collections import defaultdict
from datetime import datetime, timedelta

# === CONFIG ===
LOG_FILE = "logs/access.log"
THRESHOLD = 5        # Number of requests
TIME_WINDOW = 5      # Seconds

# Regex for Apache/Nginx style logs
log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\]')

def parse_time(timestr):
    """Parse log timestamp like 10/Oct/2000:13:55:36 -0700"""
    return datetime.strptime(timestr.split()[0], "%d/%b/%Y:%H:%M:%S")

def detect_dos():
    requests = defaultdict(list)  # {ip: [timestamps]}
    suspicious_ips = set()

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    ip = match.group(1)
                    timestamp = parse_time(match.group(2))
                    requests[ip].append(timestamp)
    except FileNotFoundError:
        print(f"Log file not found: {LOG_FILE}")
        return

    # Check for DoS activity
    for ip, times in requests.items():
        times.sort()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(seconds=TIME_WINDOW)
            count = sum(1 for t in times if window_start <= t <= window_end)
            if count >= THRESHOLD:
                suspicious_ips.add(ip)
                break

    if suspicious_ips:
        print("🚨 Possible DoS detected from the following IPs:")
        for ip in suspicious_ips:
            print(f" - {ip}")
    else:
        print("✅ No suspicious DoS activity detected.")

if __name__ == "__main__":
    detect_dos()
