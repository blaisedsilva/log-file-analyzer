import pandas as pd

# ✅ Example suspicious IP list (you can expand this later or load from file/API)
blacklist_ips = {
    "192.168.1.100": "Brute-force attacker",
    "203.0.113.45": "Known malicious bot",
    "10.0.0.50": "Port scanner"
}

def check_blacklist(detected_ips):
    """
    Compare detected IPs with blacklist and return matches.
    """
    matches = []
    for ip in detected_ips:
        if ip in blacklist_ips:
            matches.append((ip, blacklist_ips[ip]))
    return matches


if __name__ == "__main__":
    # ✅ Example: pretend these are detected from logs
    detected_ips = ["192.168.1.100", "8.8.8.8", "10.0.0.50"]

    results = check_blacklist(detected_ips)

    if results:
        print("🚨 Blacklist matches found:")
        for ip, reason in results:
            print(f" - {ip}: {reason}")
    else:
        print("✅ No blacklist matches.")
