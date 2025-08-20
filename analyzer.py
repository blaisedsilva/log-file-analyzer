import re
import pandas as pd
from pathlib import Path
import json
import matplotlib.pyplot as plt

# === File Paths ===
LOG_DIR = Path("logs")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

APACHE_LOG = LOG_DIR / "apache_access.log"
SSH_LOG = LOG_DIR / "ssh_auth.log"

# === Regex Patterns ===
apache_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

ssh_pattern = re.compile(
    r'(?P<month>\w+) +(?P<day>\d+) (?P<time>\S+) (?P<host>\S+) sshd\[\d+\]: (?P<message>.*)'
)

# === Parsing Functions ===
def parse_apache(log_file):
    data = []
    with open(log_file, "r") as f:
        for line in f:
            match = apache_pattern.match(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

def parse_ssh(log_file):
    data = []
    with open(log_file, "r") as f:
        for line in f:
            match = ssh_pattern.match(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

# === Detection Functions ===
def detect_apache_bruteforce(apache_df):
    brute = apache_df[apache_df['status'] == '401'].groupby('ip').size().reset_index(name='attempts')
    flagged = brute[brute['attempts'] >= 5]
    return flagged

def detect_ssh_bruteforce(ssh_df):
    brute = ssh_df[ssh_df['message'].str.contains("Failed password", na=False)]
    brute = brute.groupby('host').size().reset_index(name='attempts')
    flagged = brute[brute['attempts'] >= 5]
    return flagged

def detect_scanning(apache_df):
    scan = apache_df.groupby('ip')['endpoint'].nunique().reset_index(name='unique_paths')
    flagged = scan[scan['unique_paths'] >= 10]
    return flagged

def detect_dos(apache_df):
    dos = apache_df.groupby('ip').size().reset_index(name='req_count')
    flagged = dos[dos['req_count'] >= 100]
    return flagged

# === Visualization Function ===
def plot_bar(df, column, title, filename):
    if df.empty:
        print(f"No {title} detected to plot.")
        return
    plt.figure(figsize=(8,5))
    plt.bar(df[column[0]], df[column[1]], color='tomato')
    plt.title(title)
    plt.xlabel(column[0])
    plt.ylabel(column[1])
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(REPORT_DIR / filename)
    plt.close()
    print(f"📊 {title} chart saved as {filename}")

# === Main Analyzer ===
def main():
    print("\n🔎 Log File Analyzer Report\n" + "="*40)

    apache_df = parse_apache(APACHE_LOG)
    ssh_df = parse_ssh(SSH_LOG)

    print("\n✅ Logs Parsed Successfully!")
    print(f"- Apache entries: {len(apache_df)}")
    print(f"- SSH entries: {len(ssh_df)}")

    # Run detections
    apache_brute = detect_apache_bruteforce(apache_df)
    ssh_brute = detect_ssh_bruteforce(ssh_df)
    scanning = detect_scanning(apache_df)
    dos = detect_dos(apache_df)

    # Save reports
    apache_df.to_csv(REPORT_DIR / "apache_parsed.csv", index=False)
    ssh_df.to_csv(REPORT_DIR / "ssh_parsed.csv", index=False)
    apache_brute.to_csv(REPORT_DIR / "apache_bruteforce.csv", index=False)
    ssh_brute.to_csv(REPORT_DIR / "ssh_bruteforce.csv", index=False)
    scanning.to_csv(REPORT_DIR / "scanning.csv", index=False)
    dos.to_csv(REPORT_DIR / "dos.csv", index=False)

    report_summary = {
        "apache_bruteforce": apache_brute.to_dict(),
        "ssh_bruteforce": ssh_brute.to_dict(),
        "scanning": scanning.to_dict(),
        "dos": dos.to_dict()
    }
    with open(REPORT_DIR / "summary.json", "w") as f:
        json.dump(report_summary, f, indent=4)

    # Print summary
    print("\n🚨 Suspicious Activity Detected:")
    print(f"- Apache Brute Force Attempts: {len(apache_brute)}")
    print(f"- SSH Brute Force Attempts: {len(ssh_brute)}")
    print(f"- Scanning Attempts: {len(scanning)}")
    print(f"- Possible DoS Attempts: {len(dos)}")

    # Plot visualizations
    plot_bar(apache_brute, ['ip','attempts'], "Apache Brute Force Attempts", "apache_bruteforce.png")
    plot_bar(ssh_brute, ['host','attempts'], "SSH Brute Force Attempts", "ssh_bruteforce.png")
    plot_bar(scanning, ['ip','unique_paths'], "Scanning Attempts", "scanning.png")
    plot_bar(dos, ['ip','req_count'], "Possible DoS Attempts", "dos.png")

    print("\n📂 Detailed reports and charts saved in 'reports/' folder.")

if __name__ == "__main__":
    main()
