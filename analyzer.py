import re
import json
from pathlib import Path
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt

# ========================
# Paths
# ========================
LOG_DIR = Path("logs")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

APACHE_LOG = LOG_DIR / "apache_access.log"
SSH_LOG = LOG_DIR / "ssh_auth.log"

# ========================
# Regex
# ========================
apache_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

ssh_pattern = re.compile(
    r'(?P<month>\w+) +(?P<day>\d+) (?P<time>\S+) (?P<host>\S+) sshd\[\d+\]: (?P<message>.+)'
)

ip_in_msg = re.compile(r'from (\d{1,3}(?:\.\d{1,3}){3})')

# ========================
# Parsers
# ========================
def parse_apache(log_file: Path) -> pd.DataFrame:
    rows = []
    if not log_file.exists():
        return pd.DataFrame()
    with open(log_file, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = apache_pattern.match(line)
            if not m:
                continue
            d = m.groupdict()
            # convert types
            try:
                d["status"] = int(d["status"])
            except Exception:
                d["status"] = None
            try:
                d["size"] = int(d["size"])
            except Exception:
                d["size"] = None
            # parse timestamp to datetime (drop timezone)
            # e.g. "12/Mar/2025:19:15:01 +0000" -> take first token
            ts = (d.get("time") or "").split()[0]
            try:
                d["dt"] = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            except Exception:
                d["dt"] = None
            rows.append(d)
    df = pd.DataFrame(rows)
    return df


def parse_ssh(log_file: Path) -> pd.DataFrame:
    rows = []
    if not log_file.exists():
        return pd.DataFrame()
    with open(log_file, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = ssh_pattern.match(line)
            if not m:
                continue
            d = m.groupdict()
            # Extract source IP from message
            ipm = ip_in_msg.search(d["message"])
            d["ip"] = ipm.group(1) if ipm else None
            rows.append(d)
    return pd.DataFrame(rows)

# ========================
# Detections
# ========================
def detect_apache_bruteforce(apache_df: pd.DataFrame, threshold: int = 5) -> pd.DataFrame:
    if apache_df.empty:
        return pd.DataFrame(columns=["ip", "attempts"])
    failed = apache_df[(apache_df["status"] == 401) & (apache_df["endpoint"].str.contains("/login", na=False))]
    counts = failed.groupby("ip").size().reset_index(name="attempts")
    return counts[counts["attempts"] >= threshold]


def detect_ssh_bruteforce(ssh_df: pd.DataFrame, threshold: int = 5) -> pd.DataFrame:
    if ssh_df.empty:
        return pd.DataFrame(columns=["ip", "attempts"])
    failed = ssh_df[ssh_df["message"].str.contains("Failed password", na=False)]
    counts = failed.groupby("ip").size().reset_index(name="attempts")
    return counts[counts["attempts"] >= threshold]


def detect_scanning(apache_df: pd.DataFrame, threshold: int = 10) -> pd.DataFrame:
    if apache_df.empty:
        return pd.DataFrame(columns=["ip", "unique_paths"])
    uniq = apache_df.groupby("ip")["endpoint"].nunique().reset_index(name="unique_paths")
    return uniq[uniq["unique_paths"] >= threshold]


def detect_dos(apache_df: pd.DataFrame, threshold: int = 100) -> pd.DataFrame:
    if apache_df.empty:
        return pd.DataFrame(columns=["ip", "req_count"])
    counts = apache_df.groupby("ip").size().reset_index(name="req_count")
    return counts[counts["req_count"] >= threshold]

# ========================
# Visualizations (Day 4)
# ========================
def plot_apache_bruteforce(df: pd.DataFrame, out: Path):
    if df.empty:
        print("No Apache Brute Force Attempts detected to plot.")
        return
    ax = df.set_index("ip")["attempts"].plot(kind="bar", figsize=(8, 4))
    ax.set_title("Apache Brute Force Attempts")
    ax.set_xlabel("IP")
    ax.set_ylabel("Attempts")
    plt.tight_layout()
    plt.savefig(out)
    plt.close()
    print(f"📊 Saved: {out.name}")


def plot_ssh_bruteforce(df: pd.DataFrame, out: Path):
    if df.empty:
        print("No SSH Brute Force Attempts detected to plot.")
        return
    ax = df.set_index("ip")["attempts"].plot(kind="bar", figsize=(8, 4))
    ax.set_title("SSH Brute Force Attempts")
    ax.set_xlabel("IP")
    ax.set_ylabel("Attempts")
    plt.tight_layout()
    plt.savefig(out)
    plt.close()
    print(f"📊 Saved: {out.name}")


def plot_top_ips(apache_df: pd.DataFrame, out: Path, top_n: int = 10):
    if apache_df.empty:
        print("No Apache data available to plot Top IPs.")
        return
    top = apache_df["ip"].value_counts().head(top_n)
    if top.empty:
        print("No IP counts to plot.")
        return
    ax = top.plot(kind="bar", figsize=(8, 4))
    ax.set_title(f"Top {min(top_n, len(top))} IPs by Requests")
    ax.set_xlabel("IP")
    ax.set_ylabel("Requests")
    plt.tight_layout()
    plt.savefig(out)
    plt.close()
    print(f"📊 Saved: {out.name}")


def plot_requests_over_time(apache_df: pd.DataFrame, out: Path, freq: str = "1Min"):
    if apache_df.empty:
        print("No Apache data available to plot Requests Over Time.")
        return
    df = apache_df.dropna(subset=["dt"]).copy()
    if df.empty:
        print("No valid timestamps to plot Requests Over Time.")
        return
    ts = df.set_index("dt").resample(freq).size()
    if ts.empty:
        print("No time-series data to plot.")
        return
    ax = ts.plot(figsize=(9, 4))
    ax.set_title(f"Requests Over Time ({freq} bins)")
    ax.set_xlabel("Time")
    ax.set_ylabel("Requests")
    plt.tight_layout()
    plt.savefig(out)
    plt.close()
    print(f"📈 Saved: {out.name}")

# ========================
# Main
# ========================
def main():
    print("\n🔎 Log File Analyzer Report")
    print("=" * 40)

    # Parse logs
    apache_df = parse_apache(APACHE_LOG)
    ssh_df = parse_ssh(SSH_LOG)

    print("\n✅ Logs Parsed Successfully!")
    print(f"- Apache entries: {len(apache_df)}")
    print(f"- SSH entries: {len(ssh_df)}")

    # Detections
    apache_brute = detect_apache_bruteforce(apache_df)
    ssh_brute = detect_ssh_bruteforce(ssh_df)
    scanning = detect_scanning(apache_df)
    dos = detect_dos(apache_df)

    print("\n🚨 Suspicious Activity Detected:")
    print(f"- Apache Brute Force Attempts: {len(apache_brute)}")
    print(f"- SSH Brute Force Attempts: {len(ssh_brute)}")
    print(f"- Scanning Attempts: {len(scanning)}")
    print(f"- Possible DoS Attempts: {len(dos)}")

    # Save parsed CSVs
    apache_df.to_csv(REPORT_DIR / "apache_parsed.csv", index=False)
    ssh_df.to_csv(REPORT_DIR / "ssh_parsed.csv", index=False)

    # Save detection CSVs
    apache_brute.to_csv(REPORT_DIR / "apache_bruteforce.csv", index=False)
    ssh_brute.to_csv(REPORT_DIR / "ssh_bruteforce.csv", index=False)
    scanning.to_csv(REPORT_DIR / "scanning.csv", index=False)
    dos.to_csv(REPORT_DIR / "dos.csv", index=False)

    # Save JSON summary
    summary = {
        "counts": {
            "apache_entries": int(len(apache_df)),
            "ssh_entries": int(len(ssh_df)),
        },
        "detections": {
            "apache_bruteforce": apache_brute.to_dict(orient="records"),
            "ssh_bruteforce": ssh_brute.to_dict(orient="records"),
            "scanning": scanning.to_dict(orient="records"),
            "dos": dos.to_dict(orient="records"),
        },
    }
    with open(REPORT_DIR / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Charts (existing)
    plot_apache_bruteforce(apache_brute, REPORT_DIR / "apache_bruteforce.png")
    plot_ssh_bruteforce(ssh_brute, REPORT_DIR / "ssh_bruteforce.png")

    # === NEW Day 4 charts ===
    plot_top_ips(apache_df, REPORT_DIR / "top_ips.png", top_n=10)
    plot_requests_over_time(apache_df, REPORT_DIR / "requests_over_time.png", freq="1Min")

    print("\n📂 Detailed reports and charts saved in 'reports/' folder.")


if __name__ == "__main__":
    main()
