import pandas as pd
import re
import matplotlib.pyplot as plt
from datetime import datetime

# -------- Apache Log Parser --------
def parse_apache_log(file_path):
    log_pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
    )
    logs = []
    with open(file_path, 'r') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                log = match.groupdict()
                # Convert timestamp
                log["time"] = datetime.strptime(log["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
                logs.append(log)
    return pd.DataFrame(logs)

# -------- SSH Auth Log Parser --------
def parse_ssh_log(file_path):
    log_pattern = re.compile(
        r'(?P<month>\w+) +(?P<day>\d+) (?P<time>\S+) (?P<host>\S+) sshd\[\d+\]: (?P<message>.+)'
    )
    logs = []
    with open(file_path, 'r') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                logs.append(match.groupdict())
    return pd.DataFrame(logs)

if __name__ == "__main__":
    # Load Apache logs
    apache_df = parse_apache_log("sample_logs/apache_access.log")
    print("Apache Logs:\n", apache_df.head())

    # Load SSH logs
    ssh_df = parse_ssh_log("sample_logs/ssh_auth.log")
    print("\nSSH Logs:\n", ssh_df.head())
