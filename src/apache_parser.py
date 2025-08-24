import re
import pandas as pd

# Path to Apache log
log_file = "../logs/apache.log"

# Regex for Apache log format
pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)

data = []

# Read log file line by line
with open(log_file, "r") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            data.append(match.groupdict())

# Convert to DataFrame
df = pd.DataFrame(data)

# Convert status to integer
df["status"] = df["status"].astype(int)

# Count access attempts
total_requests = len(df)

# Count errors (status 4xx and 5xx)
errors = df[df["status"] >= 400].shape[0]

# Count warnings (status 3xx, like redirects)
warnings = df[(df["status"] >= 300) & (df["status"] < 400)].shape[0]

print("Total Requests:", total_requests)
print("Errors (4xx/5xx):", errors)
print("Warnings (3xx):", warnings)

# Save parsed log to CSV
df.to_csv("../reports/apache_parsed.csv", index=False)
print("Parsed log saved to reports/apache_parsed.csv")
