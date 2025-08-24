# src/ssh_parser.py
import re
import csv

# Regex for failed login
FAILED_REGEX = re.compile(
    r"(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Regex for successful login
SUCCESS_REGEX = re.compile(
    r"(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Accepted password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def parse_ssh_log(input_file, output_file):
    results = []

    with open(input_file, "r") as f:
        for line in f:
            failed_match = FAILED_REGEX.search(line)
            success_match = SUCCESS_REGEX.search(line)

            if failed_match:
                results.append({
                    "date": failed_match.group("date"),
                    "status": "FAILED",
                    "user": failed_match.group("user"),
                    "ip": failed_match.group("ip")
                })

            elif success_match:
                results.append({
                    "date": success_match.group("date"),
                    "status": "SUCCESS",
                    "user": success_match.group("user"),
                    "ip": success_match.group("ip")
                })

    # Save to CSV
    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["date", "status", "user", "ip"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"✅ Parsing complete. Results saved to {output_file}")

if __name__ == "__main__":
    parse_ssh_log("logs/ssh.log", "reports/ssh_parsed.csv")
