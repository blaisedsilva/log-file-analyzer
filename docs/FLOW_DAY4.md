
# Flow – Log File Analyzer

1. Parse Logs (Apache + SSH)
2. Detect Suspicious Activity (Brute Force, Scanning, DoS)
3. Generate Visualizations:
   - Top IPs
   - Requests over time
   - Suspicious activity charts
4. Export Reports:
   - CSV & JSON summaries
   - Charts as PNG
   - Markdown (future step: PDF)

## Results – Day 4

- Apache Entries: 13
- SSH Entries: 6

### Suspicious Activity
- Apache Brute Force Attempts: 1
- SSH Brute Force Attempts: 1
- Scanning Attempts: 0
- DoS Attempts: 0

### Charts Generated
- apache_bruteforce.png
- ssh_bruteforce.png
- top_ips.png
- requests_over_time.png

l results saved in `reports/` folder.

