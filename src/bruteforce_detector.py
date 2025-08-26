# src/ssh_analysis.py
"""
SSH analysis + Brute-force detection (25 Aug)
Produces:
 - reports/ssh_analysis.csv         (detailed rows with flags)
 - reports/bruteforce.csv           (list of brute-force incidents)
 - reports/bruteforce_top_ips.png   (visual of top IP attackers)
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from datetime import timedelta

# Configurable thresholds
WINDOW_MINUTES = 5
THRESHOLD_ATTEMPTS = 5

# Optional: username-targeted threshold
USER_WINDOW_MINUTES = 10
USER_THRESHOLD = 8

# Paths (relative to project root)
REPORTS_DIR = "reports"
SSH_PARSED = os.path.join(REPORTS_DIR, "ssh_parsed.csv")       # original parsed file
SSH_ANALYSIS = os.path.join(REPORTS_DIR, "ssh_analysis.csv")   # enriched file (output)
BRUTEFORCE_CSV = os.path.join(REPORTS_DIR, "bruteforce.csv")
BRUTEFORCE_PLOT = os.path.join(REPORTS_DIR, "bruteforce_top_ips.png")

# ---------------------
# Step 0: Load CSV
# ---------------------
if not os.path.exists(SSH_PARSED):
    raise SystemExit(f"Missing input: {SSH_PARSED} -- run ssh_parser.py first")

df = pd.read_csv(SSH_PARSED)

# Normalize columns if needed
if 'is_failed' not in df.columns:
    df['is_failed'] = df['status'].astype(str).str.upper() == 'FAILED'
if 'is_success' not in df.columns:
    df['is_success'] = df['status'].astype(str).str.upper() == 'SUCCESS'

# Parse date (add year if needed)
# If dates already have year, this will still work
try:
    df['date'] = pd.to_datetime(df['date'])
except Exception:
    df['date'] = pd.to_datetime(df['date'] + ' 2025', format='%b %d %H:%M:%S %Y')

# Sort by time for sliding-window logic
df = df.sort_values('date').reset_index(drop=True)

# ---------------------
# Step 1: Sliding-window brute-force detection (per IP)
# We'll find windows where count of failed attempts >= THRESHOLD_ATTEMPTS
# ---------------------
ip_incidents = []  # list of dicts for bruteforce.csv

# Group failed attempts by IP and scan windows
failed_df = df[df['is_failed']].copy()

for ip, group in failed_df.groupby('ip'):
    times = group['date'].sort_values().reset_index(drop=True)
    # Two-pointer sliding window
    start = 0
    for end in range(len(times)):
        # Expand window until it's within WINDOW_MINUTES
        while times[end] - times[start] > pd.Timedelta(minutes=WINDOW_MINUTES):
            start += 1
        window_count = end - start + 1
        if window_count >= THRESHOLD_ATTEMPTS:
            # Record an incident: window start, end, count
            incident = {
                'ip': ip,
                'start_time': times[start],
                'end_time': times[end],
                'failed_attempts': window_count,
                'window_minutes': WINDOW_MINUTES,
                'note': f"{window_count} failed logins in {WINDOW_MINUTES} min"
            }
            ip_incidents.append(incident)
            # Move start forward to avoid duplicate overlapping windows reporting same cluster
            start = end + 1

# ---------------------
# Step 2: Username-targeted brute-force (optional)
# ---------------------
user_incidents = []
for user, group in failed_df.groupby('user'):
    times = group['date'].sort_values().reset_index(drop=True)
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > pd.Timedelta(minutes=USER_WINDOW_MINUTES):
            start += 1
        window_count = end - start + 1
        if window_count >= USER_THRESHOLD:
            incident = {
                'user': user,
                'start_time': times[start],
                'end_time': times[end],
                'failed_attempts': window_count,
                'window_minutes': USER_WINDOW_MINUTES,
                'note': f"{window_count} failed logins for user in {USER_WINDOW_MINUTES} min"
            }
            user_incidents.append(incident)
            start = end + 1

# ---------------------
# Step 3: Create bruteforce.csv
# ---------------------
bf_rows = []
for inc in ip_incidents:
    bf_rows.append({
        'type': 'ip',
        'ip': inc['ip'],
        'user': '',
        'start_time': inc['start_time'],
        'end_time': inc['end_time'],
        'failed_attempts': inc['failed_attempts'],
        'window_minutes': inc['window_minutes'],
        'note': inc['note']
    })
for inc in user_incidents:
    bf_rows.append({
        'type': 'user',
        'ip': '',
        'user': inc['user'],
        'start_time': inc['start_time'],
        'end_time': inc['end_time'],
        'failed_attempts': inc['failed_attempts'],
        'window_minutes': inc['window_minutes'],
        'note': inc['note']
    })

bf_df = pd.DataFrame(bf_rows)
if bf_df.empty:
    # create empty but structured file
    bf_df = pd.DataFrame(columns=['type','ip','user','start_time','end_time','failed_attempts','window_minutes','note'])

bf_df.to_csv(BRUTEFORCE_CSV, index=False)
print(f"✅ Brute-force incidents saved to {BRUTEFORCE_CSV} ({len(bf_df)} incidents)")

# ---------------------
# Step 4: Mark rows in main df that belong to an incident
# (add column 'bruteforce_ip' if IP had an incident; 'bruteforce_user' for user)
# ---------------------
ips_with_incident = set(bf_df[bf_df['type']=='ip']['ip'].dropna().unique())
users_with_incident = set(bf_df[bf_df['type']=='user']['user'].dropna().unique())

df['bruteforce_ip'] = df['ip'].isin(ips_with_incident)
df['bruteforce_user'] = df['user'].isin(users_with_incident)

# Save enriched analysis CSV
df.to_csv(SSH_ANALYSIS, index=False)
print(f"✅ Enriched SSH analysis saved to {SSH_ANALYSIS}")

# ---------------------
# Step 5: Visualization - top brute-force IPs
# ---------------------
if not bf_df[bf_df['type']=='ip'].empty:
    top_ips = bf_df[bf_df['type']=='ip'].groupby('ip')['failed_attempts'].sum().reset_index().sort_values('failed_attempts', ascending=False).head(10)
else:
    # fallback to failed counts overall
    top_ips = failed_df.groupby('ip').size().reset_index(name='failed_attempts').sort_values('failed_attempts', ascending=False).head(10)

plt.figure(figsize=(10,5))
sns.barplot(x='ip', y='failed_attempts', data=top_ips, color='red')
plt.title('Top IPs involved in brute-force incidents')
plt.xlabel('IP')
plt.ylabel('Failed attempts (in incident windows)')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(BRUTEFORCE_PLOT)
plt.close()
print(f"✅ Bruteforce top-IP plot saved to {BRUTEFORCE_PLOT}")

# ---------------------
# Done
# ---------------------
print("All done. Inspect reports/bruteforce.csv and reports/ssh_analysis.csv for details.")
