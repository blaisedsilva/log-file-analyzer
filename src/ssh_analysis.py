# src/ssh_analysis.py

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# -----------------------------
# Step 1: Read the parsed SSH CSV
ssh_df = pd.read_csv("reports/ssh_parsed.csv")

# Step 2: Ensure necessary columns exist
if 'is_failed' not in ssh_df.columns:
    ssh_df['is_failed'] = ssh_df['status'] == 'FAILED'
if 'is_success' not in ssh_df.columns:
    ssh_df['is_success'] = ssh_df['status'] == 'SUCCESS'

# Step 3: Detect repeated failed attempts per IP
failed_counts = ssh_df.groupby('ip')['is_failed'].cumsum()
ssh_df['suspicious'] = ssh_df['is_failed'] & (failed_counts >= 3)

# Step 4: Map IPs to countries (simplified mapping)
def map_country(ip):
    if ip.startswith('203.'):
        return 'India'
    else:
        return 'Private Network'

ssh_df['country'] = ssh_df['ip'].apply(map_country)

# Step 5: Fix date parsing warning by adding a fixed year
ssh_df['date'] = pd.to_datetime(ssh_df['date'] + ' 2025', format='%b %d %H:%M:%S %Y')

# Step 6: Save updated CSV
ssh_df.to_csv("reports/ssh_analysis.csv", index=False)

# Step 7a: Failed attempts per IP with suspicious highlighted
failed_ip_counts = ssh_df[ssh_df['is_failed']].groupby('ip').size().reset_index(name='failed_attempts')
failed_ip_counts['highlight'] = failed_ip_counts['ip'].isin(ssh_df[ssh_df['suspicious']]['ip'].unique())

plt.figure(figsize=(10, 6))
sns.barplot(
    x='ip',
    y='failed_attempts',
    hue='highlight',   # use hue to highlight suspicious
    data=failed_ip_counts,
    dodge=False,
    palette={True: 'red', False: 'grey'}
)
plt.title("Failed SSH Login Attempts per IP (Suspicious in Red)")
plt.xlabel("IP Address")
plt.ylabel("Failed Attempts")
plt.xticks(rotation=45)
plt.legend([], [], frameon=False)  # hide legend
plt.tight_layout()
plt.savefig("reports/ssh_failed_attempts_highlighted.png")
plt.close()

# Step 7b: Suspicious attempts over time
time_counts = ssh_df[ssh_df['suspicious']].groupby('date').size().reset_index(name='suspicious_attempts')
plt.figure(figsize=(12, 6))
sns.lineplot(x='date', y='suspicious_attempts', data=time_counts, marker='o', color='orange')
plt.title('Suspicious SSH Login Attempts Over Time')
plt.xlabel('Date & Time')
plt.ylabel('Number of Suspicious Attempts')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("reports/ssh_suspicious_over_time.png")
plt.close()

# Step 7c: Success vs Failed logins pie chart
status_counts = ssh_df['status'].value_counts()
plt.figure(figsize=(6,6))
plt.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', colors=['green','red'], startangle=140)
plt.title('SSH Login Status Distribution')
plt.tight_layout()
plt.savefig("reports/ssh_status_pie.png")
plt.close()

# Step 8: Display sample data
print("✅ SSH analysis complete. Sample data:")
print(ssh_df.head())
print("\n📊 Visualizations saved in 'reports/' folder:")
print(" - ssh_failed_attempts_highlighted.png")
print(" - ssh_suspicious_over_time.png")
print(" - ssh_status_pie.png")
