# src/visualizations.py

import pandas as pd
import matplotlib.pyplot as plt
import os

# Ensure reports folder exists
os.makedirs("reports", exist_ok=True)

# --- Brute-force visualization ---
df_brute = pd.read_csv("reports/bruteforce.csv")
if not df_brute.empty:
    # Replace 'attempts' with the actual column name in your CSV, e.g., 'failed_attempts'
    attempts_col = "failed_attempts" if "failed_attempts" in df_brute.columns else df_brute.columns[1]
    top_ips_brute = df_brute.sort_values(attempts_col, ascending=False).head(10)
    plt.figure(figsize=(10,6))
    plt.bar(top_ips_brute["ip"], top_ips_brute[attempts_col], color='red')
    plt.title("Top 10 IPs - Brute Force Attempts")
    plt.xlabel("IP Address")
    plt.ylabel("Failed Login Attempts")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("reports/bruteforce_top10_ips_chart.png")
    plt.close()

# --- Scanning attacks visualization ---
df_scan = pd.read_csv("reports/scanning.csv")
if not df_scan.empty:
    top_ips_scan = df_scan.sort_values("unique_endpoints_total", ascending=False).head(10)
    plt.figure(figsize=(10,6))
    plt.bar(top_ips_scan["ip"], top_ips_scan["unique_endpoints_total"], color='orange')
    plt.title("Top 10 IPs - Scanning Attacks")
    plt.xlabel("IP Address")
    plt.ylabel("Unique Endpoints Accessed")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("reports/scanning_top10_ips_chart.png")
    plt.close()

# --- DoS attacks visualization ---
df_dos = pd.read_csv("reports/dos.csv")
if not df_dos.empty:
    df_dos['first_seen'] = pd.to_datetime(df_dos['first_seen'])
    plt.figure(figsize=(10,6))
    plt.plot(df_dos['first_seen'], df_dos['requests'], marker='o', linestyle='-')
    plt.title("DoS Activity Over Time")
    plt.xlabel("Time")
    plt.ylabel("Number of Requests")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("reports/dos_time_plot.png")
    plt.close()

print("✅ All visualizations generated in reports/ folder!")
