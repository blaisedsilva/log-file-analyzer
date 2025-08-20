# Log File Analyzer for Intrusion Detection

## Overview
This project is designed to analyze Apache and SSH logs to detect suspicious activities such as brute-force attacks, port scanning, and denial-of-service (DoS) attempts.  
It provides structured reports and visualizations to help identify intrusion patterns effectively.

## Tools
- **Python** – Core programming language  
- **Pandas** – Data manipulation and analysis  
- **Matplotlib** – Visualization of attack patterns  
- **Regex** – Pattern matching for log parsing  

## Structure
- `logs/` : Sample log files  
- `src/` : Python source code  
- `reports/` : Generated reports  
- `data/` : Processed data  
- `tests/` : Testing scripts  

## Progress
- **Day 1:** Setup project structure (`requirements.txt`, `.gitignore`, README, folders)  
- **Day 2:** Added Apache & SSH log parsing with sample logs  
- **Day 3:** Added threat detection and visualizations  
  - **Threat Detection:**  
    - SSH brute-force attempts (multiple failed logins)  
    - Apache brute-force attempts (multiple 401 responses)  
    - Port scanning (multiple unique endpoints accessed by same IP)  
    - Possible DoS attacks (high number of requests from same IP)  
  - **Visualizations:**  
    - Bar charts for Apache and SSH brute-force attempts  
    - Charts are saved as PNG files in `reports/`  
  - **Reports:**  
    - CSV files containing parsed logs and detected threats (`apache_parsed.csv`, `ssh_parsed.csv`, `bruteforce.csv`, `scanning.csv`, `dos.csv`)  
    - JSON summary (`summary.json`)  
    - PNG charts for detected events (`apache_bruteforce.png`, `ssh_bruteforce.png`)  

