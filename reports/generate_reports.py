import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Example suspicious events (replace later with real analyzer output)
suspicious_events = [
    {"event": "Failed login", "ip": "192.168.1.10", "time": "2025-08-29 14:32"},
    {"event": "Port scan", "ip": "203.0.113.45", "time": "2025-08-29 15:10"},
]

# ---- Generate CSV Report ----
with open("reports/incident_report.csv", "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["event", "ip", "time"])
    writer.writeheader()
    writer.writerows(suspicious_events)

# ---- Generate TXT Report ----
with open("reports/incident_report.txt", "w") as txtfile:
    for event in suspicious_events:
        txtfile.write(f"{event['time']} - {event['event']} from {event['ip']}\n")

# ---- Generate PDF Report ----
pdf_file = "reports/incident_report.pdf"
c = canvas.Canvas(pdf_file, pagesize=letter)
c.setFont("Helvetica", 12)
c.drawString(100, 750, "Incident Report")
y = 720
for event in suspicious_events:
    line = f"{event['time']} - {event['event']} from {event['ip']}"
    c.drawString(100, y, line)
    y -= 20
c.save()

print("✅ Reports generated in 'reports' folder: CSV, TXT, PDF")
