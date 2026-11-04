# Windows-Failed-Login-Detection-System
Mini Project - Windows Failed Login Detection System

### Beginner-friendly Google Colab project. It analyzes Windows Security Event IDs 4625 (failed logon) and 4624 (successful logon), detects repeated failures by source IP and username, and launches a Gradio SOC dashboard

!pip -q install gradio pandas tabulate

# Upload the project CSV
from google.colab import files
uploaded = files.upload()  # Choose sample_windows_auth_logs.csv

### Start the SOC dashboard

import pandas as pd
import gradio as gr
import tempfile
import os
from datetime import datetime

REQUIRED = ["Timestamp", "EventID", "Computer", "TargetUserName", "IpAddress"]

def load_logs(file_obj):
    if file_obj is None:
        raise ValueError("Please upload a CSV file.")
    path = file_obj.name if hasattr(file_obj, "name") else str(file_obj)
    data = pd.read_csv(path)
    # Normalize common column-name variations
    aliases = {
        "TimeCreated": "Timestamp", "TimeCreatedUtc": "Timestamp",
        "Event ID": "EventID", "EventId": "EventID",
        "WorkstationName": "Computer", "AccountName": "TargetUserName",
        "SourceIP": "IpAddress", "SourceIp": "IpAddress", "Ip Address": "IpAddress"
    }
    data = data.rename(columns={c: aliases.get(c, c) for c in data.columns})
    missing = [c for c in REQUIRED if c not in data.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    data["Timestamp"] = pd.to_datetime(data["Timestamp"], errors="coerce")
    data["EventID"] = pd.to_numeric(data["EventID"], errors="coerce")
    data = data.dropna(subset=["Timestamp", "EventID"]).copy()
    data["EventID"] = data["EventID"].astype(int)
    data["TargetUserName"] = data["TargetUserName"].fillna("Unknown").astype(str)
    data["IpAddress"] = data["IpAddress"].fillna("Unknown").astype(str)
    data["Computer"] = data["Computer"].fillna("Unknown").astype(str)
    return data

def detect_suspicious_activity(data, threshold, window_minutes):
    failed = data[data["EventID"] == 4625].copy()
    successful = data[data["EventID"] == 4624].copy()
    if failed.empty:
        return pd.DataFrame(), failed, successful

    # Sliding time window per source IP + username. Every event is evaluated
    # against failures occurring during the preceding window_minutes.
    failed = failed.sort_values("Timestamp")
    alert_rows = []
    for (ip, user), group in failed.groupby(["IpAddress", "TargetUserName"], dropna=False):
        times = group["Timestamp"].tolist()
        left = 0
        max_count = 0
        for right, current_time in enumerate(times):
            while left <= right and (current_time - times[left]).total_seconds() > window_minutes * 60:
                left += 1
            count = right - left + 1
            max_count = max(max_count, count)
        if max_count >= threshold:
            if max_count >= 10:
                severity = "Critical"
            elif max_count >= 5:
                severity = "High"
            elif max_count >= 3:
                severity = "Medium"
            else:
                severity = "Low"
            first_seen = group["Timestamp"].min()
            last_seen = group["Timestamp"].max()
            matching_success = successful[
                (successful["IpAddress"] == ip) &
                (successful["TargetUserName"] == user) &
                (successful["Timestamp"] >= first_seen) &
                (successful["Timestamp"] <= last_seen + pd.Timedelta(minutes=15))
            ]
            alert_rows.append({
                "Source IP": ip,
                "Username": user,
                "Computer": ", ".join(sorted(group["Computer"].unique())),
                "Failed Attempts": int(max_count),
                "First Seen": first_seen,
                "Last Seen": last_seen,
                "Severity": severity,
                "Successful Login Nearby": "Yes" if not matching_success.empty else "No",
                "Suggested Triage": (
                    "Review urgently; verify account owner, source IP and any successful login."
                    if severity in ["High", "Critical"] else
                    "Check whether failures are user error or repeated unauthorized attempts."
                )
            })
    alerts = pd.DataFrame(alert_rows)
    if not alerts.empty:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        alerts["_order"] = alerts["Severity"].map(order)
        alerts = alerts.sort_values(["_order", "Failed Attempts"], ascending=[True, False]).drop(columns="_order")
    return alerts, failed, successful

def analyze(file_obj, threshold, window_minutes):
    try:
        data = load_logs(file_obj)
        alerts, failed, successful = detect_suspicious_activity(data, int(threshold), int(window_minutes))
        total = len(data)
        fail_count = len(failed)
        success_count = len(successful)
        alert_count = len(alerts)
        critical = int((alerts["Severity"] == "Critical").sum()) if alert_count else 0
        high = int((alerts["Severity"] == "High").sum()) if alert_count else 0

        summary = (
            f"### Analysis summary\n"
            f"- Total valid events: **{total}**\n"
            f"- Failed logins (4625): **{fail_count}**\n"
            f"- Successful logins (4624): **{success_count}**\n"
            f"- Suspicious source-IP/user groups: **{alert_count}**\n"
            f"- Critical alerts: **{critical}** | High alerts: **{high}**\n"
        )
        if alert_count:
            report = (
                "# SOC Incident Report — Windows Failed Login Monitoring\n\n"
                f"**Analysis time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
                f"**Events analyzed:** {total}  \n"
                f"**Failed logins:** {fail_count}  \n"
                f"**Alert groups:** {alert_count}\n\n"
                "## Executive summary\n"
                f"The analysis identified {alert_count} source-IP and username group(s) meeting the configured "
                f"threshold of {threshold} failed logins within {window_minutes} minutes. "
                "These findings may indicate brute-force activity and require validation by an analyst.\n\n"
                "## Alert details\n"
                + alerts.to_markdown(index=False) + "\n\n"
                "## Recommended actions\n"
                "1. Validate whether the source IP belongs to an authorized user, VPN, proxy or approved system.\n"
                "2. Check for successful logins following the failed attempts and review the associated account activity.\n"
                "3. Contact the account owner / system owner and follow the organization's incident-response process.\n"
                "4. If malicious activity is confirmed, escalate to the incident-response team and apply approved containment controls.\n\n"
                "## Limitations\n"
                "This is a threshold-based demonstration using the supplied CSV fields. It does not prove malicious intent. "
                "Correlate with full Windows event details, endpoint telemetry, identity-provider logs and network records."
            )
        else:
            report = (
                "# SOC Incident Report — Windows Failed Login Monitoring\n\n"
                "No source-IP and username group met the configured alert threshold in this dataset. "
                "This does not prove that the environment is free from threats. Review the threshold, time window "
                "and data completeness as part of normal monitoring.\n"
            )

        # Save downloadable outputs for this analysis
        alert_file = tempfile.NamedTemporaryFile(delete=False, suffix="_soc_alerts.csv")
        alerts.to_csv(alert_file.name, index=False)
        report_file = tempfile.NamedTemporaryFile(delete=False, suffix="_incident_report.md", mode="w", encoding="utf-8")
        report_file.write(report)
        report_file.close()

        preview = alerts if not alerts.empty else pd.DataFrame(columns=[
            "Source IP","Username","Computer","Failed Attempts","First Seen","Last Seen",
            "Severity","Successful Login Nearby","Suggested Triage"
        ])
        return summary, preview, alert_file.name, report_file.name, data.head(10)
    except Exception as exc:
        return f"**Error:** {exc}", pd.DataFrame(), None, None, pd.DataFrame()

with gr.Blocks(title="Windows Failed Login Detection | SOC Dashboard", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🛡️ Windows Failed Login Detection System\n### Beginner SOC Analyst Project | Event ID 4625 / 4624")
    gr.Markdown("Upload a CSV containing Windows authentication events. The dashboard groups failed logins by source IP and username within a configurable time window.")
    with gr.Row():
        file_input = gr.File(label="Upload Windows authentication CSV", file_types=[".csv"], type="filepath")
    with gr.Row():
        threshold = gr.Slider(3, 20, value=5, step=1, label="Alert threshold (failed attempts)")
        window = gr.Slider(1, 60, value=10, step=1, label="Time window (minutes)")
    run_btn = gr.Button("Analyze Logs", variant="primary")
    summary = gr.Markdown()
    alerts_table = gr.Dataframe(label="Suspicious activity alerts", interactive=False, wrap=True)
    with gr.Row():
        alerts_download = gr.File(label="Download alert results (CSV)")
        report_download = gr.File(label="Download incident report (Markdown)")
    preview = gr.Dataframe(label="Input data preview (first 10 rows)", interactive=False)
    run_btn.click(analyze, inputs=[file_input, threshold, window],
                  outputs=[summary, alerts_table, alerts_download, report_download, preview])
    gr.Markdown("**Note:** Use synthetic or properly authorized logs. The sample dataset contains fictional IPs and usernames.")

if __name__ == "__main__":
    demo.launch(share=True, debug=True)
