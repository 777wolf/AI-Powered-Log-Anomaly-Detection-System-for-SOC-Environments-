# scripts/log_collector.py
# Purpose: Pull Windows Security Event Logs from remote VM using WMI

import subprocess
import pandas as pd
import os
import sys
import getpass

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import EVENT_IDS, DATA_PATH


def collect_logs_wmi(server="192.168.56.102", username=None, password=None, max_records=5000):
    """
    Uses WMI (Windows Management Instrumentation) to pull Security Event Logs
    from a remote Windows machine. More reliable than OpenEventLog for remote access.
    """

    print(f"[*] Connecting to {server} via WMI...")

    # Build Event ID filter for WMI query
    # WMI uses SQL-like syntax called WQL
    event_id_filter = " OR ".join([f"EventCode='{eid}'" for eid in EVENT_IDS])

    # WMI query to get security events
    # Win32_NTLogEvent = Windows Event Log WMI class
    wmi_query = f"SELECT * FROM Win32_NTLogEvent WHERE Logfile='Security' AND ({event_id_filter})"

    # Build PowerShell command to run WMI query remotely
    # We use PowerShell because it handles WMI auth cleanly
    ps_script = f"""
$username = '{username}'
$password = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

$events = Get-WmiObject -Query "{wmi_query}" -ComputerName {server} -Credential $cred |
          Select-Object -First {max_records}

$results = @()
foreach ($event in $events) {{
    $obj = [PSCustomObject]@{{
        timestamp    = $event.TimeGenerated
        event_id     = $event.EventCode
        source       = $event.SourceName
        computer     = $event.ComputerName
        message      = $event.Message -replace "`n", " " -replace "`r", " " -replace ",", ";"
        category     = $event.CategoryString
        event_type   = $event.Type
    }}
    $results += $obj
}}

$results | ConvertTo-Csv -NoTypeInformation
"""

    print(f"[*] Running WMI query for Event IDs: {EVENT_IDS}")
    print(f"[*] This may take 30-60 seconds for large logs...")

    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            print(f"[!] PowerShell error: {result.stderr}")
            sys.exit(1)

        if not result.stdout.strip():
            print("[!] No output returned. Check credentials and VM connectivity.")
            sys.exit(1)

        # Parse CSV output from PowerShell
        from io import StringIO
        df = pd.read_csv(StringIO(result.stdout))

        print(f"[+] Collected {len(df)} events")

        if df.empty:
            print("[!] No matching events found.")
            return df

        # Save to CSV
        output_path = os.path.join(DATA_PATH, "raw_logs.csv")
        df.to_csv(output_path, index=False)

        print(f"[+] Saved to {output_path}")
        print(f"[+] Shape: {df.shape[0]} rows x {df.shape[1]} columns")
        print(f"\n[*] Event ID breakdown:")
        print(df["event_id"].value_counts())

        return df

    except subprocess.TimeoutExpired:
        print("[!] Query timed out. VM may be slow or unreachable.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    import sys

    # Accept credentials as command line args (for dashboard automation)
    # Usage: python log_collector.py <username> <password>
    if len(sys.argv) == 3:
        username = sys.argv[1]
        password = sys.argv[2]
        print(f"[*] Using credentials from arguments: {username}")
    else:
        print("\n[*] Enter Windows 10 VM credentials:")
        username = input("    Username: ").strip()
        password = getpass.getpass("    Password: ")

    df = collect_logs_wmi(
        server="192.168.56.102",
        username=username,
        password=password,
        max_records=5000
    )

    if not df.empty:
        print("\n[*] Sample of collected data:")
        print(df.head(10))
        print("\n[+] Done. Check data/raw_logs.csv")


