from flask import Flask, jsonify, render_template_string
import subprocess
import json
import threading
import time
import os
import re
import serial
from datetime import datetime
from collections import defaultdict, deque


app = Flask(__name__)


# ============================================================
#                    TRINETRA SOC
#       Windows Event Viewer + Windows Firewall -> SIEM
# ============================================================


events = []
seen_events = set()

active_alert = None

MAX_HISTORY = 500


# ============================================================
#                    ESP8266 ALERT DEVICE
# ============================================================

ESP_PORT = "COM3"
ESP_BAUD = 115200

esp_serial = None
esp_lock = threading.Lock()


def connect_esp8266():

    global esp_serial

    try:

        esp_serial = serial.Serial(
            ESP_PORT,
            ESP_BAUD,
            timeout=1
        )

        time.sleep(2)

        print("")
        print("[+] ESP8266 connected")
        print(
            f"[+] ESP8266 Serial: "
            f"{ESP_PORT} @ {ESP_BAUD}"
        )
        print("")

        return True

    except Exception as error:

        esp_serial = None

        print("")
        print("[!] ESP8266 connection failed")
        print(f"[!] Port: {ESP_PORT}")
        print(f"[!] Error: {error}")
        print("")

        return False


def send_esp_command(command):

    global esp_serial

    with esp_lock:

        try:

            if (
                esp_serial is None
                or
                not esp_serial.is_open
            ):

                if not connect_esp8266():

                    return False

            esp_serial.write(
                (command + "\n").encode("utf-8")
            )

            esp_serial.flush()

            print(
                f"[ESP8266] Command sent: {command}"
            )

            return True

        except Exception as error:

            print(
                "[!] ESP8266 serial error:",
                error
            )

            try:

                if (
                    esp_serial
                    and
                    esp_serial.is_open
                ):

                    esp_serial.close()

            except Exception:
                pass

            esp_serial = None

            return False


# ============================================================
#                    FIREWALL CONFIGURATION
# ============================================================


FIREWALL_LOG = (
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

FIREWALL_WINDOW_SECONDS = 30

BLOCK_ATTEMPT_THRESHOLD = 5

UNIQUE_PORT_THRESHOLD = 10

firewall_activity = defaultdict(deque)

seen_firewall_lines = set()


# ============================================================
#                    EVENT RULES
# ============================================================


EVENT_RULES = {

    4624: {
        "title": "Successful Logon",
        "severity": "LOW"
    },

    4625: {
        "title": "Failed Logon",
        "severity": "HIGH"
    },

    4672: {
        "title": "Special Privileges Assigned",
        "severity": "MEDIUM"
    },

    5379: {
        "title": "Credential Manager Credentials Read",
        "severity": "MEDIUM"
    },

    1102: {
        "title": "Security Log Cleared",
        "severity": "CRITICAL"
    },

    4720: {
        "title": "User Account Created",
        "severity": "HIGH"
    },

    4726: {
        "title": "User Account Deleted",
        "severity": "HIGH"
    },

    4732: {
        "title": "Member Added To Local Security Group",
        "severity": "HIGH"
    },

    7045: {
        "title": "New Service Installed",
        "severity": "CRITICAL"
    },

    900: {
        "title": "TRINETRA Critical Test Event",
        "severity": "CRITICAL"
    },

    910: {
        "title": "Possible Network Scan Detected",
        "severity": "CRITICAL"
    }

}


# ============================================================
#                    ADD EVENT
# ============================================================


def add_event(
    log_name,
    event_id,
    record_id,
    title,
    severity,
    message,
    event_time
):

    global active_alert

    event = {

        "id": len(events) + 1,

        "log": log_name,

        "event_id": event_id,

        "record_id": record_id,

        "title": title,

        "severity": severity,

        "message": message[:700],

        "time": event_time,

        "received": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }

    events.insert(
        0,
        event
    )

    if len(events) > MAX_HISTORY:

        events.pop()

    # --------------------------------------------------------
    # ACTIVE SECURITY ALERT
    # --------------------------------------------------------

    if severity in [
        "HIGH",
        "CRITICAL"
    ]:

        # Extract source and target IP if available
        source_ip = ""
        target_ip = ""

        source_match = re.search(
            r"Source\s*[:=]?\s*"
            r"((?:\d{1,3}\.){3}\d{1,3})",
            message,
            re.IGNORECASE
        )

        target_match = re.search(
            r"(?:Target|Destination)\s*[:=]?\s*"
            r"((?:\d{1,3}\.){3}\d{1,3})",
            message,
            re.IGNORECASE
        )

        if source_match:

            source_ip = source_match.group(1)

        if target_match:

            target_ip = target_match.group(1)

        active_alert = {

            "title": title,

            "severity": severity,

            "event_id": event_id,

            "record_id": record_id,

            "log": log_name,

            "message": message[:500],

            "source_ip": source_ip,

            "target_ip": target_ip,

            "start": time.time(),

            "expires": time.time() + 60

        }

        # ----------------------------------------------------
        # PHYSICAL ESP8266 ALERT
        # ----------------------------------------------------

        if severity == "CRITICAL":

            send_esp_command(
                "CRITICAL"
            )

        elif severity == "HIGH":

            send_esp_command(
                "HIGH"
            )


# ============================================================
#                    GET WINDOWS EVENTS
# ============================================================


def get_windows_events():

    powershell_script = r"""
$security = Get-WinEvent -FilterHashtable @{ LogName='Security' } -MaxEvents 50 -ErrorAction SilentlyContinue

$system = Get-WinEvent -FilterHashtable @{ LogName='System' } -MaxEvents 50 -ErrorAction SilentlyContinue

$events = @($security) + @($system)

$result = foreach ($e in $events) {

    [PSCustomObject]@{

        LogName = $e.LogName

        Id = $e.Id

        RecordId = $e.RecordId

        TimeCreated = if ($e.TimeCreated) {

            $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")

        }
        else {

            ""

        }

        Message = if ($e.Message) {

            $e.Message

        }
        else {

            ""

        }

    }

}

$result | ConvertTo-Json -Compress
"""

    try:

        result = subprocess.run(

            [
                "powershell.exe",

                "-NoProfile",

                "-ExecutionPolicy",
                "Bypass",

                "-Command",
                powershell_script
            ],

            capture_output=True,

            text=True,

            timeout=20

        )

        if result.returncode != 0:

            print("PowerShell error:")
            print(result.stderr)

            return []

        output = result.stdout.strip()

        if not output:

            return []

        data = json.loads(output)

        if isinstance(data, dict):

            data = [data]

        return data

    except Exception as error:

        print(
            "Event collection error:",
            error
        )

        return []


# ============================================================
#                    WINDOWS EVENT MONITOR
# ============================================================


def monitor_windows_events():

    print("")
    print("[+] Windows Event Monitor started")
    print("[+] Monitoring Security + System logs")
    print("")

    while True:

        try:

            windows_events = get_windows_events()

            for event in windows_events:

                try:

                    event_id = int(
                        event["Id"]
                    )

                except Exception:

                    continue

                if event_id not in EVENT_RULES:

                    continue

                log_name = event.get(
                    "LogName",
                    "Unknown"
                )

                record_id = event.get(
                    "RecordId",
                    ""
                )

                event_time = event.get(
                    "TimeCreated",
                    ""
                )

                unique_id = (
                    f"{log_name}-"
                    f"{record_id}"
                )

                if unique_id in seen_events:

                    continue

                seen_events.add(
                    unique_id
                )

                rule = EVENT_RULES[
                    event_id
                ]

                title = rule[
                    "title"
                ]

                severity = rule[
                    "severity"
                ]

                message = event.get(
                    "Message",
                    ""
                )

                print(
                    f"[{severity}] "
                    f"{log_name} "
                    f"Event ID {event_id} "
                    f"Record {record_id}"
                )

                add_event(

                    log_name,

                    event_id,

                    record_id,

                    title,

                    severity,

                    message,

                    event_time

                )

            if len(seen_events) > 5000:

                seen_events.clear()

        except Exception as error:

            print(
                "[!] Monitor error:",
                error
            )

        time.sleep(3)


# ============================================================
#                    FIREWALL DROP PARSER
# ============================================================


def parse_firewall_line(line):

    line = line.strip()

    if not line:

        return None

    if "DROP" not in line.upper():

        return None

    if "TCP" not in line.upper():

        return None

    ips = re.findall(

        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",

        line

    )

    if len(ips) < 2:

        return None

    source_ip = ips[0]

    destination_ip = ips[1]

    match = re.search(

        r"\bDROP\s+TCP\b",

        line,

        re.IGNORECASE

    )

    if not match:

        return None

    after_protocol = line[
        match.end():
    ]

    numbers = re.findall(

        r"\b\d{1,5}\b",

        after_protocol

    )

    if len(numbers) < 2:

        return None

    try:

        source_port = int(
            numbers[0]
        )

        destination_port = int(
            numbers[1]
        )

    except ValueError:

        return None

    if not (
        0 <= source_port <= 65535
        and
        0 <= destination_port <= 65535
    ):

        return None

    time_match = re.search(

        r"(20\d{2}-\d{2}-\d{2})\s+"
        r"(\d{2}:\d{2}:\d{2})",

        line

    )

    if time_match:

        event_time = (

            time_match.group(1)
            + " "
            + time_match.group(2)

        )

    else:

        event_time = (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    return {

        "source_ip":
            source_ip,

        "destination_ip":
            destination_ip,

        "source_port":
            source_port,

        "destination_port":
            destination_port,

        "time":
            event_time,

        "raw":
            line

    }


# ============================================================
#                    FIREWALL DROP HANDLER
# ============================================================


def handle_firewall_drop(drop):

    global active_alert

    source_ip = drop[
        "source_ip"
    ]

    destination_ip = drop[
        "destination_ip"
    ]

    destination_port = drop[
        "destination_port"
    ]

    now = time.time()

    activity = firewall_activity[
        source_ip
    ]

    activity.append({

        "time": now,

        "destination_ip":
            destination_ip,

        "destination_port":
            destination_port

    })

    while activity:

        if (
            now - activity[0]["time"]
            <= FIREWALL_WINDOW_SECONDS
        ):

            break

        activity.popleft()

    blocked_attempts = len(
        activity
    )

    unique_ports = set(

        item[
            "destination_port"
        ]

        for item in activity

    )

    detection_triggered = (

        blocked_attempts
        >=
        BLOCK_ATTEMPT_THRESHOLD

        or

        len(unique_ports)
        >=
        UNIQUE_PORT_THRESHOLD

    )

    if not detection_triggered:

        return

    # --------------------------------------------------------
    # Prevent alert spam while current alert is active
    # --------------------------------------------------------

    if (

        active_alert

        and

        active_alert.get(
            "event_id"
        ) == 910

        and

        time.time()
        <
        active_alert.get(
            "expires",
            0
        )

    ):

        return

    title = (
        "Possible Network Scan Detected"
    )

    message = (

        f"Source {source_ip} generated "

        f"{blocked_attempts} blocked TCP "

        f"connection attempts against "

        f"{destination_ip} within "

        f"{FIREWALL_WINDOW_SECONDS} seconds. "

        f"Unique destination ports: "

        f"{len(unique_ports)}. "

        f"Latest blocked port: "

        f"{destination_port}."

    )

    print("")

    print(
        "[CRITICAL] "
        "Possible Network Scan Detected"
    )

    print(
        f"[+] Source: {source_ip}"
    )

    print(
        f"[+] Target: {destination_ip}"
    )

    print(
        f"[+] Blocked attempts: "
        f"{blocked_attempts}"
    )

    print(
        f"[+] Unique ports: "
        f"{len(unique_ports)}"
    )

    print("")

    add_event(

        "Windows Firewall",

        910,

        f"FW-{int(time.time() * 1000)}",

        title,

        "CRITICAL",

        message,

        drop["time"]

    )


# ============================================================
#                    WINDOWS FIREWALL MONITOR
# ============================================================


def monitor_firewall():

    print("")

    print(
        "[+] Windows Firewall Monitor started"
    )

    print(
        "[+] Monitoring:"
    )

    print(
        FIREWALL_LOG
    )

    print(

        f"[+] Port-scan threshold: "
        f"{UNIQUE_PORT_THRESHOLD} "
        f"unique ports/"
        f"{FIREWALL_WINDOW_SECONDS} seconds"

    )

    print(

        f"[+] Suspicious blocked-attempt "
        f"threshold: "
        f"{BLOCK_ATTEMPT_THRESHOLD} "
        f"attempts/"
        f"{FIREWALL_WINDOW_SECONDS} seconds"

    )

    print("")

    if not os.path.exists(
        FIREWALL_LOG
    ):

        print(
            "[!] Firewall log does not exist:"
        )

        print(
            FIREWALL_LOG
        )

        return

    try:

        with open(

            FIREWALL_LOG,

            "r",

            encoding="utf-8",

            errors="ignore"

        ) as firewall_file:

            firewall_file.seek(
                0,
                os.SEEK_END
            )

            print(
                "[+] Firewall log access confirmed"
            )

            while True:

                try:

                    line = (
                        firewall_file.readline()
                    )

                    if not line:

                        time.sleep(0.5)

                        try:

                            current_size = (
                                os.path.getsize(
                                    FIREWALL_LOG
                                )
                            )

                            current_position = (
                                firewall_file.tell()
                            )

                            if (
                                current_size
                                <
                                current_position
                            ):

                                print(
                                    "[+] Firewall log "
                                    "was reset/rotated."
                                )

                                firewall_file.seek(
                                    0,
                                    os.SEEK_SET
                                )

                        except Exception:

                            pass

                        continue

                    fingerprint = (
                        line.strip()
                    )

                    if not fingerprint:

                        continue

                    line_position = (
                        firewall_file.tell()
                    )

                    unique_line_id = (

                        f"{line_position}-"
                        f"{fingerprint}"

                    )

                    if (
                        unique_line_id
                        in
                        seen_firewall_lines
                    ):

                        continue

                    seen_firewall_lines.add(
                        unique_line_id
                    )

                    if (
                        len(
                            seen_firewall_lines
                        )
                        >
                        10000
                    ):

                        seen_firewall_lines.clear()

                    drop = (
                        parse_firewall_line(
                            line
                        )
                    )

                    if not drop:

                        continue

                    print(

                        "[FIREWALL DROP] "

                        f"{drop['source_ip']} -> "

                        f"{drop['destination_ip']}:"

                        f"{drop['destination_port']}"

                    )

                    handle_firewall_drop(
                        drop
                    )

                except Exception as error:

                    print(
                        "[!] Firewall monitor error:",
                        error
                    )

                    time.sleep(1)

    except PermissionError:

        print(
            "[!] Permission denied reading firewall log."
        )

        print(
            "[!] Run TRINETRA SOC from "
            "Administrator PowerShell."
        )

    except Exception as error:

        print(
            "[!] Firewall monitor failed:",
            error
        )


# ============================================================
#                    DASHBOARD HTML
# ============================================================


HTML = r"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>TRINETRA SOC</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family: Arial, sans-serif;

    background: #07111f;

    color: white;

}

.container {

    width: 92%;

    max-width: 1400px;

    margin: auto;

}

.header {

    padding: 35px 0 20px;

}

.logo {

    font-size: 38px;

    font-weight: bold;

}

.logo span {

    color: #00d9ff;

}

.subtitle {

    color: #8da2b8;

    margin-top: 8px;

}


/* =========================================================
   ACTIVE SECURITY ALERT
   ========================================================= */

.alert-panel {

    display: none;

    background: linear-gradient(
        135deg,
        #24111a,
        #160c13
    );

    border: 1px solid #ff4d6d;

    border-left: 6px solid #ff4d6d;

    border-radius: 16px;

    padding: 25px;

    margin: 20px 0 25px;

    box-shadow:
        0 0 25px rgba(
            255,
            77,
            109,
            0.18
        );

}

.alert-header {

    display: flex;

    justify-content: space-between;

    align-items: center;

    gap: 20px;

}

.alert-heading {

    font-size: 24px;

    font-weight: bold;

    color: #ff4d6d;

}

.alert-countdown {

    font-size: 32px;

    font-weight: bold;

    color: #ffffff;

    min-width: 90px;

    text-align: right;

}

.alert-title {

    font-size: 22px;

    font-weight: bold;

    margin-top: 20px;

    margin-bottom: 20px;

}

.alert-grid {

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 15px;

}

.alert-item {

    background: #0d1b2a;

    border: 1px solid #293d52;

    border-radius: 10px;

    padding: 15px;

}

.alert-label {

    color: #8da2b8;

    font-size: 12px;

    text-transform: uppercase;

    letter-spacing: 1px;

    margin-bottom: 7px;

}

.alert-value {

    font-size: 17px;

    font-weight: bold;

    word-break: break-word;

}

.alert-severity {

    color: #ff4d6d;

}

.alert-message {

    margin-top: 18px;

    padding: 15px;

    background: #0b1623;

    border-radius: 10px;

    color: #b9c7d5;

    line-height: 1.5;

}


/* =========================================================
   CARDS
   ========================================================= */

.cards {

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 18px;

    margin: 25px 0;

}

.card {

    background: #0d1b2a;

    border:
        1px solid #1d354d;

    border-radius: 14px;

    padding: 25px;

}

.card-title {

    color: #8da2b8;

    font-size: 13px;

    letter-spacing: 1px;

}

.card-value {

    font-size: 32px;

    font-weight: bold;

    margin-top: 10px;

}


/* =========================================================
   TABLE
   ========================================================= */

.table-container {

    background: #0d1b2a;

    border:
        1px solid #1d354d;

    border-radius: 14px;

    padding: 20px;

    overflow-x: auto;

}

table {

    width: 100%;

    border-collapse: collapse;

}

th,
td {

    padding: 14px;

    border-bottom:
        1px solid #1d354d;

    text-align: left;

}

th {

    color: #8da2b8;

    font-size: 13px;

}

.severity {

    font-weight: bold;

}

.low {

    color: #5eead4;

}

.medium {

    color: #facc15;

}

.high {

    color: #fb923c;

}

.critical {

    color: #ff4d6d;

}

.footer {

    text-align: center;

    padding: 30px;

    color: #70859a;

}

.author {

    color: #00d9ff;

}


/* =========================================================
   RESPONSIVE
   ========================================================= */

@media (max-width: 900px) {

    .cards {

        grid-template-columns:
            repeat(2, 1fr);

    }

    .alert-grid {

        grid-template-columns:
            repeat(2, 1fr);

    }

}

@media (max-width: 600px) {

    .cards {

        grid-template-columns: 1fr;

    }

    .alert-grid {

        grid-template-columns: 1fr;

    }

    .alert-header {

        align-items: flex-start;

    }

}

</style>

</head>


<body>


<div class="container">


<!-- =====================================================
     HEADER
     ===================================================== -->

<div class="header">

<div class="logo">

🛡️ TRINETRA <span>SOC</span>

</div>

<div class="subtitle">

Real-Time Windows Security Monitoring
& Threat Detection System

</div>

</div>


<!-- =====================================================
     ACTIVE SECURITY ALERT
     ===================================================== -->

<div
    id="activeAlert"
    class="alert-panel"
>

<div class="alert-header">

<div class="alert-heading">

🚨 ACTIVE SECURITY ALERT

</div>

<div
    id="alertCountdown"
    class="alert-countdown"
>

60s

</div>

</div>


<div
    id="alertTitle"
    class="alert-title"
>

Security Alert

</div>


<div class="alert-grid">


<div class="alert-item">

<div class="alert-label">

Source

</div>

<div
    id="alertSource"
    class="alert-value"
>

Unknown

</div>

</div>


<div class="alert-item">

<div class="alert-label">

Target

</div>

<div
    id="alertTarget"
    class="alert-value"
>

Unknown

</div>

</div>


<div class="alert-item">

<div class="alert-label">

Severity

</div>

<div
    id="alertSeverity"
    class="alert-value alert-severity"
>

CRITICAL

</div>

</div>


<div class="alert-item">

<div class="alert-label">

Event ID

</div>

<div
    id="alertEventId"
    class="alert-value"
>

-

</div>

</div>


<div class="alert-item">

<div class="alert-label">

Log

</div>

<div
    id="alertLog"
    class="alert-value"
>

-

</div>

</div>


<div class="alert-item">

<div class="alert-label">

Record ID

</div>

<div
    id="alertRecordId"
    class="alert-value"
>

-

</div>

</div>


</div>


<div
    id="alertMessage"
    class="alert-message"
>

Security event detected.

</div>


</div>


<!-- =====================================================
     STATISTICS
     ===================================================== -->

<div class="cards">


<div class="card">

<div class="card-title">

TOTAL EVENTS

</div>

<div
    class="card-value"
    id="total"
>

0

</div>

</div>


<div class="card">

<div class="card-title">

HIGH

</div>

<div
    class="card-value"
    id="high"
>

0

</div>

</div>


<div class="card">

<div class="card-title">

CRITICAL

</div>

<div
    class="card-value"
    id="critical"
>

0

</div>

</div>


<div class="card">

<div class="card-title">

HOST

</div>

<div
    class="card-value"
    style="font-size:20px"
>

WINDOWS 11

</div>

</div>


</div>


<!-- =====================================================
     EVENT HISTORY
     ===================================================== -->

<div class="table-container">

<h2>

📜 Real Windows Event History

</h2>


<table>

<thead>

<tr>

<th>Time</th>

<th>Log</th>

<th>Event ID</th>

<th>Event</th>

<th>Severity</th>

<th>Details</th>

</tr>

</thead>


<tbody id="eventTable">

</tbody>


</table>

</div>


<div class="footer">

TRINETRA Security Monitoring System

<br><br>

Made by

<span class="author">

Bismaya Guruprasad Panda

</span>

<br>

© 2026 TRINETRA SOC

</div>


</div>


<script>


// =========================================================
// HTML ESCAPE
// =========================================================

function escapeHtml(text) {

    if (!text) {

        return "";

    }

    return String(text)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );

}


// =========================================================
// ACTIVE ALERT
// =========================================================

function updateActiveAlert(alert) {

    const panel =
        document.getElementById(
            "activeAlert"
        );


    if (!alert) {

        panel.style.display =
            "none";

        return;

    }


    const remaining =
        Math.max(
            0,
            Math.ceil(
                alert.expires -
                (Date.now() / 1000)
            )
        );


    if (remaining <= 0) {

        panel.style.display =
            "none";

        return;

    }


    panel.style.display =
        "block";


    document.getElementById(
        "alertCountdown"
    ).textContent =
        remaining + "s";


    document.getElementById(
        "alertTitle"
    ).textContent =
        alert.title || "Security Alert";


    document.getElementById(
        "alertSource"
    ).textContent =
        alert.source_ip || "Unknown";


    document.getElementById(
        "alertTarget"
    ).textContent =
        alert.target_ip || "Unknown";


    document.getElementById(
        "alertSeverity"
    ).textContent =
        alert.severity || "UNKNOWN";


    document.getElementById(
        "alertEventId"
    ).textContent =
        alert.event_id || "-";


    document.getElementById(
        "alertLog"
    ).textContent =
        alert.log || "-";


    document.getElementById(
        "alertRecordId"
    ).textContent =
        alert.record_id || "-";


    document.getElementById(
        "alertMessage"
    ).textContent =
        alert.message || "Security event detected.";

}


// =========================================================
// DASHBOARD UPDATE
// =========================================================

async function updateDashboard() {

    try {

        const response =
            await fetch(
                "/api/status"
            );


        const data =
            await response.json();


        // -------------------------------------------------
        // Statistics
        // -------------------------------------------------

        document.getElementById(
            "total"
        ).textContent =
            data.total;


        document.getElementById(
            "high"
        ).textContent =
            data.high;


        document.getElementById(
            "critical"
        ).textContent =
            data.critical;


        // -------------------------------------------------
        // Active Security Alert
        // -------------------------------------------------

        updateActiveAlert(
            data.alert
        );


        // -------------------------------------------------
        // Event History
        // -------------------------------------------------

        const table =
            document.getElementById(
                "eventTable"
            );


        table.innerHTML = "";


        data.events.forEach(
            event => {

                const row =
                    document.createElement(
                        "tr"
                    );


                const severity =
                    String(
                        event.severity
                    ).toLowerCase();


                row.innerHTML = `

<td>
${escapeHtml(event.time)}
</td>

<td>
${escapeHtml(event.log)}
</td>

<td>
${escapeHtml(event.event_id)}
</td>

<td>
${escapeHtml(event.title)}
</td>

<td class="severity ${severity}">
${escapeHtml(event.severity)}
</td>

<td>
${escapeHtml(event.message)}
</td>

`;


                table.appendChild(
                    row
                );

            }
        );


    }

    catch (error) {

        console.error(
            "Dashboard error:",
            error
        );

    }

}


// =========================================================
// INITIAL LOAD
// =========================================================

updateDashboard();


// =========================================================
// UPDATE EVERY SECOND
//
// This is important because the 60-second countdown
// needs to update smoothly on the dashboard.
// =========================================================

setInterval(
    updateDashboard,
    1000
);

</script>


</body>

</html>
"""


# ============================================================
#                    DASHBOARD ROUTE
# ============================================================


@app.route("/")
def dashboard():

    return render_template_string(
        HTML
    )


# ============================================================
#                    API
# ============================================================


@app.route("/api/status")
def status():

    global active_alert

    # --------------------------------------------------------
    # Expire 60-second active alert
    # --------------------------------------------------------

    if active_alert:

        if (
            time.time()
            >=
            active_alert["expires"]
        ):

            active_alert = None


    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    high = sum(

        1

        for event in events

        if event["severity"]
        ==
        "HIGH"

    )


    critical = sum(

        1

        for event in events

        if event["severity"]
        ==
        "CRITICAL"

    )


    return jsonify({

        "total":
            len(events),

        "high":
            high,

        "critical":
            critical,

        "alert":
            active_alert,

        "events":
            events[:100]

    })


# ============================================================
#                    START TRINETRA SOC
# ============================================================


if __name__ == "__main__":

    print("")

    print(
        "=============================================="
    )

    print(
        "             TRINETRA SOC"
    )

    print(
        "        WINDOWS SECURITY SIEM"
    )

    print(
        "=============================================="
    )

    print(
        "[+] Windows Event Viewer monitoring"
    )

    print(
        "[+] Security log enabled"
    )

    print(
        "[+] System log enabled"
    )

    print(
        "[+] Real event collection enabled"
    )

    print(
        "[+] Event ID 900 detection enabled"
    )

    print(
        "[+] Windows Firewall monitoring enabled"
    )

    print(
        "[+] Port scan detection enabled"
    )

    print(
        "[+] Suspicious blocked-attempt detection enabled"
    )

    print(
        "[+] 60 second active alerts enabled"
    )

    print(
        "[+] Permanent session history enabled"
    )

    print("")

    # --------------------------------------------------------
    # ESP8266
    # --------------------------------------------------------

    print(
        "[+] ESP8266 physical alert enabled"
    )

    print(
        f"[+] ESP8266 port: {ESP_PORT}"
    )

    print(
        f"[+] ESP8266 baud: {ESP_BAUD}"
    )

    print("")

    # --------------------------------------------------------
    # Initial ESP8266 connection
    # --------------------------------------------------------

    connect_esp8266()

    print(
        "[+] Dashboard:"
    )

    print(
        "    http://127.0.0.1:5000"
    )

    print(
        "=============================================="
    )

    print("")

    # --------------------------------------------------------
    # Windows Event Monitor
    # --------------------------------------------------------

    event_thread = threading.Thread(

        target=monitor_windows_events,

        daemon=True

    )

    event_thread.start()

    # --------------------------------------------------------
    # Firewall Monitor
    # --------------------------------------------------------

    firewall_thread = threading.Thread(

        target=monitor_firewall,

        daemon=True

    )

    firewall_thread.start()

    # --------------------------------------------------------
    # Flask
    # --------------------------------------------------------

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=False

    )