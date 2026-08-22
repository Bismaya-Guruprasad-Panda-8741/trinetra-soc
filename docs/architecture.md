````markdown
# 🛡️ TRINETRA SOC — System Architecture

## 1. Overview

TRINETRA SOC is a lightweight Security Information and Event Management
(SIEM) prototype designed to monitor a Windows environment, detect
suspicious security activity, visualize threats in a real-time dashboard,
and provide physical alerts through an ESP8266.

The system is designed for an isolated cybersecurity laboratory using
Kali Linux and a Windows 11 VirtualBox VM.

---

# 2. High-Level Architecture

```text
                         ┌──────────────────┐
                         │    KALI LINUX    │
                         │                  │
                         │ Controlled       │
                         │ Security Testing │
                         └────────┬─────────┘
                                  │
                                  │
                         Host-Only Network
                                  │
                                  ▼
                         ┌──────────────────┐
                         │    WINDOWS 11    │
                         │       VM         │
                         │                  │
                         │ 192.168.56.101   │
                         └────────┬─────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  │                               │
                  ▼                               ▼
        ┌──────────────────┐            ┌──────────────────┐
        │ Windows Security │            │ Windows Firewall │
        │   & System Logs  │            │     pfirewall    │
        └────────┬─────────┘            └────────┬─────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                      ┌─────────────────────┐
                      │    TRINETRA SOC     │
                      │        SIEM         │
                      │                     │
                      │ Event Collection    │
                      │ Detection Engine    │
                      │ Alert Engine        │
                      └──────────┬──────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
          ┌──────────────────┐       ┌──────────────────┐
          │   SOC Dashboard  │       │     ESP8266      │
          │                  │       │ Physical Alert   │
          │ Active Alerts    │       └────────┬─────────┘
          │ Statistics       │                │
          │ Event History    │          ┌─────┴─────┐
          └──────────────────┘          ▼           ▼
                                      🔊 Buzzer    💡 LED
````

---

# 3. Network Architecture

TRINETRA SOC uses a controlled VirtualBox Host-only network.

```text
                    HOST-ONLY NETWORK
                    192.168.56.0/24
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
       ┌───────────┐               ┌───────────────┐
       │   KALI    │               │  WINDOWS 11   │
       │           │               │      VM       │
       │192.168.56.1               │192.168.56.101 │
       └───────────┘               └───────────────┘
             │                           │
             │ Controlled Testing        │
             └───────────────────────────┘
```

### Example IP Configuration

| Device        | IP Address       | Role                       |
| ------------- | ---------------- | -------------------------- |
| Kali Linux    | `192.168.56.1`   | Controlled testing machine |
| Windows 11 VM | `192.168.56.101` | Monitored endpoint         |

The network is isolated from the public Internet during testing.

---

# 4. Data Collection Layer

TRINETRA SOC collects security telemetry from two primary sources.

## 4.1 Windows Event Logs

The SIEM uses PowerShell to collect events from:

```text
Security
System
```

The collector retrieves:

* Log name
* Event ID
* Record ID
* Event timestamp
* Event message

The collected information is passed to the TRINETRA detection engine.

---

## 4.2 Windows Firewall Log

TRINETRA monitors:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

The firewall parser extracts:

```text
Source IP
Destination IP
Source Port
Destination Port
Timestamp
Action
Protocol
```

TRINETRA currently focuses on:

```text
DROP TCP
```

events.

---

# 5. Detection Engine

The detection engine analyzes collected telemetry and compares events
against predefined detection rules.

```text
                 Collected Event
                       │
                       ▼
                Event ID Check
                       │
              ┌────────┴────────┐
              │                 │
          Known Event       Unknown Event
              │                 │
              ▼                 ▼
        Detection Rule        Ignore
              │
              ▼
       Severity Classification
              │
       ┌──────┼───────────┐
       ▼      ▼           ▼
      LOW   MEDIUM    HIGH/CRITICAL
```

---

# 6. Windows Event Detection Rules

TRINETRA currently uses the following rules:

| Event ID | Description                          | Severity |
| -------- | ------------------------------------ | -------- |
| 4624     | Successful Logon                     | LOW      |
| 4625     | Failed Logon                         | HIGH     |
| 4672     | Special Privileges Assigned          | MEDIUM   |
| 5379     | Credential Manager Credentials Read  | MEDIUM   |
| 1102     | Security Log Cleared                 | CRITICAL |
| 4720     | User Account Created                 | HIGH     |
| 4726     | User Account Deleted                 | HIGH     |
| 4732     | Member Added To Local Security Group | HIGH     |
| 7045     | New Service Installed                | CRITICAL |
| 900      | TRINETRA Critical Test Event         | CRITICAL |
| 910      | Possible Network Scan Detected       | CRITICAL |

---

# 7. Firewall Detection Architecture

TRINETRA maintains firewall activity for each source IP.

```text
Windows Firewall DROP
          │
          ▼
     Parse Log Line
          │
          ▼
      Source IP
          │
          ▼
   Activity Tracking
          │
          ▼
    30 Second Window
          │
          ├───────────────────┐
          │                   │
          ▼                   ▼
   Blocked Attempts      Unique Ports
          │                   │
          ▼                   ▼
       >= 5                 >= 10
          │                   │
          └─────────┬─────────┘
                    ▼
             Detection Trigger
                    │
                    ▼
             Event ID 910
                    │
                    ▼
                CRITICAL
```

---

# 8. Firewall Detection Thresholds

Current configuration:

```text
Detection Window:
30 seconds

Blocked Attempt Threshold:
5

Unique Destination Port Threshold:
10
```

The detection engine generates a network scan alert when:

```text
Blocked attempts >= 5
```

OR:

```text
Unique destination ports >= 10
```

The generated event is:

```text
Event ID:
910

Title:
Possible Network Scan Detected

Severity:
CRITICAL
```

---

# 9. Event Processing

When an event is detected, TRINETRA creates a standardized event object.

```text
{
    id,
    log,
    event_id,
    record_id,
    title,
    severity,
    message,
    time,
    received
}
```

The event is inserted into the event history.

The system maintains a maximum history size of:

```text
500 events
```

---

# 10. Duplicate Event Prevention

TRINETRA prevents repeated processing of the same Windows event.

Windows events are identified using:

```text
LogName + RecordId
```

Example:

```text
Security-12345
System-54321
```

If the event has already been processed, it is ignored.

This prevents the same event from being continuously added during
repeated monitoring cycles.

---

# 11. Active Security Alert System

HIGH and CRITICAL events create an active security alert.

```text
             HIGH / CRITICAL EVENT
                       │
                       ▼
              ACTIVE SECURITY ALERT
                       │
                       ▼
                   60 Seconds
                       │
                       ▼
                Alert Expires
                       │
                       ▼
              Alert Removed From
                 Active Panel
                       │
                       ▼
             Event Remains In
                Event History
```

Example:

```text
🚨 ACTIVE SECURITY ALERT

Possible Network Scan Detected

Source:
192.168.56.1

Target:
192.168.56.101

Severity:
CRITICAL
```

---

# 12. Dashboard Architecture

The dashboard is built using:

```text
Python
   │
   ▼
Flask
   │
   ▼
HTML + CSS + JavaScript
```

The browser periodically requests:

```text
/api/status
```

The API provides:

```text
Total Events
HIGH Count
CRITICAL Count
Active Alert
Event History
```

---

# 13. Dashboard Data Flow

```text
TRINETRA SIEM
      │
      ▼
 Flask API
      │
      ▼
 /api/status
      │
      ▼
 JavaScript
      │
      ▼
 SOC Dashboard
```

The dashboard refreshes the displayed information periodically without
requiring the page to be manually reloaded.

---

# 14. Physical Alert Architecture

TRINETRA integrates an ESP8266 as a physical security notification
device.

```text
                    TRINETRA SIEM
                          │
                          │
                    USB Serial
                    115200 Baud
                          │
                          ▼
                     ESP8266
                          │
                 ┌────────┴────────┐
                 │                 │
                 ▼                 ▼
              Buzzer              LED
```

---

# 15. ESP8266 Pin Configuration

Current hardware configuration:

```text
ESP8266 D1 / GPIO5
        │
        ▼
      Buzzer

ESP8266 D5 / GPIO14
        │
        ▼
       LED

ESP8266 GND
        │
        ▼
      GND
```

---

# 16. ESP8266 Command Protocol

TRINETRA communicates with the ESP8266 using simple text commands.

```text
CRITICAL
HIGH
STOP
TEST
STATUS
PING
```

Example:

```text
TRINETRA
    │
    │ "CRITICAL\n"
    ▼
ESP8266
    │
    ├── Buzzer
    └── LED
```

---

# 17. CRITICAL Alert Flow

```text
CRITICAL EVENT
      │
      ▼
TRINETRA SIEM
      │
      ├──────────────────────┐
      │                      │
      ▼                      ▼
Dashboard                ESP8266
      │                      │
      ▼                      ▼
Active Alert           CRITICAL Command
      │                      │
      │                      ▼
      │                 Buzzer + LED
      │
      ▼
60 Seconds
      │
      ▼
Active Alert Expires
      │
      ▼
History Remains
```

---

# 18. HIGH Alert Flow

```text
HIGH EVENT
     │
     ▼
TRINETRA SIEM
     │
     ├─────────────────┐
     │                 │
     ▼                 ▼
Dashboard           ESP8266
     │                 │
     ▼                 ▼
HIGH Alert         HIGH Command
     │                 │
     │                 ▼
     │            Buzzer + LED
     │
     ▼
Alert Duration
     │
     ▼
History Remains
```

---

# 19. Thread Architecture

TRINETRA uses separate background threads for monitoring tasks.

```text
                    TRINETRA SOC
                         │
            ┌────────────┼────────────┐
            │            │            │
            ▼            ▼            ▼
       Event Thread  Firewall Thread Flask
            │            │            │
            ▼            ▼            ▼
       Security +    Firewall Log    Web API
       System Logs
```

### Windows Event Thread

Responsible for:

* Collecting Windows events
* Filtering configured Event IDs
* Preventing duplicates
* Creating events
* Triggering alerts

### Firewall Thread

Responsible for:

* Monitoring `pfirewall.log`
* Parsing DROP TCP events
* Tracking source IP activity
* Counting blocked attempts
* Counting unique destination ports
* Generating Event ID 910

### Flask Thread

Responsible for:

* Serving the dashboard
* Providing `/api/status`
* Delivering event data to the browser

---

# 20. Complete End-to-End Architecture

```text
┌───────────────────────────────────────────────────────────────┐
│                         TEST ENVIRONMENT                      │
│                                                               │
│  ┌───────────────┐                    ┌────────────────────┐  │
│  │  KALI LINUX   │                    │    WINDOWS 11 VM   │  │
│  │               │                    │                    │  │
│  │ 192.168.56.1  │──── Host-Only ───▶│ 192.168.56.101     │  │
│  │               │                    │                    │  │
│  └───────────────┘                    └─────────┬──────────┘  │
│                                                │             │
│                              ┌─────────────────┴──────────┐  │
│                              │                            │  │
│                              ▼                            ▼  │
│                       Windows Event Logs          Firewall Log│
│                              │                            │  │
│                              └──────────────┬─────────────┘  │
│                                             ▼                │
│                                  ┌─────────────────────┐    │
│                                  │    TRINETRA SOC     │    │
│                                  │                     │    │
│                                  │ Event Collector     │    │
│                                  │ Firewall Parser     │    │
│                                  │ Detection Engine    │    │
│                                  │ Alert Engine        │    │
│                                  └──────────┬──────────┘    │
│                                             │               │
│                              ┌──────────────┴────────────┐  │
│                              │                           │  │
│                              ▼                           ▼  │
│                       ┌──────────────┐            ┌──────────┐
│                       │ SOC Dashboard│            │ ESP8266  │
│                       │              │            │          │
│                       │ Active Alert │            │ Buzzer   │
│                       │ Statistics   │            │ LED      │
│                       │ Event History│            └──────────┘
│                       └──────────────┘                       │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

# 21. Security Detection Lifecycle

The complete TRINETRA lifecycle is:

```text
1. Event Generated
        ↓
2. Event Collected
        ↓
3. Event Parsed
        ↓
4. Detection Rule Applied
        ↓
5. Severity Determined
        ↓
6. Event Stored
        ↓
7. Active Alert Created
        ↓
8. Dashboard Updated
        ↓
9. ESP8266 Alert Triggered
        ↓
10. Active Alert Expires
        ↓
11. Historical Event Remains
```

---

# 22. Design Goals

TRINETRA SOC was designed around the following goals:

### Lightweight

Use Python, Flask, PowerShell, and simple rule-based detection rather
than requiring a large enterprise SIEM infrastructure.

### Educational

Make the internal working of a SIEM understandable and demonstrable.

### Real-Time

Detect and display security events with minimal delay.

### Physical Response

Provide a physical alert mechanism using an ESP8266.

### Controlled

Operate inside an isolated cybersecurity laboratory.

### Extensible

Allow additional Windows Event IDs, detection rules, dashboard
features, and hardware responses to be added later.

---

# 23. Future Improvements

Potential future improvements include:

* Machine-learning-based anomaly detection
* Database-backed event storage
* User authentication
* Role-based SOC access
* IP reputation checking
* Automated incident response
* Email notifications
* Telegram/Discord notifications
* More Windows Event IDs
* More advanced firewall correlation
* Threat intelligence integration
* Multiple monitored Windows endpoints
* Centralized log collection
* Improved visualization and analytics

---

# 24. Summary

TRINETRA SOC combines Windows telemetry, firewall monitoring, rule-based
threat detection, a real-time web dashboard, and physical ESP8266 alerts
into a single cybersecurity monitoring prototype.

The core architecture is:

```text
Windows Telemetry
       +
Firewall Activity
       ↓
TRINETRA Detection Engine
       ↓
┌──────┴─────────┐
▼                ▼
SOC Dashboard   ESP8266
▼                ▼
Digital Alert   Physical Alert
       │
       ▼
 Event History
```

---

## 🛡️ TRINETRA SOC

### Observe. Detect. Alert.

A lightweight security monitoring and threat detection prototype built
for controlled cybersecurity research and education.

```
```
