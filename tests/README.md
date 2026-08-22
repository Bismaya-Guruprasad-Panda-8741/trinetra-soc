````markdown
# 🧪 TRINETRA SOC — Testing Guide

This folder contains documentation for testing the TRINETRA SOC security
monitoring system in an isolated and authorized laboratory environment.

---

## 🎯 Testing Objective

The purpose of testing is to verify that TRINETRA SOC can:

- Collect Windows Security and System events
- Detect configured security events
- Monitor Windows Firewall DROP events
- Detect suspicious network activity
- Generate HIGH and CRITICAL alerts
- Display active alerts on the dashboard
- Keep detected events in history
- Trigger the ESP8266 physical alert device

---

# 🖥️ Test Environment

TRINETRA SOC is designed for a controlled VirtualBox laboratory.

```text
                    KALI LINUX
                   192.168.56.1
                        │
                        │
                Host-Only Network
                        │
                        ▼
                  WINDOWS 11 VM
                 192.168.56.101
                        │
             ┌──────────┴──────────┐
             │                     │
             ▼                     ▼
       Windows Events        Windows Firewall
             │                     │
             └──────────┬──────────┘
                        ▼
                  TRINETRA SOC
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
         Web Dashboard         ESP8266
                                │
                           ┌────┴────┐
                           ▼         ▼
                        Buzzer      LED
````

---

# 🔬 Test 1 — SIEM Startup

## Objective

Verify that TRINETRA SOC starts correctly and all monitoring components
are initialized.

## Run

Open **PowerShell as Administrator** on the Windows VM.

```powershell
python siem.py
```

or, depending on the project directory:

```powershell
python siem/siem.py
```

## Expected Console Output

You should see messages similar to:

```text
==============================================
          TRINETRA SOC WINDOWS SIEM
==============================================

[+] Windows Event Viewer monitoring
[+] Security log enabled
[+] System log enabled
[+] Real event collection enabled
[+] Windows Firewall monitoring enabled
[+] Port scan detection enabled
[+] Suspicious blocked-attempt detection enabled
[+] 60 second active alerts enabled
[+] Permanent session history enabled

[+] ESP8266 physical alert enabled
```

Then open:

```text
http://127.0.0.1:5000
```

## Expected Result

The TRINETRA SOC dashboard should load successfully.

---

# 🔌 Test 2 — ESP8266 Connection

## Objective

Verify that the SIEM can communicate with the ESP8266 through USB Serial.

## Configuration

The default configuration is:

```python
ESP_PORT = "COM3"
ESP_BAUD = 115200
```

Change `COM3` if Windows assigns a different COM port.

## Expected Result

The console should show:

```text
[+] ESP8266 connected
[+] ESP8266 Serial: COM3 @ 115200
```

The ESP8266 should also display its startup message through the serial
monitor.

---

# 🔊 Test 3 — ESP8266 Physical Alert

## Objective

Verify that the buzzer and LED connected to the ESP8266 work correctly.

## Wiring

```text
ESP8266 D1 / GPIO5  → Buzzer
ESP8266 D5 / GPIO14 → LED
ESP8266 GND         → GND
```

## Supported Commands

```text
TEST
HIGH
CRITICAL
STOP
STATUS
PING
```

## Expected Result

### TEST

The ESP8266 should activate the configured buzzer and LED test pattern.

### HIGH

The HIGH alert pattern should run for approximately 10 seconds.

### CRITICAL

The CRITICAL alert pattern should run for up to 60 seconds.

### STOP

The buzzer and LED should turn OFF.

### STATUS

The ESP8266 should report its current alert state.

### PING

Expected response:

```text
PONG
```

---

# 🪟 Test 4 — Windows Security Event Monitoring

## Objective

Verify that TRINETRA can collect and detect configured Windows events.

TRINETRA monitors selected events from:

```text
Security
System
```

The following event IDs are currently configured:

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

# 🚨 Test 5 — Critical Test Event

## Objective

Verify the complete TRINETRA alert pipeline without relying on a real
security incident.

The test event uses:

```text
Event ID: 900
Severity: CRITICAL
```

## Generate the Test Event

Run the authorized test command in **PowerShell as Administrator**:

```powershell
eventcreate /T ERROR /ID 900 /L APPLICATION /SO TRINETRA /D "TRINETRA SOC Critical Test Event"
```

## Expected Flow

```text
PowerShell
    │
    ▼
Windows Event Log
    │
    ▼
Event ID 900
    │
    ▼
TRINETRA SOC
    │
    ├───────────────┐
    ▼               ▼
Dashboard        ESP8266
    │               │
    ▼               ▼
CRITICAL         Buzzer + LED
Alert
    │
    ▼
60 Seconds
    │
    ▼
Alert disappears
    │
    ▼
History remains
```

## Expected Dashboard

```text
🚨 ACTIVE SECURITY ALERT

TRINETRA Critical Test Event

Severity:
CRITICAL

Event ID:
900
```

The alert should remain active for approximately 60 seconds.

After the timer expires, the active alert should disappear while the
event remains in the event history.

---

# 🔥 Test 6 — Windows Firewall Monitoring

## Objective

Verify that TRINETRA can monitor Windows Firewall DROP events.

TRINETRA reads:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

The current detection configuration is:

```text
Detection Window:
30 seconds

Blocked Attempt Threshold:
5

Unique Port Threshold:
10
```

---

# 🌐 Test 7 — Controlled Network Scan Detection

## Objective

Verify that repeated blocked TCP connections can trigger the network
scan detection rule.

The testing environment should remain isolated.

```text
Kali Linux
192.168.56.1
      │
      │ Host-only Network
      ▼
Windows 11 VM
192.168.56.101
```

Use only authorized testing traffic against your own Windows VM.

When Windows Firewall records sufficient DROP activity, TRINETRA should
detect the behavior.

---

## Expected Detection

```text
Firewall DROP Events
        ↓
Source IP Tracking
        ↓
Destination Port Tracking
        ↓
30 Second Window
        ↓
Threshold Reached
        ↓
Event ID 910
        ↓
CRITICAL
```

The generated event should contain information similar to:

```text
Possible Network Scan Detected

Source:
192.168.56.1

Target:
192.168.56.101

Blocked attempts:
5+

Unique ports:
10+
```

---

# 🚨 Test 8 — Active Security Alert

## Objective

Verify the 60-second active alert mechanism.

When a HIGH or CRITICAL event is detected:

```text
HIGH / CRITICAL EVENT
        ↓
🚨 ACTIVE SECURITY ALERT
        ↓
Threat Information
        ↓
60 Seconds
        ↓
🟢 Alert Disappears
        ↓
📜 History Remains
```

## Expected Dashboard

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

The alert should disappear after approximately 60 seconds.

The event must remain visible in:

```text
📜 Real Windows Event History
```

---

# 📜 Test 9 — Event History

## Objective

Verify that alerts remain stored after the active alert expires.

## Procedure

1. Generate a HIGH or CRITICAL test event.
2. Observe the active alert.
3. Wait approximately 60 seconds.
4. Observe the dashboard again.

## Expected Result

The active alert disappears:

```text
🚨 ACTIVE SECURITY ALERT
        ↓
       OFF
```

But the event remains:

```text
📜 Real Windows Event History
```

This confirms that active alerts and historical events are handled
separately.

---

# 🔁 Test 10 — Duplicate Event Prevention

## Objective

Verify that the same Windows event is not repeatedly added to the
dashboard.

TRINETRA uses Windows:

```text
LogName + RecordId
```

as the event identity.

## Expected Result

The same event should not continuously appear as a new event during
each monitoring cycle.

---

# 📊 Test 11 — Dashboard Statistics

## Objective

Verify that dashboard counters update correctly.

The dashboard displays:

```text
TOTAL EVENTS
HIGH
CRITICAL
HOST
```

## Expected Behavior

When a HIGH event is detected:

```text
HIGH counter
     +
1
```

When a CRITICAL event is detected:

```text
CRITICAL counter
     +
1
```

The TOTAL EVENTS counter should also increase.

---

# 🧪 Test 12 — Complete End-to-End Test

This is the main demonstration test for TRINETRA SOC.

```text
┌─────────────────────┐
│    Kali Linux       │
│ Controlled Testing  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│    Windows 11 VM    │
│                     │
│ Security + Firewall │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│    TRINETRA SOC     │
│       SIEM          │
└──────────┬──────────┘
           │
      ┌────┴─────┐
      ▼          ▼
 Dashboard     ESP8266
      │          │
      ▼       ┌──┴──┐
   🚨 Alert   🔊   💡
      │       Buzzer LED
      ▼
   60 Seconds
      │
      ▼
 Alert Ends
      │
      ▼
 Event History
```

---

# ✅ Test Checklist

| Test                 | Expected Result          | Status |
| -------------------- | ------------------------ | ------ |
| SIEM Startup         | Flask + monitors start   | ⬜      |
| Dashboard            | Dashboard opens          | ⬜      |
| ESP Connection       | ESP8266 connected        | ⬜      |
| ESP TEST             | Buzzer + LED respond     | ⬜      |
| ESP HIGH             | HIGH alert works         | ⬜      |
| ESP CRITICAL         | CRITICAL alert works     | ⬜      |
| Windows Events       | Events collected         | ⬜      |
| Event ID 900         | Critical alert generated | ⬜      |
| Firewall Monitor     | DROP events detected     | ⬜      |
| Event ID 910         | Network scan detected    | ⬜      |
| Active Alert         | 60-second alert shown    | ⬜      |
| Alert Expiration     | Alert disappears         | ⬜      |
| History              | Event remains            | ⬜      |
| Counters             | Statistics update        | ⬜      |
| Duplicate Prevention | Duplicate events avoided | ⬜      |

---

# ⚠️ Safety & Authorization

TRINETRA SOC is intended for educational and authorized cybersecurity
testing.

Only perform security testing against systems and networks that you own
or have explicit permission to test.

For demonstrations, use an isolated VirtualBox Host-only network and
your own Windows virtual machine.

---

# 🛡️ TRINETRA SOC

**Observe. Detect. Alert.**

A lightweight cybersecurity monitoring prototype combining Windows
telemetry, firewall detection, real-time visualization, and physical
security alerts.

```
```
