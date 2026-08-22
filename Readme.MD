````markdown
# 🛡️ TRINETRA SOC

### Real-Time Windows Security Monitoring & Threat Detection System

TRINETRA SOC is a lightweight Security Operations Center (SOC) prototype designed to monitor Windows security events and firewall activity, detect suspicious behavior, display real-time security alerts, maintain event history, and trigger physical security alerts using an ESP8266.

---

## 🚨 What is TRINETRA SOC?

Windows continuously generates thousands of security and system events. Manually monitoring these logs can make it difficult to identify important security incidents.

**TRINETRA SOC** collects, analyzes, and visualizes important Windows security events and firewall activity in a centralized dashboard.

When a suspicious event is detected, TRINETRA can:

- 🔍 Detect suspicious Windows security events
- 🧱 Monitor Windows Firewall DROP activity
- 🚨 Detect possible network scans
- 📊 Display events in a real-time SOC dashboard
- ⚠️ Classify events as LOW, MEDIUM, HIGH, or CRITICAL
- ⏱️ Display active security alerts for 60 seconds
- 📜 Maintain event history after alerts disappear
- 🔊 Trigger a physical buzzer through ESP8266
- 💡 Trigger a physical LED security alert

---

## 🧠 System Architecture

```text
                         KALI LINUX
                              │
                              │ Controlled Security Testing
                              ▼
                    ┌──────────────────┐
                    │    WINDOWS 11    │
                    │        VM        │
                    └─────────┬────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
             Windows Event Logs   Windows Firewall
                    │                   │
                    └─────────┬─────────┘
                              ▼
                    ┌──────────────────┐
                    │   TRINETRA SOC    │
                    │       SIEM        │
                    └─────────┬────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
             SOC Dashboard          ESP8266
                    │                   │
                    │              ┌────┴────┐
                    │              ▼         ▼
                    │           🔊 Buzzer   💡 LED
                    │
                    ▼
              Event History
````

---

## 🚨 Active Security Alert

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
📜 Event Remains in History
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

The active alert automatically disappears after 60 seconds, while the event remains available in the historical event table.

---

## 🔥 Network Scan Detection

TRINETRA monitors the Windows Firewall log:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

The system analyzes blocked TCP connections and tracks activity from source IP addresses.

### Current Detection Configuration

```text
Detection Window:
30 seconds

Blocked Attempt Threshold:
5 attempts

Unique Destination Port Threshold:
10 ports
```

A network-scan alert is generated when either threshold is reached.

The generated event is:

```text
Event ID: 910
Title: Possible Network Scan Detected
Severity: CRITICAL
```

---

## 🪟 Windows Security Event Detection

TRINETRA monitors selected Windows Security and System events.

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

## 🔌 ESP8266 Physical Alert System

TRINETRA SOC is connected to an ESP8266 through **USB Serial communication**.

```text
TRINETRA SIEM
      │
      │ USB Serial
      │ 115200 Baud
      ▼
   ESP8266
      │
 ┌────┴────┐
 ▼         ▼
🔊 Buzzer  💡 LED
```

### ESP8266 Wiring

```text
D1 / GPIO5   → Buzzer
D5 / GPIO14  → LED
GND          → GND
```

### Supported Commands

```text
CRITICAL
HIGH
STOP
TEST
STATUS
PING
```

### CRITICAL Alert

The ESP8266 produces the configured critical alert pattern for up to 60 seconds.

### HIGH Alert

The ESP8266 produces a shorter alert pattern for HIGH severity events.

---

## 💻 Technologies Used

### Software

* Python
* Flask
* PowerShell
* HTML
* CSS
* JavaScript
* PySerial

### Security Technologies

* Windows Event Viewer
* Windows Security Logs
* Windows System Logs
* Windows Firewall Logs
* Rule-Based Threat Detection
* Network Scan Detection

### Hardware

* ESP8266
* CP2102 USB-to-UART
* Buzzer
* LED

### Testing Environment

* Kali Linux
* Windows 11
* VirtualBox
* Host-only Network

---

## 🌐 Laboratory Network

TRINETRA is designed to be tested in an isolated cybersecurity laboratory.

Example:

```text
Kali Linux
192.168.56.1
      │
      │ VirtualBox Host-Only Network
      │
      ▼
Windows 11 VM
192.168.56.101
```

This allows controlled security testing without directly exposing the test environment to the public Internet.

---

## 🔄 Detection Workflow

```text
Windows Security Event
          │
          ▼
    Event Collection
          │
          ▼
    Event ID Filtering
          │
          ▼
    Severity Classification
          │
          ▼
     Detection Engine
          │
     ┌────┴────┐
     │         │
    HIGH    CRITICAL
     │         │
     └────┬────┘
          ▼
   Active Security Alert
          │
       60 Seconds
          │
          ▼
   Alert Automatically Ends
          │
          ▼
    Event History Remains
```

For firewall activity:

```text
Firewall DROP
      ↓
Source IP
      ↓
Destination IP
      ↓
Destination Port
      ↓
30-Second Activity Window
      ↓
Threshold Detection
      ↓
Event ID 910
      ↓
CRITICAL Alert
      ↓
Dashboard + ESP8266
```

---

## ⭐ Key Features

* 🔍 Real-time Windows event monitoring
* 🧱 Windows Firewall monitoring
* 🚨 Rule-based threat detection
* 🌐 Network scan detection
* 📊 Real-time SOC dashboard
* ⚠️ Severity-based classification
* ⏱️ 60-second active security alerts
* 📜 Persistent event history
* 🔊 Physical buzzer alert
* 💡 Physical LED alert
* 🔌 USB Serial ESP8266 communication
* 🛡️ Duplicate event prevention
* 🧪 Controlled cybersecurity testing environment

---

## 🏆 What Makes TRINETRA SOC Different?

SIEM technology already exists, and TRINETRA SOC does **not** claim to invent SIEM.

The project focuses on building a lightweight SIEM prototype and integrating multiple security components into a single system.

TRINETRA combines:

```text
Windows Security Monitoring
          +
Windows Firewall Monitoring
          +
Custom Detection Rules
          +
Network Scan Detection
          +
Real-Time SOC Dashboard
          +
60-Second Active Alerts
          +
ESP8266 Physical Alerts
```

The key feature is the integration between the software-based SIEM and a physical alert device.

A detected HIGH or CRITICAL security event can simultaneously produce:

```text
🚨 Digital Dashboard Alert
+
🔊 Audible Alert
+
💡 Visual Alert
```

---

## 🧪 Example Use Case

A controlled scan is performed from Kali Linux against the Windows 11 VM.

```text
Kali Linux
     │
     │ Controlled Test
     ▼
Windows Firewall
     │
     │ DROP events
     ▼
TRINETRA SOC
     │
     ├── Detects activity
     │
     ├── Generates Event ID 910
     │
     ├── Creates CRITICAL alert
     │
     ├── Shows dashboard alert
     │
     └── Sends CRITICAL command
                │
                ▼
             ESP8266
                │
             ┌──┴──┐
             ▼     ▼
          Buzzer  LED
```

---

## 📁 Project Structure

```text
trinetra-soc/
│
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
│
├── siem/
│   └── siem.py
│
├── esp8266/
│   └── trinetra_alert.ino
│
├── docs/
│   ├── architecture.md
│   └── screenshots/
│
└── tests/
    └── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/trinetra-soc.git
```

```bash
cd trinetra-soc
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure ESP8266

Update the serial port in `siem.py` according to the Windows COM port assigned to your ESP8266.

Example:

```python
ESP_PORT = "COM3"
ESP_BAUD = 115200
```

### 4. Upload the ESP8266 firmware

Open:

```text
esp8266/trinetra_alert.ino
```

in Arduino IDE and upload it to the ESP8266.

### 5. Run TRINETRA SOC

Run PowerShell as Administrator and execute:

```bash
python siem/siem.py
```

Dashboard:

```text
http://127.0.0.1:5000
```

---

## ⚠️ Security Disclaimer

TRINETRA SOC is an educational cybersecurity project designed for authorized and controlled testing.

Only test systems and networks that you own or have explicit permission to test.

Do not use the testing functionality against unauthorized systems.

---

## 👨‍💻 Author

### Bismaya Guruprasad Panda

**Project:** TRINETRA SOC

**Year:** 2026

---

## 📜 License

This project is released under the MIT License.

See `LICENSE` for details.

```
```
