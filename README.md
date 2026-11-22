# Network Security Analyzer v1.0

### Python-Based Host Network Monitoring and Security Alerting Tool

Network Security Analyzer is a Windows-focused cybersecurity application developed using Python.

The project monitors TCP connections, identifies associated processes, investigates Windows Firewall configurations, compares network activity against a saved baseline, and generates rule-based security alerts.

It was developed as a hands-on cybersecurity learning project focused on Blue Team security monitoring and detection engineering.

## Features

- **TCP Connection Monitoring:** Identifies listening endpoints and established TCP connections.

- **Process Identification:** Associates network connections with running processes.

- **Windows Firewall Investigation:** Retrieves firewall profile information and candidate inbound rules.

- **Network Baseline Monitoring:** Compares current listening services with a previously recorded baseline.

- **Change Detection:** Identifies new listening ports, disappeared ports, and changes to listening services.

- **Security Alert Engine:** Generates structured alerts using predefined detection rules.

- **Alert Prioritization:** Assigns informational, low, or medium investigation priorities.

- **Automated Reporting:** Generates timestamped JSON and TXT security reports.

- **Command-Line Interface:** Supports scanning, baseline management, detailed output, and automated testing.

## Technologies Used

- Python

- psutil

- TCP/IP Networking

- Windows PowerShell

- Windows Defender Firewall

- JSON

- Python argparse

- Python ipaddress

## Installation

**Requirements:** Windows, a compatible Python 3 installation, and pip.

Clone or download this repository.

Open a terminal in the project directory and install the dependency:

```bash

python -m pip install -r requirements.txt

```

## Usage

Run a standard network security analysis:

```bash

python analyzer.py

```

Run a detailed analysis:

```bash

python analyzer.py --verbose

```

Create an initial network baseline:

```bash

python analyzer.py --create-baseline

```

Display baseline information:

```bash

python analyzer.py --baseline-info

```

Run automated detection tests:

```bash

python analyzer.py --self-test

```

Display all available options:

```bash

python analyzer.py --help

```

## Detection Rules

The application includes rules for identifying:

- New loopback-only listening services.

- New non-loopback listening services.

- New listening services with unidentified processes.

- Previously observed listening ports that are no longer present.

- Changes to listening services.

- Expansion of listening addresses beyond loopback interfaces.

Alerts describe observations requiring different levels of investigation.

An alert does not automatically indicate a vulnerability or compromise.

## Testing and Validation

The application includes eight automated checks covering:

1. New listening port detection.

2. Disappeared port detection.

3. Changed listening service detection.

4. Alert priority classification.

5. Detection rule activation.

6. Alert identifier generation.

7. Unchanged baseline comparison.

8. Loopback address classification.

**Test result: 8/8 checks passed.**

A controlled functional test was also performed using a temporary Python HTTP server listening on TCP port 8765.

The application successfully detected the newly listening service, identified its associated Python process, and generated an informational security alert.

## Reporting

The application generates timestamped JSON and TXT reports containing network observations, firewall investigation results, baseline comparisons, and security alerts.

Reports are stored locally in the `reports` directory.

For privacy and security reasons, local reports and baseline files are excluded from version control.

## Limitations

This project is a learning-oriented security monitoring prototype, not a production intrusion detection system.

The application performs point-in-time network inspections rather than continuous monitoring.

Firewall rule findings do not establish actual network reachability.

Detection rules use predefined conditions and do not independently confirm malicious activity.

## Future Improvements

- Continuous network monitoring.

- Improved firewall policy evaluation.

- Configurable detection rules.

- More comprehensive automated tests.

- Enhanced alert correlation.

- Centralized security logging.

- Security dashboards.

## Project Purpose

This project demonstrates practical experience in Python development, TCP/IP networking, Windows security monitoring, baseline analysis, security automation, and rule-based detection engineering.
