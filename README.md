# Brute-force-detection-splunk
 brute force detection on splunk using self created log file

## Overview
This project demonstrates the detection of brute-force login attacks using Splunk. Custom authentication log files were created to simulate both legitimate and malicious login activity. The logs were ingested into Splunk, analyzed using SPL queries, visualized through dashboards, and monitored with automated alerts for suspicious behavior.

## Project Objectives
- Generate realistic authentication logs for testing.
- Ingest log data into Splunk.
- Detect brute-force attacks using SPL queries.
- Create dashboards for security monitoring.
- Configure automated alerts for rapid incident detection.

## Technologies Used
- Splunk Enterprise
- SPL (Search Processing Language)
- Custom-generated authentication logs
- Security Monitoring & Alerting

## Log Simulation
Custom log files were created to simulate:

- Normal login activity
- Failed login attempts
- Multiple failed login attempts from the same IP address
- Successful logins following repeated failures

### Sample Log Data

2026-04-05 10:05:11 LOGIN FAILED user=admin ip=192.168.1.10
2026-04-05 10:06:15 LOGIN SUCCESS user=john ip=192.168.1.15
2026-04-05 10:07:18 FILE UPLOAD user=john file=project2.zip
2026-04-05 10:08:28 FILE DOWNLOAD user=sarah file=report.pdf 

## Data Ingestion
The generated log files were uploaded and indexed in Splunk for analysis and monitoring.

## Detection Logic

### Brute Force Detection Query

index=main "LOGIN FAILED"
| rex "user=(?<user>\S+)"
| rex "ip=(?<ip>\S+)"
| stats count by user ip
| where count >= 1
| sort - count

## Alert Configuration

### Alert Name
Brute Force Login Detection

### Trigger Condition
The alert is configured to trigger when the search returns more than 0 results. This indicates that at least one user/IP combination has met the brute-force detection threshold.

### Alert Actions
- Generate a Splunk alert
- Notify security analysts
- Log the event for further investigation

### Alert Benefits
- Real-time detection of suspicious authentication activity
- Faster incident response
- Reduced risk of unauthorized access

## Dashboard Features
- Failed login attempts by user
- Failed login attempts by source IP
- Top targeted accounts
- Login success vs failure trends
- Potential brute-force attack indicators

## Results
The project successfully:
- Generated and ingested custom authentication logs
- Detected brute-force attack patterns using SPL
- Created dashboards for visibility and analysis
- Configured automated alerts for real-time threat detection

## Skills Demonstrated
- Security Monitoring
- Threat Detection Engineering
- Splunk Administration
- SPL Query Development
- Log Analysis
- Alert Configuration
- Dashboard Development
- Cybersecurity Operations


## Author
SULAIMAN FOLAJUWON

## License
