# Brute Force Detection Using Splunk

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

```text
2025-05-20 10:15:32 LOGIN_FAILED user=john ip=192.168.1.50
2025-05-20 10:15:35 LOGIN_FAILED user=john ip=192.168.1.50
2025-05-20 10:15:40 LOGIN_FAILED user=john ip=192.168.1.50
2025-05-20 10:16:05 LOGIN_SUCCESS user=john ip=192.168.1.50
```

## Data Ingestion
The generated log files were uploaded and indexed in Splunk for analysis and monitoring.

## Detection Logic

### Brute Force Detection Query

```spl
index=main "LOGIN FAILED"
| rex "user=(?<user>\S+)"
| rex "ip=(?<ip>\S+)"
| stats count by user ip
| where count >= 1
| sort - count
```

### Successful Login After Multiple Failures

```spl
index=bruteforce
| stats count(eval(action="LOGIN_FAILED")) as failed_attempts
        count(eval(action="LOGIN_SUCCESS")) as successful_logins
        by user, ip
| where failed_attempts > 10 AND successful_logins > 0
```

## Alert Configuration

### Alert Name
**Brute Force Login Detection**

### Trigger Condition
More than 10 failed login attempts from the same IP address or against the same user account within a specified time window.

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

## Future Improvements
- Integrate threat intelligence feeds
- Add geolocation-based detection
- Implement risk-based alerting
- Automate incident response workflows

## Author
**folajuwon sulaiman**

## License
This project was developed for educational and cybersecurity research purposes in a controlled environment.
