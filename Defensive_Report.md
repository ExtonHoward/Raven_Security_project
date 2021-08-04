# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

### Network Topology

The following machines were identified on the network:

| Name | Os | IP Address | Purpose |
| :---: | :---: | :---: | :---: | 
| Kali | Debian Kali 5.4.0 | 192.168.1.90 | Attacker Machine |
| ELK | Ubuntu 18.04 | 192.168.1.100 | SIEM |
| Target 1 | Debian GNU/Linux 8 | 192.168.1.110 | Web Server |
| Target 2 | Debian GNU/Linux 8 | 192.168.1.115 | Web Server |

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Network_Topology.png "Network Topology")

### Description of Targets

* The network contained 2 web servers that were vulnerable to attack: Target 1 (192.168.1.110) and Target 2 (192.168.1.115). Target 1 is what is covered and was attacked.

* Target 1 is an Apache web server and has SSH enabled. Ports 22, 80, 111, 139, and 445 were open. Ports 22 and 80 are possible points of entry for the attacker.

### Monitoring the Targets

Scanning Target 1 shows multiple ports open running services.

| Port | Service | Version |
| :---: | :---: | :---: |
| 22 | ssh | OpenSSH 6.7p1 Debian 5+deb8u4 |
| 80 | http | Apache httpd 2.4.10 ((Debian)) |
| 111 | rpcbind | 2-4 (RPC #10000) |
| 139 | netbios-ssn | Netbios Samba 3.x-4.x |
| 445 | netbios-ssn | Netbios Samba 3.x-4.x |

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target1/T1_nmap.JPG "nmap results")

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### Excessive HTTP Errors
Excessive HTTP Errors is implemented as follows:

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Defensive_Report/excessive_http_error_rule.JPG "Excessive HTTP Errors")

  - Metric:
      - **WHEN count() GROUPED OVER top 5 'http.response.status_code'**
  - Threshold:
      - **IS ABOVE 400**
  - Vulnerability Mitigated:
      - **Brute Force/Enumeration**
  - Reliability:
      - **This is a highly reliable alert. An indicator of Brute Force Attacks is a large uptick of http response code 401/Unauthorized.** 

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Defensive_Report/http_errors.JPG "HTTP Errors")

#### HTTP Request Alerts
HTTP Request Alerts is implemented as follows:

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Defensive_Report/http_request_alert_rule.JPG "HTTP Requests Alert")

  - Metric:
      - **WHEN count() OVER all documents**
  - Threshold:
      - **IS ABOVE 1000 FOR THE LAST 5 minutes**
  - Vulnerability Mitigated:
      - **Code Injection, Dos/DDos**
  - Reliability:
      - **This could create false positives. It is moderately reliable as there could be a large amount of legitimate HTTP traffic. However, based upon current traffic, this threshold should be good enough.**

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Defensive_Report/http_request_2.JPG "HTTP Requests")

#### CPU Usage Monitor
CPU Usage Monitor is implemented as follows:

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Defensive_Report/CPU_usage_monitor_rule.JPG "CPU Usage Monitor")

  - Metric:
      - **WHEN max() OF system.process.total.pct OVER all documents**
  - Threshold:
      - **IS ABOVE 0.5 FOR THE LAST 5 MINUITES**
  - Vulnerability Mitigated:
      - **Malicious Software, Applications using too many resources**
  - Reliability:
      - **This is a highly reliable alert as it indicates a program is consuming all the resources or that there could be a malicious actor using the computer.**

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Defensive_Report/cpu2.JPG "CPU Usage")

### Patches ###
- Each alert above pertains to a specific vulnerability/exploit. Recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identified by the alerts above, suggest a patch. E.g., implementing a blocklist is an effective tactic against brute-force attacks. It is not necessary to explain _how_ to implement each patch.

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:

Excessive HTTP Errors
  - Patch: WordPress Hardeing
      - Implement regular upgrades for Wordpress
      - Disable unused Wordpress features
      - Remove Wordpress login pages from being exposed to the internet
  - Why It Works:
      - Updating the program keeps exploits in the wild at bay as they have been (presumably) patched with the latest version of Wordpress
      - Disabling unused Wordpress features prevents sensitive data exposure and stops people from accessing more information that desired
      - The Wordpress login page should only be accessible from the intranet behind a firewall. This prevents people from brute forcing it or using another exploit to gain access
  
- HTTP Request Alerts
  - Patch: Code Injection & DDoS/DoS Hardening
      - Implement HTTP Request limit on web server
      - Implement front & back end input validation
  - Why It Works:
      - limiting HTTP requests can stop oversize requests and prevent the addition of scripts or commands at the end of the URL
      - Front & back end input validation is important because front end will stop most people and backend will stop most more skilled threat actors who are able to bypass front end validation

- CPU Usage Monitor
  - Patch: Virus/Malware Hardening
      - Install or update Antivirus
      - Implement Host Intrusion Detection System (HIDS)
  - Why It Works:
      - Keeping AV up to date means that the AV has the latest signatures of malware and more effectively detect and stop malware on the systems.
      - HIDS detect activity on the device as well as inspect and analyze the internals of the machine. It can also analyze incoming packets for malicious traffic