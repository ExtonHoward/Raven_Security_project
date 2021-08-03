# Raven Security Engagement #
### Offensive Engagement and Assessment of Web Servers ###
#### Author: Exton Howard ####
#### August 5, 2021 ####

## High Level Summary ##

The team was tasked with performing network scans, finding any vulnerabilities that are present and exploitable on Raven Security's Wordpress Web Servers, and then exploiting the vulnerabilities to find the files (flags) that are located on the machines.

## Network Topology ##

| IP | Machine |
| :---: | :---: |
| 192.168.1.1 | Hyper-V |
| 192.168.1.90 | Kali |
| 192.168.1.100 | Elastic Stack (ELK) |
| 192.168.1.110 | Target 1 |
| 192.168.1.115 | Target 2 |

![alt text](/Network_Topology.png "Network Topology")

## Target 1 Engagement ##

Scanned target computer using nmap.

```
nmap -sV -O 192.168.1.110
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_nmap.JPG "nmap results")

Determined this machine is a web server with a variety of ports open.

| Port | Service Version |
| :---: | :---: |
| 22 | OpenSSH 6.7p1 Debian |
| 80 | Apache httpd 2.4.10 |
| 111 | rpc 2-4 |
| 139 | Netbios Samba 3.x-4.x |
| 445 | Netbios Samba 3.x-4.x |

First thing that caught my eye is that a web server is up and running. Opened a browser and navigated to 192.168.1.110. Found a web server with an active page running wordpress. While navigating around the web page, discovered an exposed flag under the footer of the service tab.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_flag1_clean.JPG "Flag 1")

Decided to use wpscan to enumerate users and check for vulnerabilities on the wordpress server. 

```
wpscan --url http://192.168.1.110/wprdpress --enumerate u
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_wpscan_brute_force.JPG "Users with Brute Force Vulnerabilities")

Discovered 2 users, michael and steven, with potential brute force vulnerabilities. Decided to start with michael. Attempted to SSH into Target 1 and guess the password amongst a few really simple options. Did not successfully guess within the first 6 tries. Started Hydra with a wordlist to determine login credentials.

```
hydra -l michael -P /usr/share/wordlists/rockyou.txt 192.168.1.110 -t 4 ssh
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_hydra.JPG "Hydra")

Discovered michaels password and logged in via ssh. Found a regular user account with no sudo privileges. Looked around to see what else was in this account. Searched for flags & located flag 2 in the /var/www dir.

```
locate flag
cat /var/www/flag2.txt
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_flag2_clean.JPG "Flag 2")

Inspected the /var/www/html/ directory and found MySQL database credentials in the wp-config.php file.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_mysql_creds.JPG "Credentials")

Used mySQL command line tool to inspect the database to see if there was anything interesting, such as a users table that could potentially show passwords. Discovered a table called wp_users that would be the first place to start.

```
mysql -u root -pPASSWORD_REDACTED -D wordpress -e "show tables;"
mysql -u root -pPASSWORD_REDACTED -D wordpress -e "select * from wp_users;"
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_users_table.JPG "Users table")

Found hashed credentials in the Users table. Decided to search the remainder of the database to see if there was anything else interesting. Located both Flag 3 and Flag 4 in the wp_posts table.

```
mysql -u root -pPASSWORD_REDACTED -D wordpress -e "select * from wp_users;"
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_Flag3_Flag4.JPG "Flag 3 & Flag 4")

Discovered usernames and password hashes in the wp_users table. Since michael's password was previously determined, only copied steven's credentials to the Kali machine. Fired up John the Ripper to get to work on breaking steven's credentials.

```
john hashes.text --wordlist=/usr/share/wordlists/rockyou.txt
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_john.JPG "John The Ripper")

Once steven's credentials were cracked, the team used ssh to log in with steven's account. Checked and discovered that steven has sudo privileges without a password for python. The team executed a python command line script that would allow spawning of a privileged shell.

```
sudo -l
sudo python -c 'import pty; pty.spawn("/bin/bash")'
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_escalation.JPG "Privilege Escalation to Root")

The team now has root access to the machine. Navigated to `/root` directory and read out the final flag of flag 4.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_flag4_root.JPG  "Flag 4 as Root")


## Target 2 Engagement ##

To be added


## Vulnerabilities and Mitigation ##
Several vulnerabilities were discovered during the completeion of this engagement. Target 1 has numerous critical vulnerabilities that should be addressed immediately

### Ports Exposed to the Internet ###
The team discovered that multiple ports on Target 1 that should not have been exposed were exposed to the internet.

Mitigation
* Minimize ports exposed to the internet
* Set strict alarms to alert your SOC on any ports exposed to the internet
* Set an alarm to notify the SOC if more than 25 ports aside from 80 and 443 are scanned in under 5 minutes
* Apply a firewall rule to default-deny all non-whitelisted IP addresses to accessing ports other than port 80 or 443
* If ports other than 80 or 443 must be exposed, enable TCP wrapping and firewall rules that auto-deny any IP that is not specifically whitelisted
* Apply firewall rules to deny ICMP requests and not send responses

### Sensitive Data Exposure ###
During the engagement, the team found Target 1 has a flag exposed on the Wordpress website in the page source code for the service page. This was easily discoverable.

Mitigation
* Remove flag from the source code

### Security Misconfiguration: Brute Force Vulnerability ###
The team found the users of the Target 1 web server did not have account lockouts active for excessive failed lockout attempts.

Mitigation
* Set an alarm to notify the SOC if more than 10 HTTP 401 response codes are on the same account in under 10 minutes
* Set a user policy that locks out the account for 30 minutes after 10 failed login attempts
* Enable 2-factor authentication on all accounts
* Enable a random 1-3 second delay on password validation to slow down any brute force attacks
* If more than 20 failed login attempts from the same IP address occurs sitewide within 10 minutes, blacklist that IP until it can be reviewed

### Outdated Wordpress Version ###
The team discovered an older version of Wordpress on Target 1 with many known vulnerabilities.

Mitigation
* Update Wordpress to the lastest version (as of the time of this report, that is version 5.7.1)

### Unsalted Hashed Passwords ###
The team obtained a password hash during the engagement. An open source tool was able to quickly break the hash and allowed the team to gain login credentials for a privileged account on Target 1

Mitigation
* Restrict files with password hashes to admin level accounts
* Do not have any files that contain password hashes exposed to the internet
* Salt all password hashes

### Weak Passwords ###
The team found that the passwords they were able to Brute Force and the hashed passwords they were able to crack were short and not complex.

Mitigation
* Require all passwords to contain a minimum of 10 characters
* Require all passwords to contain at minimum 1 capital letter
* Require all passwords to contain at minimum 1 special character (!, %, *, etc)
* Require all passwords not be commonly used words, employees names, company names, or in the dictionary


## Conclusion ##

Target 1 had many substantial vulnerabilities. The quickest methods to increase the security of Target 1 is to update to the latest version of Wordpress, close extra ports, and apply account lockouts. 