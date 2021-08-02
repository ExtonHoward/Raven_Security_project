# Raven Security Engagement #
### Offesnive Angagement and Assement of Web Servers ###
#### Author: Exton Howard ####
#### August 5, 2021 ####

## High Level Summary ##

The team was tasked with performing network scans, finding any vulnerabilities that are present and exploitable on Raven Security's Wordpress Web Servers, and then exploiting the vulnerabilities to find the files (flags) that are located on the machines.

## Network Topology ##

| IP | Machine |
| :---: | :---: |
| 192.168.1.1 | Hyper-V |
| 192.168.1.90 | Kali |
| 192.168.1.100 | Elactic Stack (ELK) |
| 192.168.1.110 | Target 1 |
| 192.168.1.115 | Target 2 |

![alt text](/Network_Topology.png "Network Topology")

## Target 1 Engagement ##

Scanned target computer using nmap

'''
nmap -sV -O 192.168.1.110
'''

![alt text]( "nmap results")

Determind this machine is a web server with a series of ports & services open

| Port | Service Version |
| :---: | :---: |
| 22 | OpenSSH 6.7p1 Debian |
| 80 | Apache httpd 2.4.10 |
| 111 | rpc 2-4 |
| 139 | Netbios Samba 3.x-4.x |
| 445 | Netbios Samba 3.x-4.x |

First thing that caught my eye is a web server is up and running. Opened a browser and navigated to 192.168.1.110. Found a webserver with an active page running wordpress. While navigating around the web page, discovered an exposed flag under the footer of the service tab

![alt text]( "Flag 1")

Since this appears to be a poorly configured wordpress site decided to use wpscan to enumerate users and check for vulnerabilities on the wordpress server. 

'''
wpscan --url http://192.168.1.110/wprdpress --enumerate u
'''

![alt text]( "Users with Brute Force Vulnerabilities")

Discovered 2 users, michael and steven, with potential brute force vulnerabilities. Decided to start with michael.

'''
hydra -l michael -P /usr/share/wordlists/rockyou.txt 192.168.1.110 -t 4 ssh
'''

![alt text]( "Hydra")

Discovered michaels password and logged in via ssh. Found a regular user account with no sudo privileges. Looked around to see what was able to be found in this account. Searched for flags & located flag 2 in the /var/www dir.

'''
locate flag
'''

![alt text]( "Flag 2")

Inspected the /var/www/html/ directory and found MySQL database credentials in the wp-config.php file.

![alt text]( "Credentials")

Used mySQL command line tool to inspect the database to see if there was anything interesting, such as a users table that could potentially show passwords. Discovered a table called wp_users that would be the first place to start.

'''
mysql -u root -pREDACTED -D wordpress -e "show tables;"
mysql -u root -pREDACTED -D wordpress -e "select * from wp_users;"
'''

![alt text]( "Users table")

Since there is credentials here, decided to search the remainder of the database to see if there was anything else interesting. Located both Flag 3 and Flag 4 in the wp_posts table

'''
mysql -u root -pREDACTED -D wordpress -e "select * from wp_users;"
'''

![alt text]( "Flag 3 & Flag 4")

Discovered usernames and password hashes in the wp_users table. Since michaels password was previously determined, only copied stevens credentials to the Kali machine. Fired up John the Ripper to get to work on breaking steven's credentials

'''
john hashes.text --wordlist=/usr/share/wordlists/rockyou.txt
'''

![alt text]( "John The Ripper")

With stevens credentials, now used ssh to log in with stevens account. Checked and discovered that steven has sudo privileges without password for python. Following this, immediately executed a python command line code that would allow spawning of a privileged shell.

'''
sudo python -c 'import pty; pty.spawn("/bin/bash")'
'''

![alt text]( "Privilege Escalation to Root")

Changed to '/root' and read out the final flag of flag 4. This step was unneccassary since it was previously found in the database, but is used as proof of escelation. With this level of access, persistence can be established and we have full control of this web server.

![alt text]( "Flag 4 as Root")

