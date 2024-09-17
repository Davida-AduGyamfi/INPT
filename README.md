#  Internal Network Penetration Test


Submitted by:  
Davida Oforiwaa Adu Gyamfi 


For: D & D Enterprise

Virtual Infosec Africa, 2024

---

## Table of Contents
1. [Testing Methodology](#testing-methodology)
2. [Summary of Findings](#summary-of-findings)
3. [Detailed Findings](#detailed-findings)
4. [CVSS v3.0 Reference Table](#cvss-v30-reference-table)

---


## Testing Methodology
The test started with a host discovery to find online devices (hosts) on the network. After the identification of reachable and online hosts, port scanning to find the services these devices are running was done. After the port scan, the vulnerability analysis proceeded. The scope of engagement comprised of an internal network: `10.10.10.0/24` and a domain
name: `https://virtualinfosecafrica.com/.` A ping scan was done to determine if the hosts on the IP address were reachable i.e `ping 10.10.10.0/24` and ping `virtualinfosecafrica.com`.

Nmap was a useful tool which was used for host discovery. The following commands were used together with nmap to achieve the desired results: `-sL: List Scan - simply list targets to scan`, `-sn: Ping Scan - disable port scan (nmap -sn 10.10.10.0/24)`, `-Pn: Treat all hosts as online -- skip host discovery`. Using the command `nmap -sL 10.10.10.0/24 > targetlist.txt` provided a list of all hosts to be scanned. A total of 256 addresses are received(since we have a subnet mask of 24). After running the scan, 15 hosts were up then the filtered output were saved in a file.

Command: `nmap -sn -iL targetlist.txt | grep -i "nmap scan report" > onlinehost.txt`

![image](https://github.com/user-attachments/assets/de84fa4a-9c00-43ce-a6a0-dd41ecbc114f)

After the host discovery, port scanning was done to identify the services being run by the online hosts and get the opportunity to find vulnerabilities with the services.
The command issued is: `nmap -sV 10.10.10.0/24 -oG nmap_scan_results.gnmap`. `-sV` is used to probe open ports to determine service/version info.

![image](https://github.com/user-attachments/assets/fa8709a5-c0ac-43e6-8df1-2bcf91971a20)

From the output of the port scan, the services being run by the open ports were checked for any relevant vulnerabilities associated with the ports. Below is the results.


## Summary of Findings
| Finding                                        | Severity |
|------------------------------------------------|----------|
| Remote Code Execution Vulnerabilities          | Critical |
| Denial-Of-Service (DOS)                        | Medium   |
| Local Privilege Escalation (LPE)               | High     |
| Stored Cross-Site Scripting (XSS)              | High     |
|Elevation of Privilege                          | Moderate |
| VMWare vCenter Out of Date                     | Moderate |
| IPMI Password Hash Disclosure                  | Moderate |
| SNMP Agent Default Community Name (public)     | Moderate |
| Unauthenticated Access to Printers via HTTP and Telnet | Low     |
| Grandstream HT818 VOIP Gateway Default Credentials | Low     |

## Detailed Findings
### Remote Code Execution Vulnerabilities  
*Current Rating:* Critical 9.8 

### Evidence
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.
CVE-2021-41773	A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.


### Affected Resources
`10.10.10.2, 10.10.10.30, 10.10.10.45, 10.10.10.55`


#### Recommendations
Upgrade the Apache HTTP Server to version 2.4.51 or higher. This version addresses both CVE-2021-41773 and CVE-2021-42013 by providing a complete fix for the path traversal vulnerability.

---

### Denial-Of-Service
*Current Rating:* Medium 4.9

### Evidence
Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).
CVE-2020-14812	Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Locking). Supported versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).


### Affected Resources
10.10.10.5, 10.10.10.40

#### Recommendations
-Consider hardening your server to minimize exposure to such attacks:

-Implement rate-limiting to reduce the effectiveness of DoS attacks.

-Use a web application firewall (WAF) to filter out malformed requests before they reach the server.

-Enable mod_security or similar modules to analyze and block malicious traffic.

---

### Local Privilege Escalation (LPE)
*Current Rating:* High 7.2 

### Evidence
Axeda agent (All versions) and Axeda Desktop Server for Windows (All versions) uses hard-coded credentials for its UltraVNC installation. Successful exploitation of this vulnerability could allow a remote authenticated attacker to take full remote control of the host operating system.
CVE-2022-24750	UltraVNC is a free and open source remote pc access software. A vulnerability has been found in versions prior to 1.3.8.0 in which the DSM plugin module, which allows a local authenticated user to achieve local privilege escalation (LPE) on a vulnerable system. The vulnerability has been fixed to allow loading of plugins from the installed directory. Affected users should upgrade their UltraVNC to 1.3.8.1. Users unable to upgrade should not install and run UltraVNC server as a service. It is advisable to create a scheduled task on a low privilege account to launch WinVNC.exe instead. There are no known workarounds if winvnc needs to be started as a service.


### Affected Resources
10.10.10.50


### Recommendations
Upgrade UltraVNC:
Upgrade to UltraVNC version 1.3.8.1 or later, which includes fixes for the vulnerabilities associated with the DSM plugin module and the hard-coded credentials.
Users should always ensure they are using the latest stable release to mitigate known vulnerabilities.

---

### Stored Cross-Site Scripting (XSS)
*Current Rating:* High 7.4 

### Evidence 
CVE-2024-1331	The Team Members WordPress plugin before 5.3.2 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the author role and above to perform Stored Cross-Site Scripting attacks.CVE-2024-6894	The RD Station plugin for WordPress is vulnerable to Stored Cross-Site Scripting in all versions up to, and including, 5.3.2 due to insufficient input sanitization and output escaping of post metaboxes added by the plugin. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

### Affected Resources
10.10.10.10

#### Recommendations
-Update the Plugin: Ensure the Team Members plugin is updated to version 5.3.2 or later, where the vulnerability is addressed.
-Input Validation: Validate and escape all user input before outputting it on pages or posts.
-Limit User Roles: Review user roles and permissions to restrict access for lower-privileged users.

---


## CVSS v3.0 Reference Table
| Qualitative Rating | CVSS Score   |
|--------------------|--------------|
| None/Informational | N/A          |
| Low                | 0.1 – 3.9    |
| Medium             | 4.0 – 6.9    |
| High               | 7.0 – 8.9    |
| Critical           | 9.0 – 10.0   |
