![intro](https://github.com/user-attachments/assets/d3499a97-8b5a-4005-8d02-76492450fbc6)
![intro2](https://github.com/user-attachments/assets/5526b3d0-e823-40b4-b8f0-eb83ba319a99)

# tryhackme-Lookup

This is a walkthrough for the tryhackme CTF White Lookup. I will not provide any flags or passwords as this is intended to be used as a guide. 

## Scanning/Reconnaissance

First off, let's store the target IP as a variable for easy access.

Command: export ip=xx.xx.xx.xx

Next, let's run an nmap scan on the target IP:
```bash
nmap -sV -sC -A -v $ip -oN nmap.txt
```

Command break down:

-sV

Service Version Detection: This option enables version detection, which attempts to determine the version of the software running on open ports. For example, it might identify an HTTP server as Apache with a specific version.
-sC

Default Scripts: This option runs a collection of default NSE (Nmap Scripting Engine) scripts that are commonly useful. These scripts perform various functions like checking for vulnerabilities, gathering additional information, and identifying open services. They’re a good starting point for gathering basic information about a host.
-A

Aggressive Scan: This option enables several scans at once. It combines OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute (--traceroute). It’s useful for a comprehensive scan but can be intrusive and time-consuming.
-v

Verbose Mode: Enables verbose output, which provides more detailed information about the scan’s progress and results.
$ip

Target IP: This is a placeholder for the target IP address you want to scan. In practice, replace $ip with the actual IP of the machine you are targeting.
-oN

Output in Normal Format: This option saves the scan results in a plain text file format. After -oN, specify a filename where you want to store th
