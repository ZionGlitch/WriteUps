# Enumeration
## Nmap
Ran "Nmap -ST *IP* -p- -T4" to find all possible open ports.
Discovered that Port 22 and Port 80 were open.
Ran "Nmap -sV *IP* -p 22 -T4" and found Port 22 uses OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
Ran "Nmap -sV *IP* -p 80 -T4" and found Port 80 runs Apache httpd 2.4.41 (Ubuntu)
```console
┌─[zionglitch@parrot]─[~]
└──╼ $nmap -sT 10.10.116.209 -p- -T4
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-11 01:51 GMT
Nmap scan report for 10.10.116.209
Host is up (0.23s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 667.45 seconds
┌─[zionglitch@parrot]─[~]
└──╼ $nmap -sV 10.10.116.209 -p 22 -T4
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-11 02:05 GMT
Nmap scan report for 10.10.116.209
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds
┌─[zionglitch@parrot]─[~]
└──╼ $nmap -sV 10.10.116.209 -p 80 -T4
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-11 02:26 GMT
Nmap scan report for 10.10.116.209
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.09 seconds
```
# Exploitation
Opening Metasploit and searching for any exploits did not result in any findings.
Next, went to the webpage of the IP, nothing of interest was found on any of the pages, and neither in the Source Code.
Clicking on "Merchant Central" allows us to create a login.
Basic SQL Injection did not work here.
We created an account and logged in.
Majority of the  pages here did not work, but an Profile/Edit Profile page revealed an admin email of ```admin@sky.thm```

Using this email as the username, and running basic SQL Injection on the password did not work.
We logged back in as the user we created and noticed a reset user field, this allows us to reset the password for our account, without requiring the previous password. However, the username field is grayed out and did not allow us to change it.

We launched burp suite and used Proxy/Intercept to intercept the POST message of when we type in the new password. Sure enough, Burp Suite intercepted the POST message, and we were able to change the username field to ```admin@sky.thm``` and the password to ```password```

We logged out of our account and sure enough were able to login as the admin. Now it was time to go back to the terminal and see if we can SSH with these new credentials.

Sadly, it did not work.
```console
┌─[zionglitch@parrot]─[~]
└──╼ $ssh admin@sky.thm@10.10.105.174
The authenticity of host '10.10.105.174 (10.10.105.174)' can't be established.
ECDSA key fingerprint is SHA256:zSoCEcBBY73hNL9ItPA4CnB/405/W6GQYsl94qRMkOo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.105.174' (ECDSA) to the list of known hosts.
admin@sky.thm@10.10.105.174's password: 
Permission denied, please try again.
admin@sky.thm@10.10.105.174's password: 
Permission denied, please try again.
admin@sky.thm@10.10.105.174's password: 

┌─[✗]─[zionglitch@parrot]─[~]
└──╼ $ssh admin@10.10.105.174
admin@10.10.105.174's password: 
Permission denied, please try again.
admin@10.10.105.174's password: 
```
