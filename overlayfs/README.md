# thm: Kernel vulnerability in Overlayfs CVE-2021-3493

https://tryhackme.com/r/room/overlayfs

## Background:

- Linux namespaces: Linux namespaces essentially are used to provide an isolated view of resources on a host. 

- UnionFS (Union Mount Filesystem): UnionFS is mainly used on Linux and allows files and directories of distinct filesystems to be overlaid and with it form a single coherent file system. Union mounting is a way of combining multiple directories into one that appears to contain their combined contents.

- Overlayfs: Overlayfs is a union mount filesystem implementation for Linux. It combines multiple different underlying mount points into one, resulting in a single directory structure that contains underlying files and sub-directories from all sources. Overlayfs combine upper and lower filesystem into the same namespace. The change happens on the upper filesystem.

- Lower dir: The lower directory can be read-only or could be an overlay itself.

- Upper dir: The upper directory is normally writable. It is the top dir. When a process reads a file (READ), overlayfs checks if the file is in the upper dir, if not, it checks the lower dir. 

- Workdir: The workdir is used to prepare files as they are switched between the layers.
```
$ mount -t overlay overlay -o lowerdir=/lower,upperdir=/upper,workdir=/work /merged
```

- `Cap_convert_nscap`: it basically checks the permission of the namespace.
	
## Analysis: 	

The bug is in how OverlayFS handled the mounting process. Specifically, it didn't properly enforce permission checks when a user requested certain types of mounts.

An attacker could exploit this by creating a special mount request that abused the flawed permission checks. This allowed the attacker to mount a filesystem in a way that should not have been allowed.

By manipulating the mount in this way, the attacker could gain access to files and directories with elevated privileges. Essentially, the attacker could perform actions as if they were a more privileged user, such as root.

- Linux capabilities: Linux supports file capabilities stored in extended file attributes that work similarly to setuid-bit, but can be more fine-grained. A simplified procedure for setting file capabilities in pseudo-code looks like this:
```
setxattr(...):
	if cap_convert_nscap(...) is not OK:
    		then fail
	vfs_setxattr(...)
```

The important call is `cap_convert_nscap`, which checks permissions with respect to namespaces. 

When file capabilities are set within a user’s own namespace and on their own mount, the operation succeeds without issue because the user has the necessary permissions. The problem arises when OverlayFS forwards this operation to the underlying filesystem: it invokes `vfs_setxattr` but bypasses the checks in `cap_convert_nscap`. This behavior is also referred to as namespace escaping.
This allows the user to set arbitrary capabilities on files in the outer namespace/mount, where they will also be applied during execution.

In Linux 5.11 the call to `cap_convert_nscap` was moved into `vfs_setxattr`, so it is no longer vulnerable.

## TL;DR

OverlayFS allowed privileged file-capability xattrs to be written from inside a user namespace because it forwarded `vfs_setxattr()` to the backing fs without performing the needed `cap_convert_nscap()` check, enabling namespace escape → local privilege escalation.


team, S. S. D. technical. (2022, November 23). SSD Advisory – overlayfs PE. SSD Secure Disclosure. https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/
