---
title: "Intro to Seccomp"
date: 2023-01-17
tags:
  - linux
  - security
  - applications
categories:
  - security
  - series
---

Whenever we run a program on our machine, it runs with the same privileges as the user that started it. This is a problem, because it means that if we run a program that has a bug in it, if exploited, that bug can be used to compromise the whole machine. This is why it is important to run programs with the least amount of privileges possible.

One way to do this is to use a sandbox. A sandbox is a program that runs another program, but with a limited set of privileges. This is a good way to run untrusted code, because if the untrusted code exploits a bug, it can only do so much damage. The sandbox can also be used to limit the resources that the untrusted code can use, such as the amount of memory it can use, or the amount of CPU time it can use.

## What is Seccomp?
On Linux and in general on other operating systems too, a program invokes system calls in order to request services from the operating system. For example, if a program wants to read a file, it will make a system call to the operating system to do so. If a program wants to open a socket, it will make a system call to the operating system to do so. If a program wants to print something to the screen, it will make a system call to the operating system to do so.

A program which presents a bug that allows an attacker to divert the program’s control flow to an attacker-controlled location is called a “code injection” vulnerability. This is a very serious vulnerability, because it means that the attacker can run arbitrary code on the machine. This is why it is important to run programs with the least amount of privileges possible. An attacker can then use such a vulnerability to invoke system calls that the program would have not been able to invoke, and thus make the program do things that it would not have been able to do otherwise.

Quoting the [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) Linux man pages:
```
The seccomp() system call operates on the Secure Computing (seccomp) state of the calling process.
```

Seccomp is a Linux kernel feature that allows a program to limit the set of system calls that it can invoke. Suppose that we
have a program that needs to read a file, but we don’t want it to be able to open a socket. We can use Seccomp to tell the kernel that the program is only allowed to invoke the read system call, and not the socket system call. If the program tries to invoke the socket system call, the kernel will return an error to the program, and the program will be terminated.

## How does Seccomp work?
Seccomp utilizes [BPF](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) (Berkeley Packet Filter) to filter system calls. BPF is a bytecode-based virtual machine that is used to filter packets in the Linux kernel. Seccomp uses BPF to filter system calls. The BPF program is executed by the kernel every time a system call is invoked. The BPF program can then decide whether to allow the system call or not. Notice that the BPF program is jited by the kernel if `CONFIG_BPF_JIT` is enabled. This means that it gets translated into machine code, and thus it runs very fast.

## How to use Seccomp?
Following is the signature of the seccomp system call:
```c
int seccomp(unsigned int operation, unsigned int flags, void *args);
```

The operation argument specifies the operation to perform. The flags argument specifies the flags to use. The args argument specifies the arguments to use.

The operation argument we’re interested in is `SECCOMP_SET_MODE_FILTER`. This operation sets the seccomp filter for the calling process. We’re going to ignore the flags for now and focus on the args argument.

The args argument is a pointer to a `struct sock_fprog` structure. This structure contains a pointer to a BPF program, and the length of the BPF program. The BPF program is an array of `struct sock_filter` structures. Each `struct sock_filter` structure contains a BPF instruction.

When our program executes a syscall the kernel uses as an argument to the BPF program a pointer to a `struct seccomp_data` structure. This structure contains information about the system call that is being invoked. The BPF program can use this information to decide whether to allow the system call or not.

The `struct seccomp_data` structure has the following fields:
```c
struct seccomp_data {
    int nr;                     /* System call number */
    __u32 arch;                 /* AUDIT_ARCH_* value */
    __u64 instruction_pointer;  /* Instruction pointer */
    __u64 args[6];              /* Arguments to the system call */
};
```

The nr field contains the system call number. The `arch` field contains the architecture of the system call. The `instruction_pointer` field contains the instruction pointer of the system call. The args field contains the arguments to the system call.

The `seccomp` manual suggest to verify the architecture of the system call before allowing it. This is done by checking the arch field of the `struct seccomp_data` structure. If the architecture is not the one we expect, we can kill the process by returning `SECCOMP_RET_KILL` from the BPF program. This is because based on the architecture syscall numbers are different. For example, the `read` system call on `x86` has a syscall number of `3`, but on `x86_64` it has a syscall number of `0`. If we don’t check the architecture, we might allow the read system call on `x86`, but not on `x86_64`, and vice versa.

Bare also in mind that multiple filters can be installed. Filters are executed in reverse order in regards to their addition. This means that the last filter added will be executed first.

## Example 1 – Allow only the read system call
In the following example we’re going to allow only the `read` system call. We’re going to use the `SECCOMP_RET_ALLOW` action to allow the system call, and the `SECCOMP_RET_KILL` action to kill the process if the system call is not allowed. This first example will use the raw seccomp system call. We’ll see later that we can use libseccomp to make this easier.

```c
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    // This is a buffer that we will read into.
    char buf[32];

    struct sock_filter filter[] = {
        /* Load architecture into accumulator register. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        /* Check if the architecture is x86_64. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        /* Kill the process if architecture does not match*/
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        /* Load the system call number. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        /* Check if the system call is `read`. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        /* Allow the system call. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* Kill the process. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl(PR_SET_SECCOMP) failed");
        return 1;
    }

    read(0, buf, 4);

    // after read this program will fail...

    return 0;
}
```
Before executing let’s break down previous code and see what it does. First we create a BPF program. The BPF program is an array of `struct sock_filter` structures. Each struct sock_filter structure contains a BPF instruction.

In order to write the program in an “high level representation” we use some macros available in the `linux/filter.h` header file. The `BPF_STMT` macro is used to create a `struct sock_filter` structure from a BPF instruction which represents a statement, in this case a load operation. The `BPF_JUMP` macro is used to create a `struct sock_filter` structure from BPF instruction which represents a jump.

For example:

```c
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
```
This instruction loads the architecture of the system call into the accumulator register. The `BPF_LD` macro is used to specify that this is a load operation. The `BPF_W` macro is used to specify that the load operation is a 32-bit load operation. The `BPF_ABS` macro is used to specify that the load operation is an absolute load operation. The `offsetof(struct seccomp_data, arch)` macro is used to specify the offset of the arch field of the `struct seccomp_data` structure.

A `struct sock_filter` structure contains the following fields:

```c
struct sock_filter {
    __u16 code;     /* Actual filter code */
    __u8 jt;        /* Jump true */
    __u8 jf;        /* Jump false */
    __u32 k;        /* Generic multiuse field */
};
```

If we should translate the `sock_filter[]` array above to BPF instructions it would look like this:
```c
ld [4]                      # Load the architecture of the system call into the accumulator register.
jeq #0xc000003e, 1, 0       # Check if the architecture is x86_64.
ret #0x00000000             # Kill the process if architecture does not match.
ld [0]                      # Load the system call number.
jeq #0x00000000, 0, 1       # Check if the system call is `read`.
ret #0x7fff0000             # Allow the system call.
ret #0x00000000             # Kill the process.
```
After we created the `sock_filter[]` array we create a `struct sock_fprog` structure. The `struct sock_fprog` structure contains the following fields:
```c
struct sock_fprog {
    unsigned short len;
    struct sock_filter *filter;
};
```

The `len` field contains the number of BPF instructions in the `filter` field. The `filter` field contains a pointer to the BPF instructions.

We then invoke a `prctl(2)` syscall to set the `NO_NEW_PRIVS` flag. The `NO_NEW_PRIVS` flag prevents the process from gaining new privileges. Then with another `prctl(2)` syscall we set the seccomp filter. The `SECCOMP_MODE_FILTER` flag specifies that we want to set a seccomp filter. The &prog argument specifies the BPF program that we want to use.

Since we allowed the `read(2)` syscall we try to use it just after we set the seccomp filter. Then if you read the code above carefully I’ve left a comment telling that the program will fail to return 0 just after the read syscall.

Let’s see what happens, first we compile the program:

```c
$ gcc -o example_1 example_1.c
```

Then we run it:

```c
./example_1
aaaa
fish: Job 1, './example_1' terminated by signal SIGSYS (Bad system call)
```

As you can see the program failed with a `SIGSYS` signal. Despite we were able to read 4 bytes from the standard input the program failed. Lets `strace` the program:

```c
...snip...
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=7, filter=0x7fffd3c68b40}) = 0
read(0, aaaa
"aaa", 3)                       = 3
exit_group(0)                           = 231
+++ killed by SIGSYS (core dumped) +++
fish: Job 1, 'strace ./example_1' terminated by signal SIGSYS (Bad system call)
```

It seems our program is failing right after the `read(2)` syscall. That’s because our BPF program allows just the `read(2)`syscall, but of course a program to terminate itself needs to call `exit_group(2)` syscall. So we need to allow the `exit_group(2)` syscall too. Let’s modify our BPF program:

```c
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char buf[4];
    struct sock_filter filter[] = {
        /* Load architecture. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        /* Check if architecture is x86_64. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        /* Kill the process if architecture does not match. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        /* Load system call number. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        /* Check if system call is read. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        /* Allow the system call. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* Check if system call is exit_group. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        /* Allow the system call. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* Kill the process. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl(PR_SET_SECCOMP) failed");
        return 1;
    }

    read(0, buf, 4);

    return 0;
}
```

Now if we strace again our program we can see that it is able to read 4 bytes from the standard input and then it terminates correctly:

```c
...snip...
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=9, filter=0x7ffe48c7a070}) = 0
read(0, aaaa
"aaaa", 4)                      = 4
exit_group(0)                           = ?
+++ exited with 0 +++
```
So here’s a quicktip, man pages for `seccomp(2)` suggest to define a white lists of syscalls instead of a black list. This is because a black list can be easily miss some syscalls and this can lead to a security issue. So if you want to use a seccomp filter I suggest to use a white list instead of a black list. Of course to use a white list you need to know all the syscalls that you need to allow. This is not always easy, but if you are writing a program that needs to use a seccomp filter you could use strace to find out all the syscalls that your program needs to use.

For example the following `strace` command can be used to find out all the syscalls that the `ls` command needs to use:

```bash
strace -c ls
...snip...
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 22.82    0.000034           1        22           mmap
 13.42    0.000020           2         8           mprotect
 10.07    0.000015           2         7           openat
  6.71    0.000010           5         2           getdents64
  6.04    0.000009           1         9           close
  6.04    0.000009           1         8           newfstatat
  4.70    0.000007           7         1           munmap
  4.70    0.000007           3         2           statfs
  4.70    0.000007           1         6         4 prctl
  2.68    0.000004           4         1           write
  2.68    0.000004           1         3           brk
  2.68    0.000004           2         2           ioctl
  2.01    0.000003           1         2           pread64
  2.01    0.000003           1         2         1 access
  1.34    0.000002           0         4           read
  1.34    0.000002           1         2         1 arch_prctl
  1.34    0.000002           2         1           set_tid_address
  1.34    0.000002           2         1           set_robust_list
  1.34    0.000002           2         1           prlimit64
  1.34    0.000002           2         1           rseq
  0.67    0.000001           1         1           getrandom
  0.00    0.000000           0         1           execve
------ ----------- ----------- --------- --------- ----------------
100.00    0.000149           1        87         6 total
```

Of course while analyzing the output of `strace` you need to take into account that some syscalls are used by dynamic loader.Since the dynamic loader at some point passes the control to the main of your program you should allow just syscalls that your program makes use after the seccomp filter is set.

## Using libseccomp
You may have noticed that the code of the previous example is quite verbose. To make the code more readable and to avoid some errors you can use the `libseccomp` library. The `libseccomp` library provides a high level API to set a seccomp filter. The following example is the same as the previous one but it uses the `libseccomp` library:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/prctl.h>

int main(int argc, char *argv[])
{
    scmp_filter_ctx ctx;
    char buf[4];

    // set no_new_privs
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl failed");
        return 1;
    }

   // Create a new seccomp filter context. 
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        perror("seccomp_init failed");
        return 1;
    }

    // Add the syscalls that we want to allow to the seccomp filter context.
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) {
        perror("seccomp_rule_add failed");
        return 1;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) {
        perror("seccomp_rule_add failed");
        return 1;
    }

    // Load the seccomp filter context.
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load failed");
        return 1;
    }

    // Read 4 bytes from the standard input.
    read(0, buf, 4);

    // Release the seccomp filter context.
    seccomp_release(ctx);

    return 0;
}
```

The code above makes use of `libsecocmp` to set a seccomp filter. The code is much more readable and it is less error prone.
We just create a new seccomp filter context, we add the syscalls that we want to allow to the seccomp filter context and then we load the seccomp filter context. The `seccomp_load` function will set the seccomp filter and it will also release the seccomp filter context.

Notice the use of the macro `SCMP_SYS` to specify the syscall that we want to allow. This macro is used to avoid the use of the syscall number. The syscall number changes from architecture to architecture and it is not portable. The `SCMP_SYS` macro is used to specify the syscall name and the library will translate the syscall name to the syscall number.

In order to compile the previous example you need to link the program with the `libseccomp` library. The following command can be used to compile the previous example:

```bash
gcc -o example_3 example_3.c -lseccomp
```

In order to understand better what our filter does, `libseccomp` provides use with some helper functions that can be used to print the seccomp filter. For example adding the following line of code to the previous example just after we add our rules. will print the filter in a human readable format:

```c
seccomp_export_pfc(ctx, 1);
```

The output of the previous example is the following:

```bash
$ ./example_3
#
# pseudo filter code start
#
# filter for arch x86_64 (3221225534)
if ($arch == 3221225534)
  # filter for syscall "exit_group" (231) [priority: 65535]
  if ($syscall == 231)
    action ALLOW;
  # filter for syscall "read" (0) [priority: 65535]
  if ($syscall == 0)
    action ALLOW;
  # default action
  action KILL;
# invalid architecture action
action KILL;
#
# pseudo filter code end
#
```

As you can see this functionality is very useful to understand what our filter does and could help us to debug our filter in order to understand why it is not working as expected.

## Using libseccomp with Go
The `libseccomp` provides a nice for Go. First we’re going to write a simple program in Go that uses no `libseccomp`. Then we’ll try to understand which syscalls are used by this program. Finally we’ll write a new version of the program that uses the `libseccomp` library to deny all the syscalls that are not used by the program.

```go
package main

import (
    "log"
    "os"
)

func main() {
	// create a new file
	f, err := os.Create("test.txt")
	if err != nil {
		log.Fatal("failed to create file: ", err)
	}

	// write to the file
	if _, err := f.Write([]byte("hello world")); err != nil {
		log.Fatal("failed to write to file: ", err)
	}

	// close the file
	if err := f.Close(); err != nil {
		log.Fatal("failed to close file: ", err)
	}
}
```

Here we’ve a simple program which creates a file.

```bash
# build the program
$ go build -o simple main.go

# now we run the program attached to strace
$ strace -f -c ./simple

strace: Process 424724 attached
strace: Process 424725 attached
strace: Process 424726 attached
strace: Process 424727 attached
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ------------------
 41.70    0.000460          76         6           nanosleep
 28.38    0.000313          31        10         2 futex
  7.71    0.000085          21         4           clone
  7.71    0.000085          42         2           openat
  3.26    0.000036           2        14           rt_sigprocmask
  3.26    0.000036           4         9           gettid
  2.27    0.000025           1        22           mmap
  2.18    0.000024           2        10           sigaltstack
  1.18    0.000013          13         1           write
  0.54    0.000006           2         3           fcntl
  0.54    0.000006           3         2         1 epoll_ctl
  0.45    0.000005           5         1           pipe2
  0.27    0.000003           1         2           close
  0.27    0.000003           3         1           epoll_create1
  0.18    0.000002           2         1           getrlimit
  0.09    0.000001           1         1           setrlimit
  0.00    0.000000           0         1           read
  0.00    0.000000           0       114           rt_sigaction
  0.00    0.000000           0         1           madvise
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         1           sched_getaffinity
------ ----------- ----------- --------- --------- ------------------
100.00    0.001103           5       208         3 total
```

As you can see the program uses a lot of syscalls.

Now let’s try to write a new version of the program that uses the libseccomp-golang library that has a deny all policy by default.

```go
package main

import (
	"log"
	"os"

	seccomp "github.com/seccomp/libseccomp-golang"
)

func main() {

	// create a new filter which kills all the threads in the process
	filter, err := seccomp.NewFilter(seccomp.ActKillProcess)
	if err != nil {
		log.Fatal("failed to create filter: ", err)
	}
	defer filter.Release()

	// set the no new privs bit
	if filter.SetNoNewPrivsBit(true) != nil {
		log.Fatal("failed to set no new privs bit: ", err)
	}

	if filter.Load() != nil {
		log.Fatal("failed to load filter: ", err)
	}

	// create a new file
	f, err := os.Create("test.txt")
	if err != nil {
		log.Fatal("failed to create file: ", err)
	}

	// write to the file
	if _, err := f.Write([]byte("hello world")); err != nil {
		log.Fatal("failed to write to file: ", err)
	}

	// close the file
	if err := f.Close(); err != nil {
		log.Fatal("failed to close file: ", err)
	}
}
```

Lets build the program and run it


```bash
$ ./simple
fish: Job 1, './simple' terminated by signal SIGSYS (Bad system call)
```

Ouch! The program has been killed by the kernel because it tried to use a syscall that is not allowed by the filter. Now let’s try to understand which syscall is not allowed.

```bash
$ strace -f ./simple
...snip...
[pid 426136] openat(AT_FDCWD, "test.txt", O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0666 <unfinished ...>
[pid 426137] <... nanosleep resumed>NULL) = 0
[pid 426137] nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>
[pid 426136] <... openat resumed>)      = 257
[pid 426137] <... nanosleep resumed>NULL) = 35
[pid 426140] <... futex resumed>)       = ?
[pid 426138] <... futex resumed>)       = ?
[pid 426141] <... futex resumed>)       = ?
[pid 426140] +++ killed by SIGSYS (core dumped) +++
[pid 426138] +++ killed by SIGSYS (core dumped) +++
[pid 426141] +++ killed by SIGSYS (core dumped) +++
[pid 426137] +++ killed by SIGSYS (core dumped) +++
[pid 426139] <... futex resumed>)       = ?
[pid 426139] +++ killed by SIGSYS (core dumped) +++
+++ killed by SIGSYS (core dumped) +++
fish: Job 1, 'strace -f ./simple' terminated by signal SIGSYS (Bad system call)
```

As we can see there’s quite few syscall that are not allowed by the filter. Now let’s try to add the syscalls that we need
to the filter from the first output where we `straced` the program without `seccomp`.

```go
package main

import (
	"log"
	"os"

	seccomp "github.com/seccomp/libseccomp-golang"
)

var (
	// string slice of syscall names
	syscalls = []string{
		"nanosleep",
		"futex",
		"clone",
		"openat",
		"rt_sigprocmask",
		"gettid",
		"mmap",
		"sigaltstack",
		"write",
		"fcntl",
		"epoll_ctl",
		"pipe2",
		"close",
		"epoll_create1",
		"getrlimit",
		"setrlimit",
		"read",
		"rt_sigaction",
		"madvise",
		"execve",
		"arch_prctl",
		"sched_getaffinity",
	}
)

func main() {

	// create a new filter which kills all the threads in the process
	filter, err := seccomp.NewFilter(seccomp.ActKillProcess)
	if err != nil {
		log.Fatal("failed to create filter: ", err)
	}
	defer filter.Release()

	// set the no new privs bit
	if filter.SetNoNewPrivsBit(true) != nil {
		log.Fatal("failed to set no new privs bit: ", err)
	}

	// iterate over the syscalls slice and add them to the filter
	for _, syscall := range syscalls {
		// resolve syscall number
		seccompSys, err := seccomp.GetSyscallFromName(syscall)
		if err != nil {
			log.Fatal("failed to get syscall: ", err)
		}

		// add the syscall to the filter
		if filter.AddRule(seccompSys, seccomp.ActAllow) != nil {
			log.Fatal("failed to add rule: ", err)
		}
	}

	if filter.Load() != nil {
		log.Fatal("failed to load filter: ", err)
	}

	// create a new file
	f, err := os.Create("test.txt")
	if err != nil {
		log.Fatal("failed to create file: ", err)
	}

	// write to the file
	if _, err := f.Write([]byte("hello world")); err != nil {
		log.Fatal("failed to write to file: ", err)
	}

	// close the file
	if err := f.Close(); err != nil {
		log.Fatal("failed to close file: ", err)
	}
}
```

As you can see the logic is pretty similar to our first C example, we just iterate over the syscalls slice and add them to the filter.

Now let’s build and run the program.

```bash
./simple 
fish: Job 1, './simple' terminated by signal SIGSYS (Bad system call)
```

…and again we get the same error. Now let’s try to understand which syscall is not allowed.

```bash
$ strace -f ./simple
[pid 427733] exit_group(0)              = 231
```

All right our program after all needs to clean exit, so let’s add the `exit_group` syscall to the filter.

```go
...snip...
var (
	// string slice of syscall names
	syscalls = []string{
		"nanosleep",
		"futex",
		"clone",
		"openat",
		"rt_sigprocmask",
		"gettid",
		"mmap",
		"sigaltstack",
		"write",
		"fcntl",
		"epoll_ctl",
		"pipe2",
		"close",
		"epoll_create1",
		"getrlimit",
		"setrlimit",
		"read",
		"rt_sigaction",
		"madvise",
		"execve",
		"arch_prctl",
		"sched_getaffinity",
	}
)
...snip...
```

Now let’s build and run the program.

```bash
$ ./simple
$ cat test.txt 
hello world⏎
```

And here we go, we have a working program that is now seccomp enabled.
There’s also other syscalls that we could remove from the filter, but I’ll leave that as an exercise for the reader.
Hint: `strace` the program and try to understand which syscall is not needed, for example `arch_prctl` is not needed because it used by the loader, and execve is not needed because we are not executing any other program, it is used by the loader to execute the program.

## Seccomp in Rust
Here’s the same example in Rust, using the [libseccomp](https://crates.io/crates/libseccomp) crate.

```rust
use std::{fs::File, io::Write};

use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};

fn main() {
    // create a new filter
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::KillProcess).unwrap();

    // add architecture to filter
    let rule_openat_sys = ScmpSyscall::from_name("openat").unwrap();
    let rule_write_sys = ScmpSyscall::from_name("write").unwrap();
    let rule_fsync_sys = ScmpSyscall::from_name("fsync").unwrap();
    let rule_close_sys = ScmpSyscall::from_name("close").unwrap();
    let rule_sigaltstack_sys = ScmpSyscall::from_name("sigaltstack").unwrap();
    let rule_munmap_sys = ScmpSyscall::from_name("munmap").unwrap();
    let rule_exit_group_sys = ScmpSyscall::from_name("exit_group").unwrap();

    filter.add_rule(ScmpAction::Allow, rule_openat_sys).unwrap();
    filter.add_rule(ScmpAction::Allow, rule_write_sys).unwrap();
    filter.add_rule(ScmpAction::Allow, rule_fsync_sys).unwrap();
    filter.add_rule(ScmpAction::Allow, rule_close_sys).unwrap();
    filter.add_rule(ScmpAction::Allow, rule_sigaltstack_sys).unwrap();
    filter.add_rule(ScmpAction::Allow, rule_munmap_sys).unwrap();
    filter.add_rule(ScmpAction::Allow, rule_exit_group_sys).unwrap();

    filter.load().unwrap();

    // create a file
    let mut file = File::create("foo.txt").unwrap();

    // write some content
    file.write_all(b"Hello, world!").unwrap();

    // sync content
    file.sync_all().unwrap();
}
```

Previous example is straightforward and pretty similar to C and Go ones. Of course used syscalls vary based on the language, since Go runtime uses some syscalls that are not used by Rust. Bare also in mind that while writing code we often need to use more than one library, and each library may use different syscalls, so you may need to add more syscalls to the filter.

## Bonus: where my filter lives?
In this example we’re going to use drgn to inspect the filter that we’ve just added to the process. Drgn is a debugger which allows you to inspect the kernel and user space, and it’s written in Python.

```bash
# first we start our libseccomp example program in gdb
# and put a breakpoint just after the seccomp filter is loaded
# (notice we compile the program with debugging symbols)
$ gcc -o example_3 example_3.c -lseccomp -ggdb2
$ gdb -q ./example_3 
pwndbg> b example_3.c:48
Breakpoint 1 at 0x4012be: file example_3.c, line 48.
pwndbg> r
...snip...
In file: .../seccomp/example_3.c
   43         perror("seccomp_load failed");
   44         return 1;
   45     }
   46 
   47     // Read 4 bytes from the standard input.
 ► 48     read(0, buf, 4);
   49 
   50     // Release the seccomp filter context.
   51     seccomp_release(ctx);
   52 
   53     return 0;
...snip...

pwndbg> procinfo
exe        '.../seccomp/example_3'
pid        445243
tid        445243
selinux    unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
ppid       445170
uid        [1000, 1000, 1000, 1000]
gid        [1000, 1000, 1000, 1000]
groups     [10, 973, 1000]
fd[0]      /dev/pts/1
fd[1]      /dev/pts/1
fd[2]      /dev/pts/1
```

In another terminal we start [drgn](https://github.com/osandov/drgn) and attach to the process:

```bash
$ sudo drgn
# here we use the find_task function to get the task_struct
# Linux kernel uses the task_struct to refer to a process
>>> t = find_task(prog, 445243)
>>> t.type_
struct task_struct *
...
# as you can see the task_struct has a seccomp field
>>> prog.type("struct task_struct")
struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
...snipped...
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
...snipped...
}
# we're interested into the filter which is a pointer to a seccomp_filter struct
>>> t.seccomp
(struct seccomp){
	.mode = (int)2,
	.filter_count = (atomic_t){
		.counter = (int)1,
	},
	.filter = (struct seccomp_filter *)0xffff922e3529c300,
}
# we're near... here there's the pointer bpf_prog structure
>>> t.seccomp.filter
*(struct seccomp_filter *)0xffff922e3529c300 = {
...snipped...
	.prev = (struct seccomp_filter *)0x0,
	.prog = (struct bpf_prog *)0xffffb3e5089c5000,
...snipped...
}
# great! here is it!
>>> t.seccomp.filter.prog
*(struct bpf_prog *)0xffffb3e5089c5000 = {
	.pages = (u16)1,
	.jited = (u16)1,                                // <-- this means the filter is JITed
	.jit_requested = (u16)1,
...snipped...
	.len = (u32)16,
	.jited_len = (u32)84,                           // <-- this is the size of the filter jited code
	.tag = (u8 [8]){},
	.stats = (struct bpf_prog_stats *)0x41b40fc0f150,
	.active = (int *)0x41b40fc03218,
	.bpf_func = (unsigned int (*)(const void *, const struct bpf_insn *))0xffffffffc030d8e0,    // <-- this is the address of the filter jited code
...snipped...
}
# so what do we do now? we can use the bpf_func address to dump the filter code
# and disassemble it.
# we know the filter is 84 bytes long, so we can read 84 bytes from the address
>>> buf = prog.read(0xffffffffc030d8e0, 84)
# we use capstone library to disassemble the code
>>> from capstone import *
>>> md = Cs(CS_ARCH_X86, CS_MODE_64)
>>> for i in md.disasm(buf, 0x0):
...     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
... 
0x0:	nop	dword ptr [rax + rax]       <-- this is the first instruction of the filter a NOOP
0x5:	push	rbp                     <-- this saves rbp register which will be used later to index the stack
0x6:	mov	rbp, rsp                    <-- this stores the stack pointer value to rbp
0x9:	push	rbx                     <-- save rbp
0xa:	push	r13                     <-- save r13
0xc:	xor	eax, eax                    <-- set eax to 0
0xe:	xor	r13d, r13d                  <-- set r13 to 0
0x11:	mov	rbx, rdi                    <-- rdi points to seccomp_data struct filled with current syscall data
0x14:	mov	eax, dword ptr [rbx + 4]    <-- eax is set to arch field of seccomp_data struct
0x17:	mov	esi, 0xc000003e             <-- set rsi to 0xc000003e (x86_64)
0x1c:	cmp	rax, rsi                    <-- compare eax with rsi
0x1f:	jne	0x50                        <-- if eax != rsi jump to 0x50 and return 0 forbidding the syscall
0x21:	mov	eax, dword ptr [rbx]        <-- eax is set to nr field of seccomp_data struct
0x24:	cmp	rax, 0x40000000             <-- compare eax with 0x40000000 __X32_SYSCALL_BIT if above 32 bit syscall, if below 64 bit syscall
0x2b:	jb	0x37                        <-- if eax < 0x40000000 jump to 0x37  
0x2d:	mov	esi, 0xffffffff             <-- set rsi to 0xffffffff (-1)
0x32:	cmp	rax, rsi                    <-- compare rax with rsi
0x35:	jne	0x50                        <-- if rax != rsi jump to 0x50 and return 0 forbidding the syscall
0x37:	test	rax, rax                <-- test rax with rax is shorthand for cmp rax, 0 -> read syscall number
0x3a:	je	0x45                        <-- if rax == 0 jump to 0x45 and allow the read syscall
0x3c:	cmp	rax, 0xe7                   <-- compare rax with 0xe7 -> exit_group syscall
0x43:	jne	0x50                        <-- if rax != 0xe7 jump to 0x50 and return 0 forbidding the syscall
0x45:	mov	eax, 0x7fff0000             <-- set eax to 0x7fff0000
0x4a:	pop	r13                         <-- restore r13
0x4c:	pop	rbx                         <-- restore rbx
0x4d:	leave	                        <-- restore rbp
0x4e:	ret	                            <-- return 0x7fff0000 allowing the syscall
0x4f:	int3	                        <-- not sure why this int3 is here, probably to trap the process for some reason
0x50:	xor	eax, eax                    <-- set eax to 0
0x52:	jmp	0x4a                        <-- jump to 0x4a and return 0 forbidding the syscall
```

## Conclusion
This post was just an introduction to seccomp and how to use it. I hope it will be useful for someone. We started with the basics of seccomp, then we saw how to use it in various programming languages and finally we took a look at how it works on the kernel side. I hope you enjoyed it and learned something new. Reader is encouraged to read documentation an references provided at the end of this post and try to write a seccomp filter for a syscall and see how it works.

### References

* [Seccomp](https://en.wikipedia.org/wiki/Seccomp)
* [Seccomp filter](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
* [Seccomp man](https://man7.org/linux/man-pages/man2/seccomp.2.html)
* [Seccomp C library](https://github.com/seccomp/libseccomp)
* [Seccomp Go library](https://github.com/seccomp/libseccomp-golang)
* [Seccomp Rust library](https://crates.io/crates/libseccomp)
