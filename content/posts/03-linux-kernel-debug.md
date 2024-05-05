---
title: "Quick Linux Kernel debug with QEMU, GDB and U-ROOT"
date: 2022-02-14T17:07:01+02:00
draft: false
toc: false
images:
tags:
  - linux
  - kernel
  - qemu
  - gdb
  - u-root
  - debugging
---

When I want to harness with the Kernel, e.g., to play with some module I wrote, or just maybe learning something new about its internals I usually relay on some quick tricks to bring up a small environment to play with.

The first thing is I do is reusing the host kernel of my favorite distro: Fedora (unless some upstream feature I want to play with is not there and in that case I grab directly the sources from kernel.org building a custom one).

Second in order to have a minimal userspace I use U-ROOT to quickly build an initramfs.

```bash
GO111MODULE=off ~/go/bin/u-root -build=gbb -o initramfs
```

Third in order to get support for debugging symbols I get the kernel-debuginfo package matching the host kernel, so I have both vmlinux and modules completely unstripped.

In order to run in QEMU:

```bash
qemu-system-x86_64 -kernel /boot/vmlinuz-5.16.8-200.fc35.x86_64 -enable-kvm -smp 2 -m 2048M -s -S -initrd initramfs -append "nokaslr"
```

The above command will run QEMU with the specified kernel and provides it an initramfs. The `-s -S` switch will tell QEMU to freeze on startup and start waiting for a GDB connection on port 1234. Also do not forget to append `nokaslr` to the kernel cmdline otherwise GDB later will not be able to solve symbols addresses.

Then we can open another shell and connect to QEMU using GDB in order to start a debugging session:

```bash
gdb -q /usr/lib/debug/lib/modules/5.16.8-200.fc35.x86_64/vmlinux
pwndbg> set architecture i386:x86-64
The target architecture is set to "i386:x86-64".
pwndbg> target remote :1234
Remote debugging using :1234
pwndbg> hbreak start_kernel
Hardware assisted breakpoint 1 at 0xffffffff836c1e57: file init/main.c, line 925.
pwndbg> c
Continuing.
```

![gdb](/kernel_debugging.webp)

In the preceeding commands we first open GDB and provide the unstripped vmlinux image that comes with kernel-debuginfo package, then we set the target architecture for the running kernel, and finally put an hardware breakpoint on start_kernel function. Then we issue continue command and as soon as the breakpoint will be accessed execution will break. That’s it.
