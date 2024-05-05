---
title: "Embed and execute from memory with Golang"
date: 2021-06-22T14:33:57+02:00
draft: false
toc: false
images:
tags:
  - linux
  - golang
  - low-level
---

In this post I’ll show how to embed a file into a Golang binary and then how this file will be loaded and executed from memory on Linux with the aid of memfd_create(2) and execveat(2).

Since version 1.16 Golang introduced a nice feature which allows embedding a file or a hierarchy of files into a binary. The embedded content can then be accessed as a string, []byte slice or embed.FS object.

In order to do it will suffice to use the //go:embed file directive, e.g.

```go
//go:embed file.bin
var filePayload []byte
 
func main() {
}
```

Then the content can be accessed as a standard []byte slice variable.

Now, that we know how to embed a file (in our case a binary one), we want to copy it into a memory location and then execute it straight from there. Here Linux offers us two system calls which used in tandem will allow us to do so.

First syscall is memfd_create, is used to create a backed memory file descriptor. Quoting its man page:

```
memfd_create() creates an anonymous file and returns a file descriptor that refers to it. The file behaves like a regular file, and so can be modified, truncated, memory-mapped, and so on. However, unlike a regular file, it lives in RAM and has a volatile backing storage. Once all references to the file are dropped, it is automatically released. Anonymous memory is used for all backing pages of the file. Therefore, files created by memfd_create() have the same semantics as other anonymous memory allocations such as those allocated using mmap(2) with the MAP_ANONYMOUS flag.
```

However since Golang does not exposes this Linux specific syscall into the syscall package it is necessary to craft the code to invoke it using the specifc syscall.Syscall function. Code is however straightforward:

```go
func MemfdCreate(path string) (r1 uintptr, err error) {
    s, err := syscall.BytePtrFromString(path)
    if err != nil {
        return 0, err
    }
 
    r1, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(s)), 0, 0)
 
    if int(r1) == -1 {
        return r1, errno
    }
 
    return r1, nil
}
```

We pass to the function the virtual in memory path for our file, then we get a byte pointer which points to a \0 terminated sequence of bytes and then we feed it to the syscall.Syscall function number 319 a.k.a. memfd_create . That’s it, what we get back if no errors occur, it’s a file descriptor pointing to our in memory backed file.

Now we have to copy the content of our embedded file into that memory location, luckily we’ve to not wrap the write(2) syscall since it is already part of the syscall package. So we can craft a simple function like this:

```go
func CopyToMem(fd uintptr, buf []byte) (err error) {
    _, err = syscall.Write(int(fd), buf)
    if err != nil {
        return err
    }
 
    return nil
}
```

The final step is to execute this file descriptor using execveat for which again we’ve to craft a function using syscall.Syscall in order to invoke it. Basically execveat behaves as execve or differently based on parameters we feed to it. If we supply a file descriptor, then as a path an empty string ("") and as a flag AT_EMPTY_PATH, this combination of parameters will execute directly the file pointed by the file descriptor, and in our specific case an in memory one.

```go
func ExecveAt(fd uintptr) (err error) {
    s, err := syscall.BytePtrFromString("")
    if err != nil {
        return err
    }
    ret, _, errno := syscall.Syscall6(322, fd, uintptr(unsafe.Pointer(s)), 0, 0, 0x1000, 0)
    if int(ret) == -1 {
        return errno
    }
 
    // never hit
    log.Println("should never hit")
    return err
}
```

We gather again a NULL terminated string as a sequence of bytes, in this case an empty string. Then we use the syscall.Syscall6 (notice the name differs since this version of the function accepts up to six parameters in contrast to the previous one which accepts up to three) in order to invoke the execveat (syscall number 322) with our file descriptor as a first parameter, then the empty NULL terminated string, then we skip argv[] and envp[] (we just don’t need them for the purpose of this example since our embedded binary accepts no arguments) and finally we supply 0x1000 which is the value for AT_EMPTY_PATH. Of course as for execve if this call succeeds the program won’t return, since the image of the current process will be replaced by the new one.

So to recap we invoke the in memory execution like this:

```go
//go:embed file.bin
var filePayload []byte
 
func main() {
    fd, err := MemfdCreate("/file.bin")
    if err != nil {
        log.Fatal(err)
    }
 
    err = CopyToMem(fd, filePayload)
    if err != nil {
        log.Fatal(err)
    }
 
    err = ExecveAt(fd)
    if err != nil {
        log.Fatal(err)
    }
}
```

```go
package main
 
import (
    "fmt"
)

Our file.bin can be any executable, for example:

func main() {
    fmt.Println("executing payload")
}
```

```bash
go build -o g.go file.bin
```

If we take a look at our built executable with radare2 we see that inside our binary there’s another one embedded:

![memory hexdump](/go_embedding.png "memory hexdump")

As we can see from the image above we resolve the symbol of our payload variable main.filePayload, which is in this case a []byte slice. The first quadword is the address where this variable resides, the second quadword is the len of the slice, and the third quadword is the capacity which matches of course in this case with the length.

Then we execute executor which embeds our file and that’s done.

```bash
./executor
executing payload
```

If we strace the process we’ll see something similar

```bash
strace -ememfd_create,execveat ./executor
...
[pid 79498] memfd_create("/file.bin", 0)  = 3
[pid 79498] execveat(3, "", NULL, NULL, AT_EMPTY_PATH
...
executing payload
```

Now this example was very simple, and of course not so useful. But for what that stuff could be used for in a real world scenario? Well one could use a technique like this as a file dropper, imagine if the content of the file.bin was something encrypted, which could just being decrypted with a key downloadable over the internet. Then executing and throwing away the key, of course will remain no persistence on the file system, so basically just live memory forensic could actually catch the clear payload, and just if it is still executing while the analysis gets performed.