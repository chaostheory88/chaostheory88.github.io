---
title: "DLL Injection using Go"
date: 2022-01-19T17:11:33+02:00
draft: false
toc: false
images:
tags:
  - windows
  - low-level
  - golang
  - dll
  - injection
---

DLL injection is the act of loading a library into a running process. Purposes can be multiple ones, like hijacking or instrumenting code, extending or adding functionalities of a software without recompiling it or malicious intents like hiding malware components.

In the first part of the post we will deal with the injection itself, while in the second one we’ll build a DLL in Go emphasizing some of the limitations and try to overcome them. The whole article targets x86-64 machines and in order to build the DLL the mingw toolchain is needed. My personal choice is to install it using cygwin, but other ways do exist, so if you don’t like it, just search for something you prefer.

## DLL Injection:

In order to load a DLL into a running process what is needed are usually the following steps:

  * Call OpenProcess to obtain a handle to the process
  * Call VirtualAllocEx to allocate virtual memory into the remote process
  * Call WriteProcessMemory with the address obtained by VirtualAllocEx in order to write the path of the DLL file into remote process memory
  * Resolve the LoadLibraryA function address locally to the injector process. Since this function belongs to kernel32.dll which is mapped in all processes at the same address, we don’t need to resolve where it resides into our victim/remote process
  * Call CreateRemoteThread in order to start a thread into the remote process, the entry point will be the LoadLibraryA address and its argument will be the address where we stored the DLL path

From now on let’s see how to write code to accomplish the above steps, also notice that where possible and to make the article more readable I’m going to omit error handling.

Go provides a package to deal with some Windows Win32 APIs but not all the functions we need are implemented, but this is not a problem, because we can resolve their addresses calling GetProcAddress on the kernel32.dll module.

So, the first step is to obtain a handle to the process, its type is windows.Handle that is just a typecast of uintptr in Go

```go
// process open permissions
flags := windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_READ |   windows.PROCESS_VM_WRITE | windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION
 
// get a handle to the process
pHandle, _ := windows.OpenProcess(uint32(flags), false, pid)
```

In the previous snippet of code we ask the OS which kind of permissions we want in order to operate on the process we’re opening. Of course if our process is not privileged enough in regards to the process we’re going to open the operation will fail. Flags we need are permissions for reading/writing memory, querying its basic information and creating a thread into remote process. Then we specify as the second argument the process PID.

Once we’ve a process handle, next task will be to reserve a portion of memory into its VAD (virtual address space) which we’ll later use to write the DLL’s path. Since this function is not implemented into the Go x/sys/windows package, we’re going to call it indirectly:

```go
// obtain a windows.LazyDLL object
kernel32             := windows.NewLazySystemDLL("kernel32.dll")
// obtain a windows.LazyProc object
virtualAllocEx       := kernel32.NewProc("VirtualAllocEx")
```

Now we can implement a wrapper around VirtualAllocEx

```go
// VirtualAllocEx wrapper
func VirtualAllocEx(pHandle windows.Handle, size, allocType, allocProt uintptr) (uintptr, error) {
    // allocate virtual memory into remote process
    addr, _, err := virtualAllocEx.Call(
        uintptr(pHandle),   // handle
        uintptr(0),         // addr where allocate (0 since we ask the OS to assign one)
        uintptr(size),      // size of allocation
        uintptr(allocType), // type of allocation
        uintptr(allocProt)) // protection of the allocation
 
    if addr == 0 {
        return 0, err
    }
 
    return addr, nil
}
```

We specify the required parameters to the Call function, the process handle, the allocation size and the protection flags, we default the allocation address to 0 since we leave the task to choose an address for the mapping to the OS. Notice that we do not check directly for error, but instead we check if the addr is equal to 0. We do this because the return from VirtualAllocEx is NULL in case of error, and one should later check about the error code calling GetLastError Windows API. The LazyProc.Call combines this behavior, so we return err just in case addr == 0. Since all the wrappers we’re going to write are implemented in the same way, I’m not going to repeat this concept further.

In order to invoke our wrapper we do:

```go
// flags for VirtualAllocEx
allocType := windows.MEM_RESERVE | windows.MEM_COMMIT
allocProt := windows.PAGE_READWRITE
size := 4096
 
// alloc virtual memory into remote process and grab the address
addr, _ := VirtualAllocEx(pHandle, uintptr(size), uintptr(allocType), uintptr(allocProt))
```

We ask the OS to directly commit the memory (despite this will not allocate it, because memory will be allocated on the first access). We also specify READ/WRITE permissions and a size of 4K (specifying less won’t actually make sense since VirtualAllocEx will anyway default to a page boundary allocation). If the call succeeds we get back the address of the allocated memory into the remote process (this means that this address is valid just into the VAD of another process, and can’t be accessed directly from our process through e.g. a dereference).

Now we can write the DLL path into the remote process memory, but in order to accomplish it we need to invoke the WriteProcessMemory function. We need to write a wrapper for it too since not directly available into the Go package.

```go
// resolve the windows.LazyProc object
writeProcessMemory   = kernel32.NewProc("WriteProcessMemory")
 
// WriteProcessMemory wrapper
func WriteProcessMemory(pHandle windows.Handle, addr uintptr, path *byte, len uintptr) (ret uintptr, err error) {
 
    // write DLL path into remote process memory
    ret, _, err = writeProcessMemory.Call(
        uintptr(pHandle),                      // process handle
        uintptr(addr),                         // remote process address
        uintptr(unsafe.Pointer(path)),         // buffer to write
        uintptr(len),                          // length of the buffer
        uintptr(0)) // bytes actually written (we set it to NULL)
 
    if ret == 0 {
        return 0, err
    }
 
    return ret, nil
}
```

We pass the process handle, the address into the remote process VAD, the buffer we are going to write and its length. We set to NULL the number of bytes written return variable (since we’re not interested in).

We can now invoke it:

```go
// convert string to pointer of bytes
pathBytes, _ := windows.BytePtrFromString(dllPath)
 
// write DLL path to remote process memory
retWrite, _ := WriteProcessMemory(pHandle, addr, pathBytes, uintptr(len(dllPath)))
```

WriteProcessMemory receives a pointer and we cannot of course pass a Go string we need a way to translate it to a *byte pointer. Luckily for us the package as BytePtrFromString facility which accomplishes the job.

Now the last piece of the puzzle. We need to start a remote thread into the target process that will call LoadLibraryA(addressOfDLLPath). Another wrapper is necessary:

```go
// grab the LazyProc related to CreateRemoteThread
createRemoteThreadEx = kernel32.NewProc("CreateRemoteThreadEx")
 
// CreateRemoteThreadEx wrapper
func CreateRemoteThreadEx(pHandle windows.Handle, remoteProcAddr, argAddr uintptr) (handle uintptr, err error) {
    // create a remote thread into the targeted process
    handle, _, err = createRemoteThreadEx.Call(
        uintptr(pHandle), // process
        uintptr(0),       // security attributes NULL
        uintptr(0),       // 0 means stack size will be the default based on binary attributes
        remoteProcAddr,   // address of the entry point for this thread
        argAddr,          // address of the argument to the entry point function in this case "LoadLibraryA(ourDllPAth)"
        uintptr(0),       // thread creations flag default none, it starts executing
        uintptr(0),       // pointer to returned threadID, we don't need it
    )
 
    return handle, err
}
```

OK, we just now need to invoke it:

```go
// call LoadLibraryA(dllPath)
remThreadHandle, _ := CreateRemoteThreadEx(pHandle, loadLibraryA.Addr(), addr)
```

So this was the recipe to inject a DLL in Go in Windows process, it is identical to what one would have done for example in C, except we’re using Go abstractions and the x/sys/windows package.

### Injecting a DLL written in Go:

What we’ve assumed into the previous part of the post is that we’re injecting a DLL written in C/C++ or any other language which supports writing DLLs and that provides a DllMain function implemented. When a DLL gets loaded or unloaded, the DllMain gets invoked and should check the reason of its invocation, the next snippet of code should be self explanatory:

```c
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            break;
 
        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;
 
        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;
 
        case DLL_PROCESS_DETACH:
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
```

So basically whoever has implemented a DLL in a standard way can relay on the fact that as soon it gets loaded into the process the DllMain will give a chance to do something (benign or malicious intents).

Unfortunately writing a DLL in Go will not produce the same effect, and if we compile a Go binary as a c-shared library, when loaded into the remote process it will just sticks there in memory doing nothing… Unless the target process does not call directly on some exported function. Let’s make an example:

```go
package main
 
import (
    "fmt"
    "os"
)
import "C"
 
//export Init
func Init() {
    pid := os.Getpid()
    f, _ := os.Create("C:\\Users\\SomeUser\\Desktop\\test.txt")
    defer f.Close()
    f.WriteString(fmt.Sprintf("PID: %d\n", pid))
}
 
func main() {
 
}
```

This Go code exports a function called Init that will just write its PID into a file on the Desktop of SomeUser. The main function is empty, and this is for a reason: when we are going to compile a Go binary as a DLL its main function will never be called. And that’s obvious because as we said before the Windows loader will invoke something called DllMain. Let’s see if such function exists in a Go DLL binary and if there let’s examine what it does (notice that we need to specify the CC compiler variable in order to build a Go DLL on Windows, it actually just works with the mingw one):

```bash
CC=x86_64-w64-mingw32-gcc go build -o some.dll -buildmode=c-shared some.go
```

![injection](/dll_inject_go.webp)

When the DLL gets loaded its DllMain returns just TRUE. So its obvious that we need to find a way to tell the remote process it has to invoke something, e.g. our Init function.

Theoretically we could just do the same thing we did in order to invoke the LoadLibraryA function using CreateRemoteThreadEx and giving it the address of Init. But fact is that for non system DLLs it can happen that they reside at some different addresses, in fact in case the VAD portion of a process the DLL would like to be loaded is already occupied, so the loader will fix and relocate it elsewhere into the target memory process. So, we need to understand where the DLL has been loaded and and where the Init function address resides. But how?

Windows comes with a nice APIs to grab information about processes, loaded DLLs and heap memory status, this is the Tool Help Library. We’re also lucky enough because this set of APIs has been already wrapped into the x/sys/windows package.

So in order to get where the DLL we just loaded resides into the remote process VAD we can use the following code:

```go
// SearchModuleAddr returns the base address of a module
func SearchModuleAddr(searchDLL string, pid uint32) (addr uintptr, size uint32, err error) {
    // create a snapshot
    handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, pid)
    if err != nil {
        return 0, 0, fmt.Errorf("failed to create snapshot: %s", err.Error())
    }
 
    // setup the entry with its own size
    var entry windows.ModuleEntry32
    entry.Size = uint32(windows.SizeofModuleEntry32)
    // get first entry
    err = windows.Module32First(handle, &entry)
    if err != nil {
        return 0, 0, fmt.Errorf("failed to get first module: %s", err.Error())
    }
 
    for {
        // parse the exepath to a Unicode string
        var dllName windows.NTUnicodeString
        windows.RtlInitUnicodeString(&dllName, &entry.ExePath[0])
 
        // transform into Go string and get the DLL name
        dllNameS := filepath.Base(dllName.String())
 
        // check if it's the one we're looking for
        if dllNameS == searchDLL {
            addr = entry.ModBaseAddr
            size = entry.ModBaseSize
            break
        }
 
        err = windows.Module32Next(handle, &entry)
        if err != nil {
            break
        }
    }
 
    if addr == 0 {
        return 0, 0, fmt.Errorf("unable to retrieve: %s library", searchDLL)
    }
 
    return addr, size, nil
}
```

This function receives as an input a DLL name and a PID, then it creates a snapshot of loaded modules for the given process and iterates over them. If we find a DLL which name is equal to the one we provided it returns its address and size, otherwise returns an error.

Once we’ve the address of the DLL we need to understand where the Init function is located. So we’ve two possibilities at this point:

  * we can load the DLL into our own process and compare the address with the one of the remote process (there’s chance has not been relocated) and if they match we can easily grab the address of Init with GetProcAddr and pass it directly to CreateRemoteThreadEx
  * we inspect the Export Table of the DLL, and locate the RVA (relative virtual address) of the Init function and then we add it to the in memory base image address of the DLL

So here a snippet of code:

```go
rva, _ := SearchDLLFunctionAddr(dllPath, "Init")
 
// load DLL into our own process so we can resolve the Init symbol
dll, _ := windows.LoadDLL(dllPath)
 
// get the Init function address
initFunc, _ := dll.FindProc("Init")
 
// search the module addr into remote process memory
dllAddr, _ , _ := SearchModuleAddr(filepath.Base(dllPath), uint32(pid))
 
// if DLLs got mapped both at the same address we can call Init function directly
// with the address we resolved locally from loading DLL into our own process
if dllAddr == uintptr(dll.Handle) {
        // invoke Init into remote process since we now have the address
        remoteThreadInitCallHandle, err := CreateRemoteThreadEx(pHandle, initFunc.Addr(), uintptr(0))
 
} else {
        // we sum the RVA to the remote DLL addr and create manually address for Init function
        remoteAddr := dllAddr + uintptr(rva)
        remoteThreadInitCallHandle, _ := CreateRemoteThreadEx(pHandle, remoteAddr, uintptr(0))
}
```

What’s missing is how we get the RVA of the Init function into the DLL. I’ve accomplished the task using this really nice library which parses PE binaries.

And here is the code used:

```go
// SearchDLLFunctionAddr searches a function inside a DLL
func SearchDLLFunctionAddr(dll, function string) (rva uint32, err error) {
    peFile, err := pe.New(dll, nil)
    if err != nil {
        return 0, err
    }
    defer peFile.Close()
 
    err = peFile.Parse()
    if err != nil {
        return 0, err
    }
 
    for _, te := range peFile.Export.Functions {
        if function == te.Name {
            fmt.Printf("[+] Name: %s, RVA: 0x%08X\n", te.Name, te.FunctionRVA)
            rva = te.FunctionRVA
        }
    }
 
    if rva == 0 {
        return 0, fmt.Errorf("function: %s not found", function)
    }
 
    return rva, nil
}
```

Also if you’re curious to understand how a PE gets parsed look at the internals of the library, code is really self explanatory and full of comments.

```bash
$ ./injector -pid 17960 -dllpath "C:\\Users\\..\\evil.dll"
[+] Name: Init, RVA: 0x0008FA50
[+] Handle: 0x144
[+] VirtualAllocEx addr: 0x1a2a4af0000
[+] LoadLibraryA: 0x7ff930de04f0
[+] Local Mapped DLL Addr: 0x7ff8e14f0000
[+] Local Init() func addr: 0x7ff8e157fa50
[+] Calling CreateRemoteThread with locally resolved Init function
[+] Remote DLL addr: 0x7ff8e14f0000, size: 3678208
[+] Calculated function: 0x7ff8e157fa50
```

Above the output of a small tool I wrote to test the code and below the output of tlist.exe which shows the DLL mapped into the notepad.exe process:

```bash
..snip... 
10.0.19041.546 shp  0x00007FF92C070000  C:\WINDOWS\System32\CoreUIComponents.dll
10.0.19041.546 shp  0x00007FF930A40000  C:\WINDOWS\System32\WS2_32.dll
10.0.19041.546 shp  0x00007FF92E670000  C:\WINDOWS\SYSTEM32\ntmarta.dll
                    0x00007FF8E14F0000  C:\Users\...\evil.dll
10.0.19041.546 shp  0x00007FF92F1D0000  C:\WINDOWS\system32\CRYPTBASE.DLL
10.0.19041.546 shp  0x00007FF91CF50000  C:\WINDOWS\SYSTEM32\winmm.dll
10.0.19041.546 shp  0x00007FF92F830000  C:\WINDOWS\SYSTEM32\powrprof.dll
...snip...
```

Here we can see that the DLL just wrote a simple text file on the desktop with its PID

```bash
$ cat c:/Users/.../Desktop/test.txt
```

Notice that unload the DLL from the process can actually crash it, since this will in interfere with running goroutines.

So that’s all about I did experimenting with Go and DLLs, hope you find it useful.



