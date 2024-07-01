---
title: "Intro to Landlock"
date: 2023-07-25
tags:
  - linux
  - security
  - applications
  - landlock
categories:
  - security
  - linux
  - landlock
---

In a previous article we shown up how it is possible to make our applications more secure through
the use of seccomp which allows us to restrict the syscalls that a process or a thread can invoke. In this article we will see how to use Landlock LSM to further improve the security of our applications.

## Introduction: What's Landlock?

Landlock is a Linux security module that allows to restrict the access to the filesystem. Quoting the documentation page:

```
The goal of Landlock is to enable to restrict ambient rights (e.g. global filesystem access) for a set of processes. Because Landlock is a stackable LSM, it makes possible to create safe security sandboxes as new security layers in addition to the existing system-wide access-controls. This kind of sandbox is expected to help mitigate the security impact of bugs or unexpected/malicious behaviors in user space applications. Landlock empowers any process, including unprivileged ones, to securely restrict themselves.
```

In other words, Landlock allows a user space application to create a ruleset which will be used to restrict the access to the filesystem. In order for an application to use landlock it needs to first create a ruleset which contains the available rules. Check the documentation here for the explanation of the available access rights.

```c
// Define a new ruleset
struct landlock_ruleset_attr ruleset_attr = {
    .handled_access_fs =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM |
        LANDLOCK_ACCESS_FS_REFER |
        LANDLOCK_ACCESS_FS_TRUNCATE,
};

// Call into the kernel to create the ruleset
int ruleset_fd = syscall(SYS_landlock_create_ruleset,
                    &ruleset_attr, sizeof(ruleset_attr));
```

We can then starting to add rules to the ruleset to restrict the access to the filesystem. In order to do so we need to first create a `landlock_path_beneath_attr struct` which contains the access rights we want to grant to the process and the parent directory file descriptor. We can then add the rule to the ruleset with the `landlock_add_rule` syscall.

For example:

```c
struct landlock_path_beneath_attr path_beneath = {
    .allowed_access =
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR,
};

path_beneath.parent_fd = open("/my_app_data", O_PATH | O_CLOEXEC);

err = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                        &path_beneath, 0);
close(path_beneath.parent_fd);
```

Then we just need to load the ruleset into the kernel and we’re done.

```c
// forbid this thread from getting new privileges
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

landlock_restrict_self(ruleset_fd, 0));
close(ruleset_fd);
```

## Example of vulnerable Go application

Now we’re going to see how to use Landlock to secure a vulnerable Go application.
Suppose we’ve a vulnerable application like the following one (please notice this is just a toy example, it is not meant to be used in production or took as a reference for your own applications):

```go
package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RequestURI)

		path := r.URL.Query().Get("path")

		f, err := os.Open(path)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		defer f.Close()

		buf, err := io.ReadAll(f)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write(buf)
	})

	http.ListenAndServe(":9999", nil)
}
```

This application simply reads a path query parameter value which is used to open a file and return its content. This application is vulnerable because it is possible to read any file on the filesystem, for example:

```bash
$ curl <http://localhost:9999/?path=/etc/passwd>

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## Mitigating the vulnerability with Landlock

Now we’re going to patch our application in order to use Landlock and guarantee access just to the path where its data is stored. For simplicity it will be the current directory where we ran it.

```go
func main() {

	err := landlock.V3.BestEffort().RestrictPaths(
		landlock.RODirs("."),
	)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RequestURI)

		path := r.URL.Query().Get("path")

		f, err := os.Open(path)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		defer f.Close()

		buf, err := io.ReadAll(f)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write(buf)
	})

	http.ListenAndServe(":9999", nil)
}
```

We first select the last ABI version of Landlock which is V3, and the then invoke the `BestEffort` function which will return the strictest possible configuration up to this ABI. Then we call the `RestrictPaths` which will add an approriate rule to the ruleset in order to restrict the access to the current directory.

Let’s try to run the application again:

```bash
$ curl -v <http://localhost:9999/?path=/etc/passwd>
* Uses proxy env variable no_proxy == 'localhost,127.0.0.0/8,::1'
*   Trying 127.0.0.1:9999...
* Connected to localhost (127.0.0.1) port 9999 (#0)
> GET /?path=/etc/passwd HTTP/1.1
> Host: localhost:9999
> User-Agent: curl/8.0.1
> Accept: */*
> 
< HTTP/1.1 404 Not Found
< Date: Mon, 12 Jun 2023 11:28:10 GMT
< Content-Length: 0
< 
* Connection #0 to host localhost left intact

# in another shell were our application is logging we get
2023/06/12 11:20:19 /?path=/etc/passwd
2023/06/12 11:20:19 open /etc/passwd: permission denied
```

As we can see the application is not able to read the /etc/passwd file anymore. So Landlock implicitly mitigated the vulnerability. Seccomp and Landlock together can be a very effective combination of security measures to mitigate vulnerabilities in your applications, and they are both available as bindings for multiple languages.