---
title: "Nastry Tricks with Go Generate"
date: 2021-11-24T17:29:14+02:00
draft: false
toc: false
images:
tags:
  - golang
  - go-generate
  - linux
---

Nasty tricks with go generate
novembre 24th, 2021

What follows here is just a general idea of how and individual with malicious intent can theoretically attack a CI system or a build machine using the go generate tool.

The idea is very simple, first the attacker should embed a go generate directive into its application, then at build time (using make or cmake or whatever it’s used to run the build) should run the go generate command.

Here is a simple example of such a nasty trick.

```go
package main
import "fmt"
//go:generate bash -c "echo 'package main\nimport \"fmt\"\nfunc main() {fmt.Println(\"backdoor\")}' > bd.go && go build -o bd bd.go && ./bd"
func main() {
	fmt.Println("test")
}
```

Now if we run the go generate command:

That’s of course just pure speculation and I’m not very sure how much this is feasible to accomplish this attack inside an organization/company which is very dedicated to review the source code and the build system, but I think that’s not impossible for a malicious developer accomplish it.

