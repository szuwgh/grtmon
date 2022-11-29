//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"grtmon/cmd"
	//_ "github.com/cilium/ebpf/cmd/bpf2go"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-12 -cflags "-O2 -g -Wall -Werror" -type gorevent bpf ./bpf/gor/gor.c -- -DOUTPUT_SKB -D__TARGET_ARCH_x86 -I./bpf/headers
func main() {
	cmd.Execute()
}
