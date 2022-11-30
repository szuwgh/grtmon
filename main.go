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


func main() {
	cmd.Execute()
}
