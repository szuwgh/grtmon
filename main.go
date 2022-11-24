//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"time"

	//_ "github.com/cilium/ebpf/cmd/bpf2go"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-12 -cflags "-O2 -g -Wall -Werror" bpf ./bpf/gor/gor.c -- -DOUTPUT_SKB -D__TARGET_ARCH_x86 -I./bpf/headers

const mapKey uint32 = 2

const (
	// The path to the ELF binary containing the function to trace.
	// On some distributions, the 'readline' function is provided by a
	// dynamically-linked library, so the path of the library will need
	// to be specified instead, e.g. /usr/lib/libreadline.so.8.
	// Use `ldd /bin/bash` to find these paths.
	binPath = "/opt/goproject/rtmon/src/github.com/szuwgh/rtmon/testgo/testgo"
	symbol  = "main.hello"
)

func main() {

	// Name of the kernel function to trace.
	//fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// Open a Uretprobe at the exit point of the symbol and attach
	// the pre-compiled eBPF program to it.
	up, err := ex.Uprobe(symbol, objs.UprobeMainHello, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer up.Close()

	// kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		var value uint64
		if err := objs.UprobeMap.Lookup(mapKey, &value); err != nil {
			log.Printf("reading map: %v", err)
			continue
		}
		log.Printf("%s called %d times\n", symbol, value)
	}
}
