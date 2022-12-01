//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-12 -cflags "-O2 -g -Wall -Werror" -target native -type gorevent bpf ../bpf/gor/gor.c -- -I../bpf/headers
package user

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var gorEvent = map[uint32]string{1: "create", 2: "put global g", 3: "get global g", 4: "steal", 5: "exit"}

const mapKey uint32 = 2

const (
	// The path to the ELF binary containing the function to trace.
	// On some distributions, the 'readline' function is provided by a
	// dynamically-linked library, so the path of the library will need
	// to be specified instead, e.g. /usr/lib/libreadline.so.8.
	// Use `ldd /bin/bash` to find these paths.
	binPath = "/opt/goproject/rtmon/src/grtmon/testgo/testgo"

	newproc1    = "runtime.newproc1"
	runqputslow = "runtime.runqputslow"
	globrunqget = "runtime.globrunqget"
	runqsteal   = "runtime.runqsteal"
	execute     = "runtime.execute"
	goexit0     = "runtime.goexit0"

	gcMark                = "runtime.gcStart"
	gcMarkDone            = "runtime.gcMarkDone"
	gcSweep               = "runtime.gcSweep"
	gcSweepDone           = "runtime.traceGCSweepDone"
	stopTheWorldWithSema  = "runtime.stopTheWorldWithSema"
	startTheWorldWithSema = "runtime.startTheWorldWithSema"

	mallocgc = "runtime.mallocgc"
)

func ObserveGor() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	up, err := ex.Uprobe(newproc1, objs.UprobeRuntimeNewproc1, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up.Close()
	up1, err := ex.Uprobe(runqputslow, objs.UprobeRuntimeRunqputslow, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up1.Close()
	up2, err := ex.Uprobe(globrunqget, objs.UprobeRuntimeGlobrunqget, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up2.Close()
	// up3, err := ex.Uprobe(runqsteal, objs.UprobeRuntimeRunqsteal, nil)
	// if err != nil {
	// 	log.Fatalf("creating uprobe: %s", err)
	// }
	// defer up3.Close()
	up4, err := ex.Uprobe(execute, objs.UprobeRuntimeExecute, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up4.Close()
	up5, err := ex.Uprobe(goexit0, objs.UprobeRuntimeGoexit0, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up5.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	log.Printf("Listening for events..")
	var event bpfGorevent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("fn:%6x, goid:%6d, pid:%d, event:%12s, time:%d\n", event.Fn, event.Goid, event.Pid, gorEvent[event.Event], event.Time)
	}
}

func ObserveGC() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}
	up, err := ex.Uprobe(gcMark, objs.UprobeRuntimeGcStart, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up.Close()

	up1, err := ex.Uprobe(gcMarkDone, objs.UprobeRuntimeGcMarkDone, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up1.Close()

	up2, err := ex.Uprobe(gcSweep, objs.UprobeRuntimeGcsweep, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up2.Close()

	up3, err := ex.Uprobe(startTheWorldWithSema, objs.UprobeRuntimeStartTheWorldWithSema, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up3.Close()
	up4, err := ex.Uprobe(stopTheWorldWithSema, objs.UprobeRuntimeStopTheWorldWithSema, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up4.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		var value uint64
		if err := objs.UprobeMap.Lookup(mapKey, &value); err != nil {
			log.Printf("reading map: %v", err)
			continue
		}
		log.Printf("%s called %d times\n", newproc1, value)
	}

}

func ObserveMalloc() {

}

// func event() {

// 	// Name of the kernel function to trace.
// 	//fn := "sys_execve"

// 	// Allow the current process to lock memory for eBPF resources.

// 	// Load pre-compiled programs and maps into the kernel.
// 	objs := bpfObjects{}
// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		log.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()

// 	// Open a Kprobe at the entry point of the kernel function and attach the
// 	// pre-compiled program. Each time the kernel function enters, the program
// 	// will increment the execution counter by 1. The read loop below polls this
// 	// map value once per second.

// 	ex, err := link.OpenExecutable(binPath)
// 	if err != nil {
// 		log.Fatalf("opening executable: %s", err)
// 	}

// 	// Open a Uretprobe at the exit point of the symbol and attach
// 	// the pre-compiled eBPF program to it.
// 	up, err := ex.Uprobe(mallocgc, objs.UprobeRuntimeMallocgc, nil)
// 	if err != nil {
// 		log.Fatalf("creating uretprobe: %s", err)
// 	}
// 	defer up.Close()

// 	// up1, err := ex.Uprobe(runqput, objs.UprobeRuntimeRunqput, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("creating uretprobe: %s", err)
// 	// }
// 	// defer up1.Close()

// 	// up2, err := ex.Uprobe(execute, objs.UprobeRuntimeExecute, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("creating uretprobe: %s", err)
// 	// }
// 	// defer up2.Close()

// 	// up3, err := ex.Uprobe(goexit0, objs.UprobeRuntimeGoexit0, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("creating uretprobe: %s", err)
// 	// }
// 	// defer up3.Close()

// 	// up4, err := ex.Uprobe(gcDrain, objs.UprobeRuntimeGcDrain, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("creating uretprobe: %s", err)
// 	// }
// 	// defer up4.Close()

// 	// // up5, err := ex.Uprobe(gcMarkDone, objs.UprobeRuntimeGcMarkDone, nil)
// 	// // if err != nil {
// 	// // 	log.Fatalf("creating uretprobe: %s", err)
// 	// // }
// 	// // defer up5.Close()

// 	// up6, err := ex.Uprobe(gcSweep, objs.UprobeRuntimeGcsweep, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("creating uretprobe: %s", err)
// 	// }
// 	// defer up6.Close()

// 	// up7, err := ex.Uprobe(stopTheWorldWithSema, objs.UprobeRuntimeStopTheWorldWithSema, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("creating uretprobe: %s", err)
// 	// }
// 	// defer up7.Close()

// 	// up8, err := ex.Uprobe(startTheWorldWithSema, objs.UprobeRuntimeStartTheWorldWithSema, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("creating uretprobe: %s", err)
// 	// }
// 	// defer up8.Close()

// 	// kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
// 	// if err != nil {
// 	// 	log.Fatalf("opening kprobe: %s", err)
// 	// }
// 	// defer kp.Close()

// 	// Read loop reporting the total amount of times the kernel
// 	// function was entered, once per second.
// 	ticker := time.NewTicker(1 * time.Second)
// 	defer ticker.Stop()

// 	log.Println("Waiting for events..")
// 	for range ticker.C {
// 		var value uint64
// 		if err := objs.UprobeMap.Lookup(mapKey, &value); err != nil {
// 			log.Printf("reading map: %v", err)
// 			continue
// 		}
// 		log.Printf("%s called %d times\n", newproc1, value)
// 	}
// }
