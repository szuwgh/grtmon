//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-12 -cflags "-O2 -g -Wall -Werror" -target native -type gorevent bpf ../bpf/gor/gor.c -- -I../bpf/headers
package user

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const _NumSizeClasses = 68

var class_to_size = [_NumSizeClasses]uint16{0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264, 28672, 32768}

var gorEvent = map[uint32]string{1: "create", 2: "put global g", 3: "get global g", 4: "steal", 5: "exit"}

var gcEvent = map[uint32]string{1: "mark", 2: "sweep", 3: "stw"}

var memType = []string{"< 16B", "24B", "32B", "48B", "64B", "80B", "96B", "112B", "128B", "144B", "160B", "176B", "192B", "208B", "224B", "240B", "256B",
	"288B", "320B", "352B", "384B", "416B", "448B", "480B", "512B", "576B", "640B", "704B", "768B", "896B", "1024B", "1152B", "1280B", "1408B", "1536B", "1792B", "2048B", "2304B", "2688B", "3072B", "3200B", "3456B",
	"4096B", "4864B", "5376B", "6144B", "6528B", "6784B", "6912B", "8192B", "9472B", "9728B", "10240B", "10880B", "12288B", "13568B", "14336B", "16384B", "18432B", "19072B", "20480B", "21760B", "24576B", "27264B", "28672B", "32768B", "> 32K"}

const (
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

type Observe struct {
	exec  *link.Executable
	links []link.Link
}

func (o *Observe) OpenExecutable(binPath string) error {
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return err
	}
	o.exec = ex
	return nil
}

func (o *Observe) AttachUprobe(symbol string, prog *ebpf.Program) error {
	up, err := o.exec.Uprobe(symbol, prog, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	o.links = append(o.links, up)
	return nil
}

func (o *Observe) Close() error {
	for _, v := range o.links {
		v.Close()
	}
	return nil
}

func (o *Observe) PerfEvent() {

}

func ObserveGor(binPath string) {
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

	obs := &Observe{}
	err := obs.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	obs.AttachUprobe(newproc1, objs.UprobeRuntimeNewproc1)
	obs.AttachUprobe(runqputslow, objs.UprobeRuntimeRunqputslow)
	obs.AttachUprobe(globrunqget, objs.UprobeRuntimeGlobrunqget)
	obs.AttachUprobe(execute, objs.UprobeRuntimeExecute)
	obs.AttachUprobe(goexit0, objs.UprobeRuntimeGoexit0)

	defer obs.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()
	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()
	fmt.Println("Tracing... Hit Ctrl-C to end.")
	fmt.Printf("   %-8s  %-6s  %-6s  %-12s  %-6s\n", "FN", "GOID", "PID", "EVENT", "TIME(ns)")
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
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("   %-8x  %-6d  %-6d  %-12s  %-d\n", event.Fn, event.Goid, event.Pid, gorEvent[event.Event], event.Time)
	}
}

func ObserveGorSeq(binPath string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	obs := &Observe{}
	err := obs.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}

	obs.AttachUprobe(execute, objs.UprobeRuntimeExecute)
	obs.AttachUprobe(goexit0, objs.UprobeRuntimeGoexit1)

	defer obs.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	fmt.Println("Tracing... Hit Ctrl-C to end.")
	for range ticker.C {
		var values []int
		var value uint64
		for i := uint32(0); i < 23; i++ {
			if err := objs.GrHistMap.Lookup(i, &value); err != nil {
				log.Printf("reading map: %v", err)
				continue
			}
			values = append(values, int(value))
		}
		printLog2Hist(values, "latency(μs)", 22)
		fmt.Println("--------------------------------------------------------------------------------------------------")
	}

}

func ObserveGC(binPath string) {
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

	obs := &Observe{}
	err := obs.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	obs.AttachUprobe(gcMark, objs.UprobeRuntimeGcStart)
	obs.AttachUprobe(gcMarkDone, objs.UprobeRuntimeGcMarkDone)
	obs.AttachUprobe(gcSweep, objs.UprobeRuntimeGcsweep)
	obs.AttachUprobe(startTheWorldWithSema, objs.UprobeRuntimeStartTheWorldWithSema)
	obs.AttachUprobe(stopTheWorldWithSema, objs.UprobeRuntimeStopTheWorldWithSema)

	defer obs.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()
	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()
	fmt.Println("Tracing... Hit Ctrl-C to end.")
	fmt.Printf("   %-12s  %-s\n", "EVENT", "TIME(ns)")
	var event bpfGcevent
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
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("   %-12s  %-d\n", gcEvent[event.Event], event.Time)
	}

}

func ObserveMalloc(binPath string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	obs := &Observe{}
	err := obs.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	obs.AttachUprobe(mallocgc, objs.UprobeRuntimeMallocgc)

	defer obs.Close()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	fmt.Println("Tracing... Hit Ctrl-C to end.")
	for range ticker.C {
		var values []int
		var value uint64
		for i := uint32(0); i < _NumSizeClasses+1; i++ {
			if i == 1 || i == 2 {
				continue
			}
			if err := objs.GmHistMap.Lookup(i, &value); err != nil {
				log.Printf("reading map: %v", err)
				continue
			}
			values = append(values, int(value))
		}
		printLogHist(memType, values, "malloc")
		fmt.Println("")
	}
}

func printLogHist(type_ []string, vals []int, val_type string) {
	stars_max := 60
	idx_max := -1
	t_max, val, val_max := 0, 0, 0
	var low, high uint64
	var stars, width, i int

	for i = 0; i < len(vals); i++ {
		val = vals[i]
		if val > 0 {
			idx_max = i
		}
		if val > val_max {
			val_max = val
		}
		if len(type_[i]) > t_max {
			t_max = len(type_[i])
		}

	}

	if idx_max < 0 {
		return
	}

	// w1,  := 0

	// if idx_max <= 32 {
	// 	w1 = 0
	// 	w2 = 14
	// } else {
	// 	w1 = 0
	// 	w2 = 29
	// }
	//f := ""
	fmt.Printf("   %*s%-*s : count    distribution\n", 0, "", t_max+4, val_type)

	if idx_max <= 32 {
		stars = stars_max
	} else {
		stars = stars_max / 2
	}

	for i = 0; i <= idx_max; i++ {
		low = (uint64(1) << (i + 1)) >> 1
		high = (uint64(1) << (i + 1)) - 1
		if low == high {
			low -= 1
		}
		val = vals[i]
		width = t_max + 4
		fmt.Printf("   %-*s : %-8d |", width, type_[i], val)
		print_stars(val, val_max, stars)
		fmt.Print("|\n")
	}
}

func printLog2Hist(vals []int, val_type string, max int) {
	stars_max := 60
	idx_max := -1
	val, val_max := 0, 0
	var low, high uint64
	var stars, width, i int

	for i = 0; i < len(vals); i++ {
		val = vals[i]
		if val > 0 {
			idx_max = i
		}
		if val > val_max {
			val_max = val
		}
	}

	if idx_max < 0 {
		return
	}

	w1, w2 := 0, 0

	if idx_max <= 32 {
		w1 = 9
		w2 = 14
	} else {
		w1 = 15
		w2 = 29
	}
	//f := ""
	fmt.Printf("%*s%-*s : count    distribution\n", w1, "", w2, val_type)

	if idx_max <= 32 {
		stars = stars_max
	} else {
		stars = stars_max / 2
	}

	for i = 0; i <= idx_max; i++ {
		low = (uint64(1) << (i + 1)) >> 1
		high = (uint64(1) << (i + 1)) - 1
		if low == high {
			low -= 1
		}
		val = vals[i]
		//var width int
		if idx_max <= 32 {
			width = 10
		} else {
			width = 20
		}
		if i == max {
			fmt.Printf("%*d -> %-*s : %-8d |", width, high, width, "+∞", val)
		} else {
			fmt.Printf("%*d -> %-*d : %-8d |", width, low, width, high, val)
		}

		print_stars(val, val_max, stars)
		fmt.Print("|\n")
	}
}

func print_stars(val, val_max, width int) {
	var num_stars, num_spaces, i int
	var need_plus bool

	num_stars = min(val, val_max) * width / val_max
	num_spaces = width - num_stars
	need_plus = val > val_max

	for i = 0; i < num_stars; i++ {
		fmt.Print("*")
	}

	for i = 0; i < num_spaces; i++ {
		fmt.Print(" ")
	}

	if need_plus {
		fmt.Print("+")
	}
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
