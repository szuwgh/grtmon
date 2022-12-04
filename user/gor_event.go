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

var gorEvent = map[uint32]string{1: "create", 2: "put global g", 3: "get global g", 4: "steal", 5: "exit"}

var gcEvent = map[uint32]string{1: "mark", 2: "sweep", 3: "stw"}

const gmKey0 uint32 = 0
const gmKey1 uint32 = 1
const gmKey2 uint32 = 2

const (
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
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("fn:%6x, goid:%6d, pid:%d, event:%12s, time:%d\n", event.Fn, event.Goid, event.Pid, gorEvent[event.Event], event.Time)
	}
}

func ObserveGC() {
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
	log.Printf("Listening for events..")
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

		fmt.Printf(" event:%12s, time:%d\n", gcEvent[event.Event], event.Time)
	}

}

func ObserveMalloc() {
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

	log.Println("Waiting for events..")
	for range ticker.C {
		var value0, value1, value2 uint64
		if err := objs.GmHistMap.Lookup(gmKey0, &value0); err != nil {
			log.Printf("reading map: %v", err)
			continue
		}
		if err := objs.GmHistMap.Lookup(gmKey1, &value1); err != nil {
			log.Printf("reading map: %v", err)
			continue
		}
		if err := objs.GmHistMap.Lookup(gmKey2, &value2); err != nil {
			log.Printf("reading map: %v", err)
			continue
		}
		log.Printf("%d, %d, %d", value0, value1, value2)
	}
}

// static void print_stars(unsigned int val, unsigned int val_max, int width)
// {
// 	int num_stars, num_spaces, i;
// 	bool need_plus;

// 	num_stars = min(val, val_max) * width / val_max;
// 	num_spaces = width - num_stars;
// 	need_plus = val > val_max;

// 	for (i = 0; i < num_stars; i++)
// 		printf("*");
// 	for (i = 0; i < num_spaces; i++)
// 		printf(" ");
// 	if (need_plus)
// 		printf("+");
// }

// void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
// {
// 	int stars_max = 40, idx_max = -1;
// 	unsigned int val, val_max = 0;
// 	unsigned long long low, high;
// 	int stars, width, i;

// 	for (i = 0; i < vals_size; i++) {
// 		val = vals[i];
// 		if (val > 0)
// 			idx_max = i;
// 		if (val > val_max)
// 			val_max = val;
// 	}

// 	if (idx_max < 0)
// 		return;

// 	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
// 		idx_max <= 32 ? 19 : 29, val_type);

// 	if (idx_max <= 32)
// 		stars = stars_max;
// 	else
// 		stars = stars_max / 2;

// 	for (i = 0; i <= idx_max; i++) {
// 		low = (1ULL << (i + 1)) >> 1;
// 		high = (1ULL << (i + 1)) - 1;
// 		if (low == high)
// 			low -= 1;
// 		val = vals[i];
// 		width = idx_max <= 32 ? 10 : 20;
// 		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
// 		print_stars(val, val_max, stars);
// 		printf("|\n");
// 	}
// }

// kbytes          : count     distribution
// 0 -> 1        : 3        |                                      |
// 2 -> 3        : 0        |                                      |
// 4 -> 7        : 211      |**********                            |
// 8 -> 15       : 0        |                                      |
// 16 -> 31       : 0        |                                      |
// 32 -> 63       : 0        |                                      |
// 64 -> 127      : 1        |                                      |
// 128 -> 255      : 800      |**************************************|

func printLogHist(type_ []string, vals []int, val_type string) {
	stars_max := 40
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
	fmt.Printf("%*s%-*s : count    distribution\n", 0, "", t_max+4, val_type)

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
		// if idx_max <= 32 {
		// 	width = 10
		// } else {
		// 	width = 20
		// }
		width = t_max + 4
		fmt.Printf("%-*s : %-8d |", width, type_[i], val)
		print_stars(val, val_max, stars)
		fmt.Print("|\n")
	}
}

func printLog2Hist(vals []int, val_type string) {
	stars_max := 40
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
		w1 = 10
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
		fmt.Printf("%*d -> %-*d : %-8d |", width, low, width, high, val)
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
