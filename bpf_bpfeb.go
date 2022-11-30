// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfGorevent struct {
	Fn    uint64
	Event uint32
	Pid   uint32
	Pid2  uint32
	_     [4]byte
	Goid  int64
	Mid   uint64
	Time  uint64
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bpfObjects
//     *bpfPrograms
//     *bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	UprobeRuntimeExecute               *ebpf.ProgramSpec `ebpf:"uprobe_runtime_execute"`
	UprobeRuntimeGcDrain               *ebpf.ProgramSpec `ebpf:"uprobe_runtime_gcDrain"`
	UprobeRuntimeGcsweep               *ebpf.ProgramSpec `ebpf:"uprobe_runtime_gcsweep"`
	UprobeRuntimeGoexit0               *ebpf.ProgramSpec `ebpf:"uprobe_runtime_goexit0"`
	UprobeRuntimeMallocgc              *ebpf.ProgramSpec `ebpf:"uprobe_runtime_mallocgc"`
	UprobeRuntimeNewproc1              *ebpf.ProgramSpec `ebpf:"uprobe_runtime_newproc1"`
	UprobeRuntimeRunqputslow           *ebpf.ProgramSpec `ebpf:"uprobe_runtime_runqputslow"`
	UprobeRuntimeRunqsteal             *ebpf.ProgramSpec `ebpf:"uprobe_runtime_runqsteal"`
	UprobeRuntimeStartTheWorldWithSema *ebpf.ProgramSpec `ebpf:"uprobe_runtime_startTheWorldWithSema"`
	UprobeRuntimeStopTheWorldWithSema  *ebpf.ProgramSpec `ebpf:"uprobe_runtime_stopTheWorldWithSema"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Gorevents *ebpf.MapSpec `ebpf:"gorevents"`
	MemMap    *ebpf.MapSpec `ebpf:"mem_map"`
	TimeMap   *ebpf.MapSpec `ebpf:"time_map"`
	UprobeMap *ebpf.MapSpec `ebpf:"uprobe_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Gorevents *ebpf.Map `ebpf:"gorevents"`
	MemMap    *ebpf.Map `ebpf:"mem_map"`
	TimeMap   *ebpf.Map `ebpf:"time_map"`
	UprobeMap *ebpf.Map `ebpf:"uprobe_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Gorevents,
		m.MemMap,
		m.TimeMap,
		m.UprobeMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	UprobeRuntimeExecute               *ebpf.Program `ebpf:"uprobe_runtime_execute"`
	UprobeRuntimeGcDrain               *ebpf.Program `ebpf:"uprobe_runtime_gcDrain"`
	UprobeRuntimeGcsweep               *ebpf.Program `ebpf:"uprobe_runtime_gcsweep"`
	UprobeRuntimeGoexit0               *ebpf.Program `ebpf:"uprobe_runtime_goexit0"`
	UprobeRuntimeMallocgc              *ebpf.Program `ebpf:"uprobe_runtime_mallocgc"`
	UprobeRuntimeNewproc1              *ebpf.Program `ebpf:"uprobe_runtime_newproc1"`
	UprobeRuntimeRunqputslow           *ebpf.Program `ebpf:"uprobe_runtime_runqputslow"`
	UprobeRuntimeRunqsteal             *ebpf.Program `ebpf:"uprobe_runtime_runqsteal"`
	UprobeRuntimeStartTheWorldWithSema *ebpf.Program `ebpf:"uprobe_runtime_startTheWorldWithSema"`
	UprobeRuntimeStopTheWorldWithSema  *ebpf.Program `ebpf:"uprobe_runtime_stopTheWorldWithSema"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.UprobeRuntimeExecute,
		p.UprobeRuntimeGcDrain,
		p.UprobeRuntimeGcsweep,
		p.UprobeRuntimeGoexit0,
		p.UprobeRuntimeMallocgc,
		p.UprobeRuntimeNewproc1,
		p.UprobeRuntimeRunqputslow,
		p.UprobeRuntimeRunqsteal,
		p.UprobeRuntimeStartTheWorldWithSema,
		p.UprobeRuntimeStopTheWorldWithSema,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
