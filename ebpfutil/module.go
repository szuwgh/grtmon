package ebpfutil

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

type Module struct {
}

// loadBpf returns the embedded CollectionSpec for bpf.
func (m *Module) loadBpf(_BpfBytes []byte) (*ebpf.CollectionSpec, error) {
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
func (m *Module) LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions, _BpfBytes []byte) error {
	spec, err := m.loadBpf(_BpfBytes)
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}
