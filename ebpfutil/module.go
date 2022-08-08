package ebpfutil

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

type Module struct {
}

func (m *Module) LoadBpf(_BpfBytes []byte) (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}
