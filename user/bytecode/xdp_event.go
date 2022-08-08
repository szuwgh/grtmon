package user

import (
	"io"
	"villus/ebpfutil"

	"github.com/cilium/ebpf"
)

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

type xdpBpfObjects struct {
	xdpBpfPrograms
	xdpBpfMaps
}

type xdpBpfPrograms struct {
	XdpDump *ebpf.Program `ebpf:"xdp_dump"`
}

func (p *xdpBpfPrograms) Close() error {
	return _BpfClose(
		p.XdpDump,
	)
}

type xdpBpfMaps struct {
	KprobeMap *ebpf.Map `ebpf:"kprobe_map"`
}

func (m *xdpBpfMaps) Close() error {
	return _BpfClose(
		m.KprobeMap,
	)
}

type XdpEvent struct {
	ebpfutil.Module
}

func (m *XdpEvent) loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := m.LoadBpf(_XdpBpfBytes)
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

var _XdpBpfBytes []byte
