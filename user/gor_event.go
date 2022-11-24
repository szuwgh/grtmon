package user

import (
	"io"

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

type GorBpfObjects struct {
	MainHello *ebpf.Program `ebpf:"uprobe_main_hello"`
	UprobeMap *ebpf.Map     `ebpf:"uprobe_map"`
}

func (m *GorBpfObjects) Close() error {
	return _BpfClose(
		m.MainHello,
		m.UprobeMap,
	)
}

var _gorBpfBytes []byte
