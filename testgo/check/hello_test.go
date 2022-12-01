package check

import (
	"fmt"
	"testing"
	"unsafe"
)

type A struct{}

type B struct {
	a A
	c uint64
}

func Test_size(t *testing.T) {
	var a B
	fmt.Println(unsafe.Sizeof(a)) // 5
}
