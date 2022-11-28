package check

import (
	"fmt"
	"time"

	"github.com/rpccloud/goid"
)

//go:noinline
func Hello(xxx int) {
	fmt.Println(xxx)
	fmt.Println("Current Hello Goroutine ID:", goid.GetRoutineId())
	time.Sleep(1 * time.Second)
}

//go:noinline
func Bye(xxx int) {
	fmt.Println(xxx)
	fmt.Println("Current Bye Goroutine ID:", goid.GetRoutineId())
}

//go:noinline
func aaa() {
	fmt.Println("xxx")
}

func Ok(i int) {
	if i%2 == 0 {
		go Hello(i)
	} else {
		go Bye(i)
	}

	aaa()
}
