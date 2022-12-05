package main

import (
	"runtime"
	"time"
)

// "testgo/check"
// "time"
//	"os"

type A struct {
	aa int
}

func a() {
	xx := make([]int, 1000)
	yy := make([]int, 100000000)
	a := &A{}
	xx[0] = 1
	yy[0] = 2
	a.aa = 1
}

func main() {
	//runtime.StartTrace()
	//runtime.GOMAXPROCS(1)
	// var i int = 101
	// for {

	// 	check.Ok(i)
	// 	i++
	// 	time.Sleep(2 * time.Second)
	// }
	for {
		time.Sleep(2 * time.Second)
		a()
		runtime.GC()

	}
	//select {}
}
