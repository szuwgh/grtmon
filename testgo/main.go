package main

import (
	"fmt"
	"runtime"
)

type A struct {
	aa int
}

func a() {
	xx := make([]int, 1000)
	a := &A{}
	fmt.Println(xx, a)
}

func main() {
	runtime.GOMAXPROCS(1)
	//var i int = 101
	// for {

	// 	check.Ok(i)
	// 	i++
	// 	time.Sleep(2 * time.Second)
	// }
	a()
	runtime.GC()
	//select {}
}
