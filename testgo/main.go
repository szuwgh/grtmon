package main

import "time"

func hello(xxx int) {
	println(xxx)
}

func main() {
	var i int
	for {
		go hello(i)
		i++
		time.Sleep(2 * time.Second)
	}
	select {}
}
