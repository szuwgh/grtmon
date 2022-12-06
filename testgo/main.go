package main

import (
	"fmt"
	"os"
	"runtime"
	"testgo/check"
	"time"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "testgo",
	Short: "go runtime simple monitor based on ebpf",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

var goroutineCmd = &cobra.Command{
	Use:   "gr",
	Short: "observe goroutine creation schedule",
	Run:   goroutineCommandFunc,
}

var gcCmd = &cobra.Command{
	Use:   "gc",
	Short: "observe gc",
	Run:   gcCommandFunc,
}

var gmCmd = &cobra.Command{
	Use:   "gm",
	Short: "observe gc",
	Run:   gmCommandFunc,
}

func init() {
	rootCmd.AddCommand(goroutineCmd)
	rootCmd.AddCommand(gcCmd)
	rootCmd.AddCommand(gmCmd)

}

type A struct {
	aa int
	bb []uint8
}

func a() {

	for i := 1; i < 100; i++ {
		a := &A{}
		a.aa = 1
		a.bb = make([]uint8, i)
		a.aa = 1
	}
	yy1 := make([]int, 10000000)
	yy1[0] = 1
	yy2 := make([]int, 1000)
	yy2[0] = 1
}

func goroutineCommandFunc(command *cobra.Command, args []string) {
	var i int = 101
	for {
		check.Ok(i)
		i++
		time.Sleep(2 * time.Second)
	}
}

func gcCommandFunc(command *cobra.Command, args []string) {
	a()
	runtime.GC()
}

func gmCommandFunc(command *cobra.Command, args []string) {
	a()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
