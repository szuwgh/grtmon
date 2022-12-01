package cmd

import (
	"fmt"
	"grtmon/user"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "grtmon",
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

var mallocCmd = &cobra.Command{
	Use:   "gm",
	Short: "observe memory allocation",
	Run:   mallocCommandFunc,
}

func init() {
	rootCmd.AddCommand(goroutineCmd)
	rootCmd.AddCommand(gcCmd)
	rootCmd.AddCommand(mallocCmd)

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func goroutineCommandFunc(command *cobra.Command, args []string) {
	fmt.Println("goroutineCommandFunc")
	user.ObserveGor()
}

func gcCommandFunc(command *cobra.Command, args []string) {
	fmt.Println("gcCommandFunc")
	user.ObserveGC()
	//select {}
}

func mallocCommandFunc(command *cobra.Command, args []string) {
	fmt.Println("mallocCommandFunc")
}
