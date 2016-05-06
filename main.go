package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	sg "github.com/subgraph/go-seccomp"
	"github.com/twtiger/gosecco/asm"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func checkArgs() bool {
	return len(os.Args) < 4 ||
		(os.Args[1] != "white" && os.Args[1] != "black") ||
		(os.Args[2] != "true" && os.Args[2] != "false") ||
		!fileExists(os.Args[3])
}

func main() {
	if checkArgs() {
		fmt.Println("Usage: go-seccomp-tester [white|black] <enforce> <filename>")
		return
	}

	whiteList := os.Args[1] == "white"
	enforce := os.Args[2] == "true"
	filename := os.Args[3]

	sg.CheckSupport()
	var e error
	var filters []sg.SockFilter

	if whiteList {
		filters, e = sg.Compile(filename, enforce)
	} else {
		filters, e = sg.CompileBlacklist(filename, enforce)
	}

	if e != nil {
		fmt.Printf("Had error when compiling: %#v\n", e)
	} else {
		our := copyFilters(filters)
		fmt.Print(asm.Dump(our))
	}
}

func copyFilters(inp []sg.SockFilter) []unix.SockFilter {
	result := make([]unix.SockFilter, len(inp))
	for ix, v := range inp {
		result[ix] = unix.SockFilter{
			Code: v.Code,
			Jt:   v.JT,
			Jf:   v.JF,
			K:    v.K,
		}
	}
	return result
}
