package main

import (
	"fmt"

	sg "github.com/subgraph/go-seccomp"

	"github.com/twtiger/go-seccomp-tester/helpers"
	"github.com/twtiger/gosecco"
	"github.com/twtiger/gosecco/data"
	"github.com/twtiger/gosecco/emulator"
	"github.com/twtiger/gosecco/native"
)

func main() {
	filename := "bug"
	enforce := true

	sgFilters, sgE := sg.Compile(filename, enforce)
	ourFilters, ourE := gosecco.Compile(filename, enforce)

	if sgE != nil {
		fmt.Printf("%#v", sgE)
	}
	if ourE != nil {
		fmt.Printf("%#v", ourE)
	}

	d := data.SeccompWorkingMemory{
		Arch: native.AuditArch,
		NR:   157,
		Args: [6]uint64{4, 0, 0, 0, 0},
	}

	sgRes := emulator.Emulate(d, helpers.CopyFilters(sgFilters))
	ourRes := emulator.Emulate(d, ourFilters)

	fmt.Printf("go-secc: %#v\n", sgRes)
	fmt.Printf("gosecco: %#v\n", ourRes)
}
