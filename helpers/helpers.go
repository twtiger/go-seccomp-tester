package helpers

import (
	sg "github.com/subgraph/go-seccomp"
	"golang.org/x/sys/unix"
)

func CopyFilters(inp []sg.SockFilter) []unix.SockFilter {
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
