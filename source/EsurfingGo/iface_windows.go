package main

import (
	"math/bits"
	"syscall"
)

// IP_UNICAST_IF chooses the physical egress even when TUN routes exist.
func interfaceControl(index int) func(string, string, syscall.RawConn) error {
	return func(network, address string, conn syscall.RawConn) error {
		var sockErr error
		err := conn.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, int(bits.ReverseBytes32(uint32(index))))
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
