package nftables

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// isReadReady reports whether the netlink connection is ready for reading.
// It uses poll with a zero timeout on the underlying raw connection. This
// allows for an efficient check of socket readiness without blocking.
//
// poll is used instead of (p)select because select's fd_set is a fixed-size
// bitmap limited to FD_SETSIZE (1024) descriptors. In long-running processes
// that hold many descriptors, the netlink socket can easily be assigned a
// number above that limit, and setting such a descriptor in an fd_set panics
// with an index out of range. poll takes the descriptor as a plain integer and
// therefore has no such upper bound.
//
// If the Conn was created with a TestDial function, it assumes readiness.
func (cc *Conn) isReadReady(conn *netlink.Conn) (bool, error) {
	if cc.TestDial != nil {
		return true, nil
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("get raw conn: %w", err)
	}

	var n int
	var opErr error
	err = rawConn.Control(func(fd uintptr) {
		fds := []unix.PollFd{{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		}}

		for {
			// A zero timeout returns immediately.
			n, opErr = unix.Poll(fds, 0)
			if opErr != unix.EINTR {
				break
			}
		}
	})
	if err != nil {
		return false, err
	}

	if opErr != nil {
		return false, fmt.Errorf("poll: %w", opErr)
	}

	return n > 0, nil
}
