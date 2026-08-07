//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "golang.org/x/sys/unix"

// darwin has no SO_MARK. The "mark" is reused as the index of the interface to
// bind the socket to (IP_BOUND_IF / IPV6_BOUND_IF), scoping the socket's route
// lookup to that interface. libxtun passes the physical interface index so the
// proxy's own packets bypass the tunnel. A mark of 0 clears the binding.
func (s *StdNetBind) SetMark(mark uint32) error {
	var operr error
	if s.ipv4 != nil {
		fd, err := s.ipv4.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	if s.ipv6 != nil {
		fd, err := s.ipv6.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}
