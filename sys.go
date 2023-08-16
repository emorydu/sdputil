// Copyright 2023 Emory.Du <orangeduxiaocheng@gmail.com>. All rights reserved.
// Use of this source code is governed by a Apache2.0 style
// license that can be found in the LICENSE file.

package sdputil

import (
	"syscall"
)

// defines system drive operating signals.
const (
	v4netAddRule    = 0
	v4netDelRule    = 1
	v4netLookupRule = 10
	v4netClsRule    = 11
	v4netRuleLen    = 100

	netRuleSat = 101

	v6netAddRule    = 110
	v6netDelRule    = 111
	v6netLookupRule = 1000
	v6netRuleLen    = 1010
)

func syscallCreate(typ string, fd uintptr, v uintptr) (r1, r2 uintptr, err syscall.Errno) {
	var signal uintptr
	if typ == ipv4 {
		signal = v4netAddRule
	} else {
		signal = v6netAddRule
	}

	return syscall.Syscall(syscall.SYS_IOCTL, fd, signal, v)
}

func syscallLen(typ string, fd uintptr) (r1, r2 uintptr, err syscall.Errno) {
	var signal uintptr
	if typ == ipv4 {
		signal = v4netRuleLen
	} else {
		signal = v6netAddRule
	}

	return syscall.Syscall(syscall.SYS_IOCTL, fd, signal, 0)
}

func syscallLookup(typ string, fd uintptr, v uintptr) (r1, r2 uintptr, err syscall.Errno) {
	var signal uintptr
	if typ == ipv4 {
		signal = v4netLookupRule
	} else {
		signal = v6netAddRule
	}

	return syscall.Syscall(syscall.SYS_IOCTL, fd, signal, v)
}

func syscallDelete(typ string, fd uintptr, v uintptr) (r1, r2 uintptr, err syscall.Errno) {
	var signal uintptr
	if typ == ipv4 {
		signal = v4netDelRule
	} else {
		signal = v6netAddRule
	}

	return syscall.Syscall(syscall.SYS_IOCTL, fd, signal, v)
}
