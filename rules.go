// Copyright 2023 Emory.Du <orangeduxiaocheng@gmail.com>. All rights reserved.
// Use of this source code is governed by a Apache2.0 style
// license that can be found in the LICENSE file.

package sdputil

// RuleT4 define the `ipv4` rule format, field names [must] be fixed.
type RuleT4 struct {
	SourceIp          uint32
	Sourceip_extern   uint32
	Sip_extern_switch uint32
	DestIp            uint32
	Destip_extern     uint32
	Dip_extern_switch int32
	SourcePort        uint16
	DestPort          uint16
	Protocol          uint16
	next              *RuleT4
}

// RuleT6 define the `ipv6` rule format, field names [must] be fixed.
type RuleT6 struct {
	Sourceippart1 uint32
	Sourceippart2 uint32
	Sourceippart3 uint32
	Sourceippart4 uint32
	Destippart1   uint32
	Destippart2   uint32
	Destippart3   uint32
	Destippart4   uint32
	Sourceport    uint16
	Destport      uint16
	Protocol      uint16
	next          *RuleT6
}

type Rule struct {
	RuleT4
	RuleT6
}
