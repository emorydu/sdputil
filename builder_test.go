// Copyright 2023 Emory.Du <orangeduxiaocheng@gmail.com>. All rights reserved.
// Use of this source code is governed by a Apache2.0 style
// license that can be found in the LICENSE file.

package sdputil

import (
	"fmt"
	"testing"
)

func TestCOrD(t *testing.T) {
	bd, err := Init(nil)
	if err != nil {
		panic(err)
	}
	defer bd.Close()

	err = bd.C([]RuleT4{
		{
			SourceIp:          0,
			Sourceip_extern:   0xFFFF,
			Sip_extern_switch: 0,
			DestIp:            0,
			Destip_extern:     0xFFFF,
			Dip_extern_switch: 0,
			SourcePort:        0,
			DestPort:          1897,
			Protocol:          6,
		},
		{
			SourceIp:          0,
			Sourceip_extern:   0xFFFF,
			Sip_extern_switch: 0,
			DestIp:            0,
			Destip_extern:     0xFFFF,
			Dip_extern_switch: 0,
			SourcePort:        0,
			DestPort:          999,
			Protocol:          6,
		},
	})
	if err != nil {
		fmt.Println(err)
	}

	err = bd.D([]RuleT4{
		{
			SourceIp:          0,
			Sourceip_extern:   0xFFFF,
			Sip_extern_switch: 0,
			DestIp:            0,
			Destip_extern:     0xFFFF,
			Dip_extern_switch: 0,
			SourcePort:        0,
			DestPort:          1897,
			Protocol:          6,
		},
		{
			SourceIp:          0,
			Sourceip_extern:   0xFFFF,
			Sip_extern_switch: 0,
			DestIp:            0,
			Destip_extern:     0xFFFF,
			Dip_extern_switch: 0,
			SourcePort:        0,
			DestPort:          999,
			Protocol:          6,
		},
	})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(bd.(*builder).f)
	fmt.Println(bd.(*builder).f)

	bd.Close()

	fmt.Println(bd.(*builder).f)
	fmt.Println(bd.(*builder).f)

}
