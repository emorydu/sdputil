// Copyright 2023 Emory.Du <orangeduxiaocheng@gmail.com>. All rights reserved.
// Use of this source code is governed by a Apache2.0 style
// license that can be found in the LICENSE file.

package sdputil

import (
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"sync"
	"syscall"
	"unsafe"
)

// defines the rule type (v4 or v6)
const (
	ipv4 = "ipv4"
	ipv6 = "ipv6"
)

type Builder interface {
	// C create a network-driven rule list.
	C(interface{}) error

	// D delete a network-driven rule list.
	D(interface{}) error

	// Self the rules are self-updating.
	Self(interface{}) error

	// Close used to close the file stream for an open drive.
	Close()
}

type builder struct {
	typ  string
	fd   uintptr
	f    *os.File
	lock sync.Mutex
}

var mu sync.Mutex

// Init initializes builder with specified options.
func Init(opts *Options) (Builder, error) {
	mu.Lock()
	defer mu.Unlock()

	builder, err := New(opts)
	if err != nil {
		return nil, nil
	}

	return builder, nil
}

func New(opts *Options) (Builder, error) {
	if opts == nil {
		opts = NewOptions()
	}

	f, fd, err := opts.Fd()
	if err != nil {
		return nil, err
	}

	return &builder{
		fd: fd,
		f:  f,
	}, nil
}

var _ Builder = (*builder)(nil)

func (b *builder) Close() {
	err := b.f.Close()
	if err != nil {
		fmt.Println(err)
	}
}

func (b *builder) C(rules interface{}) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.create(b.fd, rules)
}

func (b *builder) D(rules interface{}) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.delete(b.fd, rules)
}

func (b *builder) Self(rules interface{}) error {
	return b.self(b.fd, rules)
}

// doCreate creates a rule in the rule list.
func doCreate(typ string, fd uintptr, v4Data []RuleT4, v6Data []RuleT6) (r1, r2 uintptr, err syscall.Errno) {
	for _, v := range v4Data {
		v := v
		r1, r2, ep := syscallCreate(typ, fd, uintptr(unsafe.Pointer(&v)))
		if ep != 0 {
			continue
		}
		return r1, r2, ep

	}
	for _, v := range v6Data {
		v := v
		r1, r2, ep := syscallCreate(typ, fd, uintptr(unsafe.Pointer(&v)))
		if ep != 0 {
			continue
		}
		return r1, r2, ep
	}

	return 0, 0, 0
}

// doDiff ddd rules that are not present in the network driver, including IPv4 and IPv6.
func doDiff(typ string, fd uintptr, v4Data []RuleT4, v6Data []RuleT6, addLen int32) (r1, r2 uintptr, err syscall.Errno) {
	v4Array := make([]RuleT4, addLen)
	v6Array := make([]RuleT6, addLen)

	var (
		v4s *[]RuleT4
		v6s *[]RuleT6
	)

	if len(v4Data) != 0 {
		r1, r2, err = syscallLookup(typ, fd, uintptr(unsafe.Pointer(&v4Array[0])))
		if err != 0 {
			return
		}
		v4s = (*[]RuleT4)(unsafe.Pointer(&v4Array))
	}
	if len(v6Data) != 0 {
		r1, r2, err = syscallLookup(typ, fd, uintptr(unsafe.Pointer(&v6Array[0])))
		if err != 0 {
			return
		}
		v6s = (*[]RuleT6)(unsafe.Pointer(&v6Array))
	}

	// TODO: post-optimization is expected
	if len(v4Data) != 0 {
		for _, out := range v4Data {
			ok := false
			for _, inner := range *v4s {
				if inner.SourceIp == out.SourceIp &&
					inner.SourcePort == out.SourcePort &&
					inner.DestIp == out.DestIp &&
					inner.DestPort == out.DestPort &&
					inner.Protocol == out.Protocol {
					ok = true
					break
				}
			}
			if !ok {
				rule := out
				_, _, ep := doCreate(typ, fd, []RuleT4{rule}, v6Data)
				if ep != 0 {
					return
				}
				log.Printf("sdputil: doDiff, add a variance rule successfully %v\n", rule)
			}
		}
	}

	if len(v6Data) != 0 {
		for _, out := range v6Data {
			ok := false
			for _, inner := range *v6s {
				if inner.Sourceippart1 == out.Sourceippart1 &&
					inner.Sourceippart2 == out.Sourceippart2 &&
					inner.Sourceippart3 == out.Sourceippart3 &&
					inner.Sourceippart4 == out.Sourceippart4 &&
					inner.Destippart1 == out.Destippart1 &&
					inner.Destippart2 == out.Destippart2 &&
					inner.Destippart3 == out.Destippart3 &&
					inner.Destippart4 == out.Destippart4 &&
					inner.Destport == out.Destport &&
					inner.Protocol == out.Protocol {
					ok = true
					break
				}
			}
			if !ok {
				rule := out
				_, _, ep := doCreate(typ, fd, v4Data, []RuleT6{rule})
				if ep != 0 {
					return
				}
				log.Printf("sdputil: doDiff, add a variance rule successfully %v\n", rule)
			}
		}
	}

	return 0, 0, 0
}

func (b *builder) create(fd uintptr, values interface{}) error {
	v4s, v6s, err := b.ref(values)
	if err != nil {
		return err
	}

	// gets the rule length
	res, _, ep := syscallLen(b.typ, fd)
	if ep != 0 {
		return ep
	}
	if int32(res) == 0 {
		// all added
		res, _, ep = doCreate(b.typ, fd, v4s, v6s)
		if ep != 0 {
			return ep
		}
		return nil
	}

	// make a difference item to add
	_, _, ep = doDiff(b.typ, fd, v4s, v6s, int32(res))
	if ep != 0 {
		return ep
	}

	return nil
}

// ref returns a list of rules for supported rule types.
func (b *builder) ref(values interface{}) ([]RuleT4, []RuleT6, error) {
	var (
		v4list []RuleT4
		v6list []RuleT6
	)

	retValue := reflect.ValueOf(values)
	if retValue.Kind() != reflect.Slice {
		return nil, nil, errors.New("unsupported rule types")
	}
	switch retValue.Type().String() {
	case "[]sdputil.RuleT4":
		b.typ = ipv4
		v4list = make([]RuleT4, 0, retValue.Len())
	case "[]sdputil.RuleT6":
		b.typ = ipv6
		v6list = make([]RuleT6, 0, retValue.Len())
	}

	for i := 0; i < retValue.Len(); i++ {
		value := retValue.Index(i)
		switch b.typ {
		case ipv4:
			v4list = append(v4list, RuleT4{
				SourceIp:          value.Field(0).Interface().(uint32),
				Sourceip_extern:   value.Field(1).Interface().(uint32),
				Sip_extern_switch: value.Field(2).Interface().(uint32),
				DestIp:            value.Field(3).Interface().(uint32),
				Destip_extern:     value.Field(4).Interface().(uint32),
				Dip_extern_switch: value.Field(5).Interface().(int32),
				SourcePort:        value.Field(6).Interface().(uint16),
				DestPort:          value.Field(7).Interface().(uint16),
				Protocol:          value.Field(8).Interface().(uint16),
			})
		case ipv6:
			v6list = append(v6list, RuleT6{
				Sourceippart1: value.Field(0).Interface().(uint32),
				Sourceippart2: value.Field(1).Interface().(uint32),
				Sourceippart3: value.Field(2).Interface().(uint32),
				Sourceippart4: value.Field(3).Interface().(uint32),
				Destippart1:   value.Field(4).Interface().(uint32),
				Destippart2:   value.Field(5).Interface().(uint32),
				Destippart3:   value.Field(6).Interface().(uint32),
				Destippart4:   value.Field(7).Interface().(uint32),
				Sourceport:    value.Field(8).Interface().(uint16),
				Destport:      value.Field(9).Interface().(uint16),
				Protocol:      value.Field(10).Interface().(uint16),
			})
		}
	}

	return v4list, v6list, nil
}

// delete specifies to remove the rule that exists in the
// network driver, if the rule does not exist, an error will be returned if it is removed.
func (b *builder) delete(fd uintptr, values interface{}) error {

	var (
		v4List *[]RuleT4
		v6List *[]RuleT6
	)

	v4s, v6s, err := b.ref(values)
	if err != nil {
		return err
	}

	// gets the rule length
	res, _, ep := syscallLen(b.typ, fd)
	if ep != 0 {
		return ep
	}

	v4Array := make([]RuleT4, int32(res))
	v6Array := make([]RuleT6, int32(res))

	if len(v4s) != 0 {
		_, _, ep = syscallLookup(b.typ, fd, uintptr(unsafe.Pointer(&v4Array[0])))
		if ep != 0 {
			return ep
		}
		v4List = (*[]RuleT4)(unsafe.Pointer(&v4Array))
	}
	if len(v6s) != 0 {
		_, _, ep = syscallLookup(b.typ, fd, uintptr(unsafe.Pointer(&v6Array[0])))
		if ep != 0 {
			return ep
		}
		v6List = (*[]RuleT6)(unsafe.Pointer(&v6Array))
	}

	// TODO: post-optimization is expected
	if len(v4s) != 0 {
		//for _, outer := range *v4List {
		//	for _, inner := range v4s {
		//		rule := inner
		for _, outer := range v4s {
			for _, inner := range *v4List {
				rule := outer
				if outer.SourceIp == inner.SourceIp &&
					outer.SourcePort == inner.SourcePort &&
					outer.DestIp == inner.DestIp &&
					outer.DestPort == inner.DestPort &&
					outer.Protocol == inner.Protocol {
					_, _, ep := syscallDelete(b.typ, fd, uintptr(unsafe.Pointer(&rule)))
					if ep != 0 {
						return ep
					}
					log.Printf("sdputil: delete, delete the presence rule successfully %v\n", rule)
				}
			}

		}
	}

	if len(v6s) != 0 {
		for _, outer := range v6s {
			for _, inner := range *v6List {
				rule := outer
				if outer.Sourceippart1 == inner.Sourceippart1 &&
					outer.Sourceippart2 == inner.Sourceippart2 &&
					outer.Sourceippart3 == inner.Sourceippart3 &&
					outer.Sourceippart4 == inner.Sourceippart4 &&
					outer.Destippart1 == inner.Destippart1 &&
					outer.Destippart2 == inner.Destippart2 &&
					outer.Destippart3 == inner.Destippart3 &&
					outer.Destippart4 == inner.Destippart4 &&
					outer.Destport == inner.Destport &&
					outer.Protocol == inner.Protocol {
					_, _, ep := syscallDelete(b.typ, fd, uintptr(unsafe.Pointer(&rule)))
					if ep != 0 {
						return ep
					}
					log.Printf("sdputil: delete, delete the presence rule successfully %v\n", rule)
				}
			}
		}
	}

	return nil
}

func (b *builder) self(fd uintptr, values interface{}) error {
	var (
		v4List *[]RuleT4
		v6List *[]RuleT6
	)

	v4s, v6s, err := b.ref(values)
	if err != nil {
		return err
	}

	// gets the rule length
	res, _, ep := syscallLen(b.typ, fd)
	if ep != 0 {
		return ep
	}

	v4Array := make([]RuleT4, int32(res))
	v6Array := make([]RuleT6, int32(res))

	if len(v4s) != 0 {
		_, _, ep = syscallLookup(b.typ, fd, uintptr(unsafe.Pointer(&v4Array[0])))
		if ep != 0 {
			return ep
		}
		v4List = (*[]RuleT4)(unsafe.Pointer(&v4Array))
	}
	if len(v6s) != 0 {
		_, _, ep = syscallLookup(b.typ, fd, uintptr(unsafe.Pointer(&v6Array[0])))
		if ep != 0 {
			return ep
		}
		v6List = (*[]RuleT6)(unsafe.Pointer(&v6Array))
	}

	if len(v4s) != 0 {
		for _, nac := range *v4List {
			flag := false
			for _, r := range v4s {
				if nac.SourceIp == r.SourceIp &&
					nac.SourcePort == r.SourcePort &&
					nac.DestIp == r.DestIp &&
					nac.DestPort == r.DestPort &&
					nac.Protocol == r.Protocol {
					flag = true
				}
			}
			if !flag {
				_, _, ep := syscallDelete(b.typ, fd, uintptr(unsafe.Pointer(&nac)))
				if ep != 0 {
					return ep
				}
				log.Printf("sdputil: delete, delete the presence rule successfully %v\n", nac)
			}
		}
	}

	if len(v6s) != 0 {
		for _, nac := range *v6List {
			flag := false
			for _, r := range v6s {
				if nac.Sourceippart1 == r.Sourceippart1 &&
					nac.Sourceippart2 == r.Sourceippart2 &&
					nac.Sourceippart3 == r.Sourceippart3 &&
					nac.Sourceippart4 == r.Sourceippart4 &&
					nac.Destippart1 == r.Destippart1 &&
					nac.Destippart2 == r.Destippart2 &&
					nac.Destippart3 == r.Destippart3 &&
					nac.Destippart4 == r.Destippart4 &&
					nac.Destport == r.Destport &&
					nac.Protocol == r.Protocol {
					flag = true
				}
			}
			if !flag {
				_, _, ep := syscallDelete(b.typ, fd, uintptr(unsafe.Pointer(&nac)))
				if ep != 0 {
					return ep
				}
				log.Printf("sdputil: delete, delete the presence rule successfully %v\n", nac)
			}
		}
	}

	return nil
}
