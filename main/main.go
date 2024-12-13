package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/emorydu/sdputil"
	"github.com/thinkeridea/go-extend/exnet"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

type (
	Rule struct {
		SourceIp string `json:"source_ip"`
		Port     uint16 `json:"port"`
		Protocol uint16 `json:"protocol"`
	}
)

var (
	item *string
	op   *string
)

type Rules struct {
	SourceIp          uint32 // 来源IP
	Sourceip_extern   uint32 // 来源IP范围	TODO
	Sip_extern_switch int32  // 0 关闭/ 1 开启 表示是否开启IP范围
	DestIp            uint32 // 目标IP
	Destip_extern     uint32 // 目标IP范围
	Dip_extern_switch int32
	SourcePort        uint16 // 来源端口
	DestPort          uint16 // 873 3306
	Protocol          uint16 // 协议6 TCP
	next              *Rule  //
}

func init() {
	item = flag.String("items", "", "handle rule item")
	op = flag.String("op", "", "action (e.g: add/del/show/clear)")

	flag.Parse()
}
func main() {
	bd, err := sdputil.Init(nil)
	if err != nil {
		panic(err)
	}
	defer bd.Close()

	var v []Rule
	var rules []sdputil.RuleT4
	if *item != "" {
		err = json.Unmarshal([]byte(*item), &v)
		if err != nil {
			panic(err)
		}
		rules = Pack(v)
	}

	switch *op {
	case "clear":
		err = clean()
		if err != nil {
			panic(err)
		}
	case "add":
		err = bd.C(rules)
		if err != nil {
			panic(err)
		}
	case "del":
		err = bd.D(rules)
		if err != nil {
			panic(err)
		}
	case "show":
	default:
		panic("unknown action")
	}
}

func clean() error {
	builder, err := sdputil.Init(nil)
	if err != nil {
		return err
	}
	defer builder.Close()

	file, err := os.Open("/dev/authon_netfilter")
	defer file.Close()
	if err != nil {
		return err
	}

	fd := file.Fd()

	res, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(100), 0)
	if ep != 0 {
		return ep
	}

	if int32(res) == 0 {
		return nil
	}

	ruleArr := make([]Rules, int32(res))
	res, _, ep = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(10), uintptr(unsafe.Pointer(&ruleArr[0])))
	if ep != 0 {
		return ep
	}

	ruleList := (*[]Rules)(unsafe.Pointer(&ruleArr))

	for _, rule := range *ruleList {
		if rule.SourceIp != 0 {
			ruleInfo := sdputil.RuleT4{
				SourceIp:          rule.SourceIp,
				Sourceip_extern:   rule.Sourceip_extern,
				Sip_extern_switch: uint32(rule.Sip_extern_switch),
				DestIp:            rule.DestIp,
				Destip_extern:     rule.Destip_extern,
				Dip_extern_switch: rule.Dip_extern_switch,
				SourcePort:        rule.SourcePort,
				DestPort:          rule.DestPort,
				Protocol:          rule.Protocol,
			}
			err = builder.D([]sdputil.RuleT4{ruleInfo})
			if err != nil {
				return err
				//res, _, ep = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(1), uintptr(unsafe.Pointer(&rule)))
				//if ep != 0 {
				//	logrus.Error(err)
				//	return ep
			}
		}
	}
	return nil
}

func Pack(rules []Rule) (rules4 []sdputil.RuleT4) {
	for _, rule := range rules {
		// ipv4
		if strings.Contains(rule.SourceIp, ".") {
			values := strings.Split(rule.SourceIp, ".")
			bigEndianOrder := fmt.Sprintf("%v.%v.%v.%v", values[3], values[2], values[1], values[0])
			sourceIp, _ := exnet.IPString2Long(bigEndianOrder)
			rules4 = append(rules4, sdputil.RuleT4{
				SourceIp:          uint32(sourceIp),
				Sourceip_extern:   0xFFFF,
				Sip_extern_switch: 0,
				DestIp:            0,
				Destip_extern:     0xFFFF,
				Dip_extern_switch: 0,
				SourcePort:        0,
				DestPort:          rule.Port,
				Protocol:          rule.Protocol,
			})
		}
	}

	return
}
