package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/emorydu/sdputil"
	"github.com/thinkeridea/go-extend/exnet"
	"strings"
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

func init() {
	item = flag.String("items", "", "handle rule item")
	op = flag.String("op", "", "action (e.g: add/del/show)")

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
