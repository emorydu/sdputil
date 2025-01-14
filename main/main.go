package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/emorydu/sdputil"
	"github.com/hashicorp/go-version"
	"github.com/thinkeridea/go-extend/exnet"
	"io"
	"os"
	"os/exec"
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

//func init() {
//	defer func() {
//		if err := recover(); err != nil {
//			fmt.Fprintln(os.Stderr, 1)
//		}
//	}()
//
//}

func RunIptablesCommand() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("创建iptables实例失败: %v", err)
	}

	exists, err := ipt.Exists("filter", "FORWARD", "-m", "state", "--state", "INVALID,NEW,RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("执行iptables命令失败: %v", err)
	}

	if exists == false {
		err = ipt.Insert("filter", "FORWARD", 1, "-m", "state", "--state", "INVALID,NEW,RELATED,ESTABLISHED", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("添加默认iptables规则失败: %v", err)
		}

		ExecCommand("service iptables save")

		exist, err := ipt.Exists("filter", "FORWARD", "-m", "state", "--state", "INVALID,NEW,RELATED,ESTABLISHED", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("执行iptables命令失败: %v", err)
		}

		if !exist {
			return fmt.Errorf("add default iptables rules faield")
		}

	}

	return nil
}

func ExecCommand(params string) (result string, err error) {
	cmd := exec.Command("/bin/sh", "-c", params)
	//StdoutPipe方法返回一个在命令Start后与命令标准输出关联的管道。Wait方法获知命令结束后会关闭这个管道，一般不需要显式的关闭该管道。
	stdout, err := cmd.StdoutPipe()
	defer stdout.Close()
	if err != nil {
		return "", err
	}

	cmd.Start()
	//创建一个流来读取管道内内容，这里逻辑是通过一行一行的读取的
	reader := bufio.NewReader(stdout)
	sb := strings.Builder{}
	//实时循环读取输出流中的一行内容
	for {
		line, err2 := reader.ReadString('\n')
		if err2 != nil || io.EOF == err2 {
			break
		}
		v := strings.ReplaceAll(line, "\n", "")
		sb.WriteString(v)
		sb.WriteString(";")
	}
	//阻塞直到该命令执行完成，该命令必须是被Start方法开始执行的
	cmd.Wait()

	res := sb.String()
	sz := len(res)

	if sz > 0 && res[sz-1] == ';' {
		res = res[:sz-1]
	}

	return res, nil
}

func compareKernel() (bool, error) {
	cmd := exec.Command("uname", "-r")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	ver := strings.Split(string(output), "-")[0]

	v1, _ := version.NewVersion(ver)
	v2, _ := version.NewVersion("4.19")
	if v1.GreaterThanOrEqual(v2) {
		return true, nil
	}

	return false, nil
}

func CheckSDPMiddlewares() error {
	ok, err := compareKernel()
	if err != nil {
		return fmt.Errorf("compare sem version failed: %v", err)
	}
	if !ok {
		res, err := ExecCommand("lsmod|awk {'print $1'}|grep nf_conntrack")
		if err != nil {
			return fmt.Errorf("chek nf_conntrace module load failed: %v", err)
		}

		if strings.Index(res, "nf_conntrack_ipv4") == -1 {
			ExecCommand("modprobe ip_conntrack")

			result, err := ExecCommand("lsmod|awk {'print $1'}|grep nf_conntrack")
			if err != nil {
				return fmt.Errorf("check nf_conntrack module load failed: %v", err)
			}
			if strings.Index(result, "nf_conntrack") == -1 {
				return fmt.Errorf("ip_conntrack module load failed")
			}
		}

		if strings.Index(res, "nf_conntrack_ipv6") == -1 {
			ExecCommand("modprobe nf_conntrack_ipv6")

			result, err := ExecCommand("lsmod|awk {'print $1'}|grep nf_conntrack")
			if err != nil {
				return fmt.Errorf("checknf_conntrack module load failed: %v", err)
			}
			if strings.Index(result, "nf_conntrack_ipv6") == -1 {
				return fmt.Errorf("ip_conntrack module load failed")
			}
		}
	} else {
		ExecCommand("modprobe nf_conntrack")
		ExecCommand("modprobe ip_conntrack")

		result, err := ExecCommand("lsmod|awk {'print $1'}|grep nf_conntrack")
		if err != nil {
			return fmt.Errorf("check nf_conntrack module load faield: %v", err)
		}
		if strings.Index(result, "nf_conntrack") == -1 {
			return fmt.Errorf("nf_conntrack module load failed")
		}
	}

	return nil
}

func main() {

	item = flag.String("items", "", "handle rule item")
	op = flag.String("op", "", "action (e.g: add/del/show/clear)")

	flag.Parse()

	var err error
	err = RunIptablesCommand()
	if err == nil {
		err = CheckSDPMiddlewares()
	}
	if err != nil {
		fmt.Fprintln(os.Stdout, err)
		return
	}

	bd, err := sdputil.Init(nil)
	if err != nil {
		fmt.Fprintln(os.Stdout, 1)
		return
	}
	defer bd.Close()

	var v []Rule
	var rules []sdputil.RuleT4
	if *item != "" {
		err = json.Unmarshal([]byte(*item), &v)
		if err != nil {
			fmt.Fprintln(os.Stdout, 1)
			return
		}
		rules = Pack(v)
	}

	switch *op {
	case "clear":
		err = clean()
		if err != nil {
			fmt.Fprintln(os.Stdout, 1)
		} else {
			fmt.Fprintln(os.Stdout, 0)
		}
	case "add":
		err = bd.C(rules)
		if err != nil {
			fmt.Fprintln(os.Stdout, 1)
		} else {
			fmt.Fprintln(os.Stdout, 0)
		}
	case "del":
		err = bd.D(rules)
		if err != nil {
			fmt.Fprintln(os.Stdout, 1)
		} else {
			fmt.Fprintln(os.Stdout, 0)
		}
	default:
		fmt.Fprintln(os.Stdout, 1)
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
