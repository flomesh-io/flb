package bpf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	nl "github.com/vishvananda/netlink"

	dp "github.com/flomesh-io/flb/pkg/datapath"
	"github.com/flomesh-io/flb/pkg/tk"
)

// LoadXdpProg - load xdp program
func LoadXdpProg() int {
	shell(fmt.Sprintf(`bpftool prog loadall %s %s/flb_xdp_main type xdp`, dp.FLB_FP_IMG_DEFAULT, dp.FLB_DB_MAP_PDIR))
	return 0
}

func UnloadXdpProg() {
	os.RemoveAll(fmt.Sprintf(`%s/flb_xdp_main`, dp.FLB_DB_MAP_PDIR))
}

// AttachXdpProg - attach eBPF program to an interface
func AttachXdpProg(intfName string) int {
	shell(fmt.Sprintf(`bpftool net attach xdpgeneric name xdp_packet_func dev %s`, intfName))
	return 0
}

// DetachXdpProg - detach eBPF program to an interface
func DetachXdpProg(intfName string) int {
	shell(fmt.Sprintf(`bpftool net detach xdpgeneric dev %s`, intfName))
	return 0
}

// AttachTcProg - attach eBPF program to an interface
func AttachTcProg(intfName string) int {
	if !hasLoadedTcProg(intfName) {
		shell(fmt.Sprintf(`ftc qdisc add dev %s clsact`, intfName))
		shell(fmt.Sprintf(`ftc filter add dev %s ingress bpf da obj %s sec tc_packet_hook0`, intfName, dp.FLB_FP_IMG_BPF))
	}
	return 0
}

// DetachTcProg - detach eBPF program from an interface
func DetachTcProg(intfName string) int {
	if hasLoadedTcProg(intfName) {
		shell(fmt.Sprintf(`ftc filter del dev %s ingress`, intfName))
		shell(fmt.Sprintf(`ftc qdisc del dev %s clsact`, intfName))
	}
	return 0
}

func hasLoadedTcProg(intfName string) bool {
	if true { //通过 shell 脚本实现
		command := fmt.Sprintf(`ftc filter show dev %s ingress`, intfName)
		cmd := exec.Command("bash", "-c", command)
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(output), `tc_packet_hook0`)
	}

	//通过 netlink 系统调用 脚本实现
	link, err := nl.LinkByName(intfName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[DP] Port %s not found, error:%v\n", intfName, err)
		return false
	}

	filters, err := nl.FilterList(link, nl.HANDLE_MIN_INGRESS)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[DP] Filter on %s not found, error:%v\n", intfName, err)
		return false
	}
	for _, f := range filters {
		if t, ok := f.(*nl.BpfFilter); ok {
			if strings.Contains(t.Name, "tc_packet_hook0") {
				return true
			}
		}
	}
	return false
}

func shell(command string) bool {
	cmd := exec.Command("bash", "-c", command)
	_, err := cmd.Output()
	if err != nil {
		return false
	}
	return true
}
