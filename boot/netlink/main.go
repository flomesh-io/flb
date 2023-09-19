package main

import (
	"github.com/flomesh-io/flb/netlink"
	"github.com/flomesh-io/flb/pkg/api"
)

func main() {
	/*
			ip tuntap add flb0 mode tap
			ip link set flb0 up

		    bpftool flb0 xdp
			ntc qdisc add dev flb0 clsact
			ntc filter add dev flb0 ingress bpf da obj /opt/fsmxlb/flb_ebpf_main.o sec tc_packet_hook0

			ntc qdisc add dev ens33 clsact
			ntc filter add dev ens33 ingress bpf da obj /opt/fsmxlb/flb_ebpf_main.o sec tc_packet_hook0

			ntc qdisc add dev ens36 clsact
			ntc filter add dev ens36 ingress bpf da obj /opt/fsmxlb/flb_ebpf_main.o sec tc_packet_hook0
	*/

	netlink.NlpRegister(api.NetAPIInit())
	netlink.NlpInit()

	/*
	 runtime api config
	*/
}
