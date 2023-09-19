package tk

import "C"
import (
	"encoding/binary"
	"net"
	"strings"
	"unsafe"
)

// IsNetIPv4 - Check if net.IP is ipv4 address
func IsNetIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

// IsNetIPv6 - Check if net.IP is ipv6 address
func IsNetIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

// Ntohl - Network to host byte-order long
func Ntohl(i uint32) uint32 {
	return binary.BigEndian.Uint32((*(*[4]byte)(unsafe.Pointer(&i)))[:])
}

// Htonl - Host to network byte-order long
func Htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

// Htons - Host to network byte-order short
func Htons(i uint16) uint16 {
	var j = make([]byte, 2)
	binary.BigEndian.PutUint16(j[0:2], i)
	return *(*uint16)(unsafe.Pointer(&j[0]))
}

// Ntohs - Network to host byte-order short
func Ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&i)))[:])
}

// IPtonl - Convert net.IP to network byte-order long
func IPtonl(ip net.IP) uint32 {
	var val uint32

	if len(ip) == 16 {
		val = uint32(ip[12])
		val |= uint32(ip[13]) << 8
		val |= uint32(ip[14]) << 16
		val |= uint32(ip[15]) << 24
	} else {
		val = uint32(ip[0])
		val |= uint32(ip[1]) << 8
		val |= uint32(ip[2]) << 16
		val |= uint32(ip[3]) << 24
	}

	return val
}

// NltoIP - Convert network byte-order long to net.IP
func NltoIP(addr uint32) net.IP {
	var dip net.IP

	dip = append(dip, uint8(addr&0xff))
	dip = append(dip, uint8(addr>>8&0xff))
	dip = append(dip, uint8(addr>>16&0xff))
	dip = append(dip, uint8(addr>>24&0xff))

	return dip
}

func ConvNetIP2DPv6Addr(addr unsafe.Pointer, goIP net.IP) {
	aPtr := (*C.uchar)(addr)
	for bp := 0; bp < 16; bp++ {
		*aPtr = C.uchar(goIP[bp])
		aPtr = (*C.uchar)(GetPtrOffset(unsafe.Pointer(aPtr),
			C.sizeof_uchar))
	}
}
