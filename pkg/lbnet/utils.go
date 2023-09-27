package lbnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/flomesh-io/flb/pkg/tk"
)

// IterIntf - interface implementation to iterate various flbnet
// subsystems entitities
type IterIntf interface {
	NodeWalker(b string)
}

// FileExists - Check if file exists
func FileExists(fname string) bool {
	info, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// FileCreate - Create a file
func FileCreate(fname string) int {
	file, e := os.Create(fname)
	if e != nil {
		return -1
	}
	file.Close()
	return 0
}

// ReadPIDFile - Read a PID file
func ReadPIDFile(pf string) int {

	if exists := FileExists(pf); !exists {
		return 0
	}

	d, err := ioutil.ReadFile(pf)
	if err != nil {
		return 0
	}

	pid, err := strconv.Atoi(string(bytes.TrimSpace(d)))
	if err != nil {
		return 0
	}

	p, err1 := os.FindProcess(int(pid))
	if err1 != nil {
		return 0
	}

	err = p.Signal(syscall.Signal(0))
	if err != nil {
		return 0
	}

	return pid
}

// RunCommand - Run a bash command
func RunCommand(command string, isFatal bool) (int, error) {
	cmd := exec.Command("bash", "-c", command)
	err := cmd.Run()
	if err != nil {
		tk.LogIt(tk.LogError, "Error in running %s:%s\n", command, err)
		if isFatal {
			os.Exit(1)
		}
		return 0, err
	}

	return 0, nil
}

// LogString2Level - Convert log level in string to LogLevelT
func LogString2Level(logStr string) tk.LogLevelT {
	logLevel := tk.LogDebug
	switch logStr {
	case "info":
		logLevel = tk.LogInfo
	case "error":
		logLevel = tk.LogError
	case "notice":
		logLevel = tk.LogNotice
	case "warning":
		logLevel = tk.LogWarning
	case "alert":
		logLevel = tk.LogAlert
	case "critical":
		logLevel = tk.LogCritical
	case "emergency":
		logLevel = tk.LogEmerg
	default:
		logLevel = tk.LogDebug
	}
	return logLevel
}

// HTTPSProber - Do a https probe for given url
// returns true/false depending on whether probing was successful
func HTTPSProber(urls string, cert tls.Certificate, certPool *x509.CertPool, resp string) bool {
	var err error
	var req *http.Request
	var res *http.Response

	timeout := time.Duration(2 * time.Second)
	client := http.Client{Timeout: timeout,
		Transport: &http.Transport{
			IdleConnTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert},
				RootCAs: certPool}},
	}
	if req, err = http.NewRequest(http.MethodGet, urls, nil); err != nil {
		tk.LogIt(tk.LogError, "unable to create http request: %s\n", err)
		return false
	}

	res, err = client.Do(req)
	if err != nil || res.StatusCode != 200 {
		tk.LogIt(tk.LogError, "unable to create http request: %s\n", err)
		return false
	}
	defer res.Body.Close()
	if resp != "" {
		data, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return false
		}
		return string(data) == resp
	}

	return true
}

// IsIPHostAddr - Check if provided address is a local address
func IsIPHostAddr(ipString string) bool {
	// get list of available addresses
	addr, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	for _, addr := range addr {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			// check if IPv4 or IPv6 is not nil
			if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
				if ipnet.IP.String() == ipString {
					return true
				}
			}
		}
	}

	return false
}

// GratArpReq - sends a gratuitious arp reply given the DIP, SIP and interface name
func GratArpReq(AdvIP net.IP, ifName string) (int, error) {
	bcAddr := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(tk.Htons(syscall.ETH_P_ARP)))
	if err != nil {
		return -1, errors.New("af-packet-err")
	}
	defer syscall.Close(fd)

	if err := syscall.BindToDevice(fd, ifName); err != nil {
		return -1, errors.New("bind-err")
	}

	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return -1, errors.New("intf-err")
	}

	ll := syscall.SockaddrLinklayer{
		Protocol: tk.Htons(syscall.ETH_P_ARP),
		Ifindex:  ifi.Index,
		Pkttype:  0, // syscall.PACKET_HOST
		Hatype:   1,
		Halen:    6,
	}

	for i := 0; i < 8; i++ {
		ll.Addr[i] = 0xff
	}

	buf := new(bytes.Buffer)

	var sb = make([]byte, 2)
	binary.BigEndian.PutUint16(sb, 1) // HwType = 1
	buf.Write(sb)

	binary.BigEndian.PutUint16(sb, 0x0800) // protoType
	buf.Write(sb)

	buf.Write([]byte{6}) // hwAddrLen
	buf.Write([]byte{4}) // protoAddrLen

	binary.BigEndian.PutUint16(sb, 0x2) // OpCode
	buf.Write(sb)

	buf.Write(ifi.HardwareAddr) // senderHwAddr
	buf.Write(AdvIP.To4())      // senderProtoAddr

	buf.Write(bcAddr)      // targetHwAddr
	buf.Write(AdvIP.To4()) // targetProtoAddr

	if err := syscall.Bind(fd, &ll); err != nil {
		return -1, errors.New("bind-err")
	}
	if err := syscall.Sendto(fd, buf.Bytes(), 0, &ll); err != nil {
		return -1, errors.New("send-err")
	}

	return 0, nil
}

// GratArpReq - sends a gratuitious arp reply given the DIP, SIP and interface name
func GratArpReqWithCtx(ctx context.Context, rCh chan<- int, AdvIP net.IP, ifName string) (int, error) {
	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		default:
			ret, _ := GratArpReq(AdvIP, ifName)
			rCh <- ret
			return 0, nil
		}
	}
}
