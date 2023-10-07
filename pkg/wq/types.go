package wq

import (
	"fmt"
	"net"
	"time"

	"github.com/flomesh-io/flb/pkg/cmn"
)

// man names constants
const (
	MapNameCt4  = "CT4"
	MapNameCt6  = "CT6"
	MapNameNat4 = "NAT4"
	MapNameBD   = "BD"
	MapNameRxBD = "RXBD"
	MapNameTxBD = "TXBD"
	MapNameRt4  = "RT4"
	MapNameULCL = "ULCL"
	MapNameIpol = "IPOL"
	MapNameFw4  = "FW4"
)

// DpWorkT - type of requested work
type DpWorkT uint8

// dp work codes
const (
	DpCreate DpWorkT = iota + 1
	DpRemove
	DpChange
	DpStatsGet
	DpStatsClr
	DpMapGet
)

// DpStatusT - status of a dp work
type DpStatusT uint8

// dp work status codes
const (
	DpCreateErr DpStatusT = iota + 1
	DpRemoveErr
	DpChangeErr
	DpUknownErr
	DpInProgressErr
)

// MirrDpWorkQ - work queue entry for mirror operation
type MirrDpWorkQ struct {
	Work      DpWorkT
	Name      string
	Mark      int
	MiPortNum int
	MiBD      int
	Status    *DpStatusT
}

// PortDpWorkQ - work queue entry for port operation
type PortDpWorkQ struct {
	Work       DpWorkT
	Status     *DpStatusT
	OsPortNum  int
	PortNum    int
	IngVlan    int
	SetBD      int
	SetZoneNum int
	Prop       cmn.PortProp
	SetMirr    int
	SetPol     int
	LoadEbpf   string
}

// L2AddrDpWorkQ - work queue entry for l2 address operation
type L2AddrDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	L2Addr  [6]uint8
	Tun     DpTunT
	NhNum   int
	PortNum int
	BD      int
	Tagged  int
}

// DpTunT - type of a dp tunnel
type DpTunT uint8

// tunnel type constants
const (
	DpTunVxlan DpTunT = iota + 1
	DpTunGre
	DpTunGtp
	DpTunStt
	DpTunIPIP
)

// RouterMacDpWorkQ - work queue entry for rt-mac operation
type RouterMacDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	L2Addr  [6]uint8
	PortNum int
	BD      int
	TunID   uint32
	TunType DpTunT
	NhNum   int
}

// NextHopDpWorkQ - work queue entry for nexthop operation
type NextHopDpWorkQ struct {
	Work        DpWorkT
	Status      *DpStatusT
	TunNh       bool
	TunID       uint32
	TunType     DpTunT
	RIP         net.IP
	SIP         net.IP
	NNextHopNum int
	NextHopNum  int
	Resolved    bool
	DstAddr     [6]uint8
	SrcAddr     [6]uint8
	BD          int
}

// RouteDpWorkQ - work queue entry for rt operation
type RouteDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	ZoneNum int
	Dst     net.IPNet
	RtType  int
	RtMark  int
	NMark   int
}

// StatDpWorkQ - work queue entry for stat operation
type StatDpWorkQ struct {
	Work        DpWorkT
	Name        string
	Mark        uint32
	Packets     *uint64
	Bytes       *uint64
	DropPackets *uint64
}

// TableDpWorkQ - work queue entry for map related operation
type TableDpWorkQ struct {
	Work DpWorkT
	Name string
}

// PolDpWorkQ - work queue entry for policer related operation
type PolDpWorkQ struct {
	Work   DpWorkT
	Name   string
	Mark   int
	Cir    uint64
	Pir    uint64
	Cbs    uint64
	Ebs    uint64
	Color  bool
	Srt    bool
	Status *DpStatusT
}

// PeerDpWorkQ - work queue entry for peer association
type PeerDpWorkQ struct {
	Work   DpWorkT
	PeerIP net.IP
	Status *DpStatusT
}

// FwOpT - type of firewall operation
type FwOpT uint8

// Fw type constants
const (
	DpFwDrop FwOpT = iota + 1
	DpFwFwd
	DpFwRdr
	DpFwTrap
)

// FwDpWorkQ - work queue entry for fw related operation
type FwDpWorkQ struct {
	Work     DpWorkT
	Status   *DpStatusT
	ZoneNum  int
	SrcIP    net.IPNet
	DstIP    net.IPNet
	L4SrcMin uint16
	L4SrcMax uint16
	L4DstMin uint16
	L4DstMax uint16
	Port     uint16
	Pref     uint16
	Proto    uint8
	Mark     int
	FwType   FwOpT
	FwVal1   uint16
	FwVal2   uint32
	FwRecord bool
}

// NatT - type of NAT
type NatT uint8

// nat type constants
const (
	DpSnat NatT = iota + 1
	DpDnat
	DpHsnat
	DpHdnat
	DpFullNat
)

// NatSel - type of nat end-point selection algorithm
type NatSel uint8

// nat selection algorithm constants
const (
	EpRR NatSel = iota + 1
	EpHash
	EpPrio
)

// NatEP - a nat end-point
type NatEP struct {
	XIP      net.IP
	RIP      net.IP
	XPort    uint16
	Weight   uint8
	InActive bool
}

// NatDpWorkQ - work queue entry for nat related operation
type NatDpWorkQ struct {
	Work      DpWorkT
	Status    *DpStatusT
	ZoneNum   int
	ServiceIP net.IP
	L4Port    uint16
	BlockNum  uint16
	DsrMode   bool
	CsumDis   bool
	Proto     uint8
	Mark      int
	NatType   NatT
	EpSel     NatSel
	InActTo   uint64
	EndPoints []NatEP
	SecIP     []net.IP
}

// DpCtInfo - representation of a datapath conntrack information
type DpCtInfo struct {
	DIP     net.IP    `json:"dip"`
	SIP     net.IP    `json:"sip"`
	Dport   uint16    `json:"dport"`
	Sport   uint16    `json:"sport"`
	Proto   string    `json:"proto"`
	CState  string    `json:"cstate"`
	CAct    string    `json:"cact"`
	CI      string    `json:"ci"`
	Packets uint64    `json:"packets"`
	Bytes   uint64    `json:"bytes"`
	Deleted int       `json:"deleted"`
	PKey    []byte    `json:"pkey"`
	PVal    []byte    `json:"pval"`
	LTs     time.Time `json:"lts"`
	NTs     time.Time `json:"nts"`
	XSync   bool      `json:"xsync"`

	// LB Association Data
	ServiceIP  net.IP `json:"serviceip"`
	ServProto  string `json:"servproto"`
	L4ServPort uint16 `json:"l4servproto"`
	BlockNum   uint16 `json:"blocknum"`
}

// UlClDpWorkQ - work queue entry for ul-cl filter related operation
type UlClDpWorkQ struct {
	Work   DpWorkT
	Status *DpStatusT
	MDip   net.IP
	MSip   net.IP
	MTeID  uint32
	Zone   int
	Qfi    uint8
	Mark   int
	TDip   net.IP
	TSip   net.IP
	TTeID  uint32
	Type   DpTunT
}

// Key - outputs a key string for given DpCtInfo pointer
func (ct *DpCtInfo) Key() string {
	return fmt.Sprintf("%s%s%d%d%s", ct.DIP.String(), ct.SIP.String(), ct.Dport, ct.Sport, ct.Proto)
}

// String - stringify the given DpCtInfo
func (ct *DpCtInfo) String() string {
	str := fmt.Sprintf("%s:%d->%s:%d (%s), ", ct.SIP.String(), ct.Sport, ct.DIP.String(), ct.Dport, ct.Proto)
	str += fmt.Sprintf("%s:%s [%v:%v]", ct.CState, ct.CAct, ct.Packets, ct.Bytes)
	return str
}

func (q *PortDpWorkQ) Key() string {
	return fmt.Sprintf("IngVlan:%d,OsPortNum:%d", q.IngVlan, q.OsPortNum)
}

func (q *L2AddrDpWorkQ) Key() string {
	return fmt.Sprintf("L2Addr:%v,BD:%d", q.L2Addr, q.BD)
}

func (q *RouterMacDpWorkQ) Key() string {
	return fmt.Sprintf("L2Addr:%v,TunType:%d,TunID:%d", q.L2Addr, q.TunType, q.TunID)
}

func (q *NextHopDpWorkQ) Key() string {
	return fmt.Sprintf("NextHopNum:%d", q.NextHopNum)
}

func (q *RouteDpWorkQ) Key() string {
	return fmt.Sprintf("Dst:%s", q.Dst.String())
}

func (q *NatDpWorkQ) Key() string {
	return fmt.Sprintf("daddr:%s,mark:%d,dport:%d,l4proto:%d,zone:%d", q.ServiceIP.String(), q.Mark, q.L4Port, q.Proto, q.ZoneNum)
}

// DpRetT - an empty interface to represent immediate operation result
type DpRetT interface {
}

type ArrayMeta struct {
	PortDpWorkQ      []PortDpWorkQ
	L2AddrDpWorkQ    []L2AddrDpWorkQ
	RouteDpWorkQ     []RouteDpWorkQ
	RouterMacDpWorkQ []RouterMacDpWorkQ
	NextHopDpWorkQ   []NextHopDpWorkQ

	MirrDpWorkQ  []MirrDpWorkQ
	PolDpWorkQ   []PolDpWorkQ
	NatDpWorkQ   []NatDpWorkQ
	UlClDpWorkQ  []UlClDpWorkQ
	StatDpWorkQ  []StatDpWorkQ
	TableDpWorkQ []TableDpWorkQ
	FwDpWorkQ    []FwDpWorkQ
	PeerDpWorkQ  []PeerDpWorkQ
}

type MapMeta struct {
	PortDpWorkQ      map[string]PortDpWorkQ
	L2AddrDpWorkQ    map[string]L2AddrDpWorkQ
	RouteDpWorkQ     map[string]RouteDpWorkQ
	RouterMacDpWorkQ map[string]RouterMacDpWorkQ
	NextHopDpWorkQ   map[string]NextHopDpWorkQ

	MirrDpWorkQ  map[string]MirrDpWorkQ
	PolDpWorkQ   map[string]PolDpWorkQ
	NatDpWorkQ   map[string]NatDpWorkQ
	UlClDpWorkQ  map[string]UlClDpWorkQ
	StatDpWorkQ  map[string]StatDpWorkQ
	TableDpWorkQ map[string]TableDpWorkQ
	FwDpWorkQ    map[string]FwDpWorkQ
	PeerDpWorkQ  map[string]PeerDpWorkQ
}

func NewMeta() *MapMeta {
	meta := new(MapMeta)
	meta.MirrDpWorkQ = make(map[string]MirrDpWorkQ)
	meta.PolDpWorkQ = make(map[string]PolDpWorkQ)
	meta.PortDpWorkQ = make(map[string]PortDpWorkQ)
	meta.L2AddrDpWorkQ = make(map[string]L2AddrDpWorkQ)
	meta.RouterMacDpWorkQ = make(map[string]RouterMacDpWorkQ)
	meta.NextHopDpWorkQ = make(map[string]NextHopDpWorkQ)
	meta.RouteDpWorkQ = make(map[string]RouteDpWorkQ)
	meta.NatDpWorkQ = make(map[string]NatDpWorkQ)
	meta.UlClDpWorkQ = make(map[string]UlClDpWorkQ)
	meta.StatDpWorkQ = make(map[string]StatDpWorkQ)
	meta.TableDpWorkQ = make(map[string]TableDpWorkQ)
	meta.FwDpWorkQ = make(map[string]FwDpWorkQ)
	meta.PeerDpWorkQ = make(map[string]PeerDpWorkQ)
	return meta
}
