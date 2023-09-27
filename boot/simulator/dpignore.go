package main

import (
	. "github.com/flomesh-io/flb/pkg/wq"
)

type DpIgnore struct {
}

func (d *DpIgnore) DpMirrAdd(q *MirrDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpMirrDel(q *MirrDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpPolAdd(q *PolDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpPolDel(q *PolDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpNatLbRuleAdd(q *NatDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpNatLbRuleDel(q *NatDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpFwRuleAdd(w *FwDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpFwRuleDel(w *FwDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpStat(q *StatDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpUlClAdd(w *UlClDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpUlClDel(w *UlClDpWorkQ) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpTableGet(w *TableDpWorkQ) (DpRetT, error) {
	// netlink模拟器不会调用此函数,无须实现
	return nil, nil
}

func (d *DpIgnore) DpCtAdd(w *DpCtInfo) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpCtDel(w *DpCtInfo) int {
	// netlink模拟器不会调用此函数,无须实现
	return 0
}

func (d *DpIgnore) DpCtGetAsync() {
	// netlink模拟器不会调用此函数,无须实现
}

func (d *DpIgnore) DpGetLock() {
	// netlink模拟器不会调用此函数,无须实现
}

func (d *DpIgnore) DpRelLock() {
	// netlink模拟器不会调用此函数,无须实现
}
