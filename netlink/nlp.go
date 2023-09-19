package netlink

import (
	nlp "github.com/vishvananda/netlink"
	nlf "github.comflomesh-io/flb/pkg/netlink"
)

var hooks nlf.NetHookInterface

func NlpRegister(hook nlf.NetHookInterface) {
	hooks = hook
}

func GetLinkNameByIndex(index int) (string, error) {
	brLink, err := nlp.LinkByIndex(index)
	if err != nil {
		return "", err
	}
	return brLink.Attrs().Name, nil
}
