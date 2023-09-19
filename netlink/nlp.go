package netlink

import (
	nlf "github.com/flomesh-io/flb/pkg/netlink"
	nlp "github.com/vishvananda/netlink"
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
