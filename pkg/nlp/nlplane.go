package nlp

import "github.com/flomesh-io/flb/pkg/cmn"

var hooks cmn.NlpHookInterface

func NlpRegister(hook cmn.NlpHookInterface) {
	hooks = hook
}

func NlpInit() {
	nlpMonitor()
}
