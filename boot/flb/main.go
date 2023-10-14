package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jessevdk/go-flags"

	opts "github.com/flomesh-io/flb/options"
	dp "github.com/flomesh-io/flb/pkg/datapath"
	"github.com/flomesh-io/flb/pkg/lbnet"
	"github.com/flomesh-io/flb/pkg/nlp"
)

func main() {
	// Parse command-line arguments
	_, err := flags.Parse(&opts.Opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 5)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGCHLD, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	nodeNo := uint32(0)
	loadAttachEBpf(nodeNo)

	dp.FLBInit()
	dpHook := new(DpEbpfH)
	success := lbnet.FLBInit(dpHook, sigCh, func() {
		unloadEBpf()
	})

	if !success {
		os.Exit(1)
	}

	nlHook := lbnet.NetAPIInit()
	nlp.NlpRegister(nlHook)
	nlp.NlpInit()

	go restCliServer(nlHook)

	lbnet.FLBRun()
}
