package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"

	"github.com/flomesh-io/flb/nlp"
	opts "github.com/flomesh-io/flb/options"
	dp "github.com/flomesh-io/flb/pkg/datapath"
	"github.com/flomesh-io/flb/pkg/lbnet"
	"github.com/flomesh-io/flb/pkg/tk"
)

var (
	wg     sync.WaitGroup
	sigCh  = make(chan os.Signal, 5)
	ticker = time.NewTicker(10 * time.Second)
)

const (
	NetlinkMetaURI = `http://127.0.0.1:18080`
)

func main() {
	// Parse command-line arguments
	_, err := flags.Parse(&opts.Opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	wg.Add(1)

	signal.Notify(sigCh, os.Interrupt, syscall.SIGCHLD, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	nodeNo := uint32(0)
	loadAttachEBpf(nodeNo)

	dp.FLBInit()
	dpHook := new(DpEbpfH)
	zone, mtx := lbnet.Start(dpHook)

	nlHook := netAPIInit(zone, mtx)
	nlHook.
		nlp.NlpRegister(nlHook)
	nlp.NlpInit(opts.Opts.BlackList)

	go flbTicker()

	wg.Wait()
}

func flbTicker() {
	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGCHLD {
				var ws syscall.WaitStatus
				var ru syscall.Rusage
				wpid := 1
				try := 0
				for wpid >= 0 && try < 100 {
					wpid, _ = syscall.Wait4(-1, &ws, syscall.WNOHANG, &ru)
					try++
				}
			} else if sig == syscall.SIGHUP {
				tk.LogIt(tk.LogCritical, "SIGHUP received\n")
			} else if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				tk.LogIt(tk.LogCritical, "Shutdown on signal %v\n", sig)
				unloadEBpf()
				wg.Done()
			}
		case t := <-ticker.C:
			tk.LogIt(-1, "Tick at %v\n", t)
		}
	}
}
