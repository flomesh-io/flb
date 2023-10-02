package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/flomesh-io/flb/pkg/api"
	"github.com/flomesh-io/flb/pkg/lbnet"
	"github.com/flomesh-io/flb/pkg/tk"
)

var (
	wg     sync.WaitGroup
	sigCh  = make(chan os.Signal, 5)
	tDone  = make(chan bool)
	ticker = time.NewTicker(10 * time.Second)
)

const (
	NetlinkMetaURI = `http://127.0.0.1:18080`
)

//func simpleMain() {
//	wg.Add(1)
//	if success := setResourceLimit(); !success {
//		fmt.Println(`Failed to increase RLIMIT_MEMLOCK limit!`)
//		os.Exit(-1)
//	}
//	dpH := new(DpEbpfH)
//	nDp := flbnet.DpBrokerInit(dpH)
//	go syncDatapathMeta(nDp.ToDpCh)
//	wg.Wait()
//}

func main() {
	wg.Add(1)
	if success := setResourceLimit(); !success {
		tk.LogIt(tk.LogCritical, `Failed to increase RLIMIT_MEMLOCK limit!`)
		os.Exit(-1)
	}

	signal.Notify(sigCh, os.Interrupt, syscall.SIGCHLD, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	loadAttachEBpf()

	dpH := new(DpEbpfH)
	nDp := lbnet.DpBrokerInit(dpH)

	api.DpInit()

	go restfullCliServer(nDp.ToDpCh)
	go syncDatapathMeta(nDp.ToDpCh, getNetlinkMeta)

	go flbTicker()
	wg.Wait()
}

func flbTicker() {
	for {
		select {
		case <-tDone:
			return
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
