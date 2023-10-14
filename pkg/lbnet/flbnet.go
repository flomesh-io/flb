package lbnet

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	opts "github.com/flomesh-io/flb/options"
	"github.com/flomesh-io/flb/pkg/tk"
)

const (
	// RootZone string constant representing root security zone
	RootZone = "root"

	LbnetTiVal = 10
)

type flbNetH struct {
	dp     *DpH
	zn     *ZoneH
	zr     *Zone
	mtx    sync.RWMutex
	ticker *time.Ticker
	tDone  chan bool
	sigCh  chan os.Signal
	wg     sync.WaitGroup
	sumDis bool
	pProbe bool
	logger *tk.Logger
	ready  bool
	self   int
}

var mh flbNetH

func FLBInit(dpHook DpHookInterface, sigCh chan os.Signal, shutdown func()) bool {
	// Initialize logger and specify the log file
	logfile := fmt.Sprintf("%s%s.log", "/var/log/flb", os.Getenv("HOSTNAME"))
	logLevel := LogString2Level(opts.Opts.LogLevel)
	mh.logger = tk.LogItInit(logfile, logLevel, true)

	// Stack trace logger
	defer func() {
		if e := recover(); e != nil {
			tk.LogIt(tk.LogCritical, "%s: %s", e, debug.Stack())
		}
	}()

	mh.self = opts.Opts.ClusterSelf
	mh.sumDis = opts.Opts.CSumDisable
	mh.pProbe = opts.Opts.PassiveEPProbe
	mh.sigCh = sigCh

	mh.dp = DpBrokerInit(dpHook)

	// Initialize the security zone subsystem
	mh.zn = ZoneInit()

	// Add a root zone by default
	mh.zn.ZoneAdd(RootZone)
	mh.zr, _ = mh.zn.Zonefind(RootZone)
	if mh.zr == nil {
		tk.LogIt(tk.LogError, "root zone not found\n")
		return false
	}

	mh.tDone = make(chan bool)
	mh.ticker = time.NewTicker(LbnetTiVal * time.Second)
	mh.wg.Add(1)
	go lbnetTicker(shutdown)
	mh.ready = true

	return true
}

// FLBRun - This routine will not return
func FLBRun() {
	mh.wg.Wait()
}

func lbnetTicker(shutdown func()) {
	for {
		select {
		case <-mh.tDone:
			return
		case sig := <-mh.sigCh:
			if sig == syscall.SIGCHLD {
				var ws syscall.WaitStatus
				var ru syscall.Rusage
				wpid := 1
				try := 0
				for wpid >= 0 && try < 100 {
					wpid, _ = syscall.Wait4(-1, &ws, syscall.WNOHANG, &ru)
					try++
				}
			} else if sig == syscall.SIGHUP || sig == syscall.SIGINT || sig == syscall.SIGTERM {
				tk.LogIt(tk.LogCritical, "Shutdown on sig %v\n", sig)
				// TODO - More subsystem cleanup TBD
				mh.zr.Rules.RuleDestructAll()
				if shutdown != nil {
					shutdown()
				}
			}
		case t := <-mh.ticker.C:
			tk.LogIt(-1, "Tick at %v\n", t)
			// Do any housekeeping activities for security zones
			mh.zn.ZoneTicker()
		}
	}
}
