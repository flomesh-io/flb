package lbnet

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"

	opts "github.com/flomesh-io/flb/options"
	"github.com/flomesh-io/flb/pkg/tk"
)

const (
	// RootZone string constant representing root security zone
	RootZone = "root"
)

type flbNetH struct {
	dp     *DpH
	zn     *ZoneH
	zr     *Zone
	mtx    sync.RWMutex
	tDone  chan bool
	sigCh  chan os.Signal
	sumDis bool
	pProbe bool
	logger *tk.Logger
	ready  bool
	self   int
}

var mh flbNetH

func Start(dph DpHookInterface) (*Zone, *sync.RWMutex) {
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

	mh.dp = DpBrokerInit(dph)

	// Initialize the security zone subsystem
	mh.zn = ZoneInit()

	// Add a root zone by default
	mh.zn.ZoneAdd(RootZone)
	mh.zr, _ = mh.zn.Zonefind(RootZone)
	if mh.zr == nil {
		tk.LogIt(tk.LogError, "root zone not found\n")
		return nil, nil
	}

	mh.tDone = make(chan bool)

	mh.ready = true

	return mh.zr, &mh.mtx
}
