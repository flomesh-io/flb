package options

var Opts struct {
	ClusterSelf    int    `long:"self" description:"annonation of self in cluster" default:"0"`
	LogLevel       string `long:"loglevel" description:"One of debug,info,error,warning,notice,critical,emergency,alert" default:"debug"`
	CSumDisable    bool   `long:"disable-csum" description:"Disable checksum update(experimental)"`
	PassiveEPProbe bool   `long:"passive-probe" description:"Enable passive liveness probes(experimental)"`
	BlackList      string `long:"blacklist" description:"Regex string of blacklisted ports" default:"none"`
}
