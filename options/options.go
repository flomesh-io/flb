package options

import (
	"github.com/jessevdk/go-flags"
)

var Opts struct {
	Version           bool           `short:"v" long:"version" description:"Show flb version"`
	Host              string         `long:"host" description:"the IP to listen on" default:"0.0.0.0" env:"HOST"`
	Port              int            `long:"port" description:"the port to listen on for insecure connections" default:"11111" env:"PORT"`
	TLSHost           string         `long:"tls-host" description:"the IP to listen on for tls, when not specified it's the same as --host" env:"TLS_HOST"`
	TLSPort           int            `long:"tls-port" description:"the port to listen on for secure connections" default:"8091" env:"TLS_PORT"`
	TLSCertificate    flags.Filename `long:"tls-certificate" description:"the certificate to use for secure connections" default:"/opt/flb/cert/server.crt" env:"TLS_CERTIFICATE"`
	TLSCertificateKey flags.Filename `long:"tls-key" description:"the private key to use for secure connections" default:"/opt/flb/cert/server.key" env:"TLS_PRIVATE_KEY"`
	ClusterSelf       int            `long:"self" description:"annonation of self in cluster" default:"0"`
	LogLevel          string         `long:"loglevel" description:"One of debug,info,error,warning,notice,critical,emergency,alert" default:"debug"`
	CPUProfile        string         `long:"cpuprofile" description:"Enable cpu profiling and specify file to use" default:"none" env:"CPUPROF"`
	CSumDisable       bool           `long:"disable-csum" description:"Disable checksum update(experimental)"`
	PassiveEPProbe    bool           `long:"passive-probe" description:"Enable passive liveness probes(experimental)"`
	RssEnable         bool           `long:"rss-enable" description:"Enable rss optimization(experimental)"`
	EgrHooks          bool           `long:"egr-hooks" description:"Enable eBPF egress hooks(experimental)"`
	BlackList         string         `long:"blacklist" description:"Regex string of blacklisted ports" default:"none"`
}
