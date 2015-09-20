package main

import (
	"flag"
	"k.prv/secproxy/config"
	log "k.prv/secproxy/logging"
	"k.prv/secproxy/resources"
	"k.prv/secproxy/server"
	"k.prv/secproxy/admin"
	//	"k.prv/secproxy/admin"
	//	"net/http"
	// _ "net/http/pprof" // /debug/pprof/
	"runtime"
	//"time"
)

func main() {
	log.Info("Starting... ver %s", config.AppVersion)
	configFilename := flag.String("config", "./config.toml", "Configuration filename")
	debug := flag.Int("debug", -1, "Run in debug mode (1) or normal (0)")
	forceLocalFiles := flag.Bool("forceLocalFiles", false, "Force use local files instead of embended assets")
	localFilesPath := flag.String("localFilesPath", ".", "Path to static and templates directory")
	logFilename := flag.String("log", "./secproxy.log", "Log file name")
	flag.Parse()

	log.Init(*logFilename, *debug > 0)

	globals := config.NewGlobals(*configFilename, *debug)

	if !globals.Config.Debug {
		log.Info("NumCPU: %d", runtime.NumCPU())
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	if resources.Init(*forceLocalFiles, *localFilesPath) {
		log.Info("Using embended resources...")
	} else {
		log.Info("Using local files...")
	}

	server.Init(globals)

	for epname := range globals.Endpoints.Endpoints {
		server.StartEndpoint(epname, globals)
	}

//	server.StopEndpoint("google", globals)

	admin.StartAdmin(globals)
}
