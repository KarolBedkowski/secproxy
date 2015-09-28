package main

import (
	"flag"
	"k.prv/secproxy/admin"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"k.prv/secproxy/resources"
	"k.prv/secproxy/server"
	//	"k.prv/secproxy/admin"
	//	"net/http"
	// _ "net/http/pprof" // /debug/pprof/
	"runtime"
	//"time"
	"os"
	"os/signal"
	"syscall"
)

// http://localhost:8000/debug/vars

func main() {
	log := logging.NewLogger("main")

	log.Info("Starting... ", "ver", config.AppVersion)
	configFilename := flag.String("config", "./config.toml", "Configuration filename")
	debug := flag.Int("debug", 1, "Run in debug mode (1) or normal (0)")
	forceLocalFiles := flag.Bool("forceLocalFiles", false, "Force use local files instead of embended assets")
	localFilesPath := flag.String("localFilesPath", ".", "Path to static and templates directory")
	logFilename := flag.String("log", "./secproxy.log", "Log file name")
	flag.Parse()

	logging.Init(*logFilename, *debug > 0)

	globals := config.NewGlobals(*configFilename, *debug)

	defer func() {
		if e := recover(); e != nil {
			globals.Close()
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
		globals.Close()
		os.Exit(-1)
	}()

	log.Info("Starting ...", "Debug", globals.Debug)

	if !globals.Debug {
		log.Info("NumCPU: %d", runtime.NumCPU())
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	if resources.Init(*forceLocalFiles, *localFilesPath) {
		log.Info("Using embended resources...")
	} else {
		log.Info("Using local files...")
	}

	server.Init(globals)

	log.Info("Autostarting...")
	for _, ep := range globals.GetEndpoints() {
		if ep.Autostart {
			log.Debug("Starting endpoint", "endpoint", ep.Name)
			server.StartEndpoint(ep.Name, globals)
		}
	}

	//	server.StopEndpoint("google", globals)

	log.Info("Starting Admin Panel...")
	admin.StartAdmin(globals)
}
