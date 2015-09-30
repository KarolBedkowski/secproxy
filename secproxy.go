package main

import (
	"flag"
	"k.prv/secproxy/admin"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"k.prv/secproxy/resources"
	"k.prv/secproxy/server"
	// _ "net/http/pprof" // /debug/pprof/
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// http://localhost:8000/debug/vars

func main() {
	log := logging.NewLogger("main")

	log.Info("Starting secproxy... ", "ver", config.AppVersion)
	log.Info("Copyright (c) Karol Będkowski, 2015")

	flag.Parse()

	logging.Init()
	globals := config.NewGlobals()

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
		os.Exit(0)
	}()

	log.Info("Setting maxprocs", "numcpu", runtime.NumCPU())
	runtime.GOMAXPROCS(runtime.NumCPU())

	if resources.Init() {
		log.Info("Using embended resources...")
	} else {
		log.Info("Using local files...")
	}

	log.Info("Autostarting endpoints...")
	for _, ep := range globals.GetEndpoints() {
		if ep.Autostart {
			log.Info("Starting endpoint", "endpoint", ep.Name)
			server.StartEndpoint(ep.Name, globals)
		}
	}
	log.Info("All endpoints started")

	log.Info("Starting Admin Panel...")
	admin.StartAdmin(globals)
}
