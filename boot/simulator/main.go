package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/jessevdk/go-flags"

	"github.com/flomesh-io/flb/nlp"
	opts "github.com/flomesh-io/flb/options"
	"github.com/flomesh-io/flb/pkg/lbnet"
)

func main() {
	// Parse command-line arguments
	_, err := flags.Parse(&opts.Opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dpHook := initDpCacheH()
	zone, mtx := lbnet.Start(dpHook)

	nlHook := netAPIInit(zone, mtx)
	nlp.NlpRegister(nlHook)
	nlp.NlpInit(opts.Opts.BlackList)

	r := mux.NewRouter()
	r.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(dpHook); err != nil {
			fmt.Println(err.Error())
		}
	}).Methods("GET")

	srv := &http.Server{
		Handler: r,
		Addr:    "0.0.0.0:18080",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		fmt.Println(err.Error())
	}

	tDone := make(chan bool)
	<-tDone
}
