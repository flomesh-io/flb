package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/flomesh-io/flb/pkg/cmn"
	"github.com/flomesh-io/flb/pkg/tk"
)

type CliMeta struct {
	LbRules []*cmn.LbRuleMod
}

func restCliServer(cliHook cmn.CliHookInterface) {
	r := mux.NewRouter()
	r.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		bytes, err := io.ReadAll(req.Body)
		if err != nil {
			tk.LogIt(tk.LogError, "error restfull request: %v\n", err)
		} else {
			cliMeta := new(CliMeta)
			err = json.Unmarshal(bytes, cliMeta)
			if err != nil {
				tk.LogIt(tk.LogError, "error unmarshal restfull request: %v\n", err)
			} else {
				for _, lbRule := range cliMeta.LbRules {
					if _, err = cliHook.NetLbRuleAdd(lbRule); err != nil {
						tk.LogIt(tk.LogError, "error NetLbRuleAdd: %v\n", err)
						break
					}
				}
			}
		}
		res.Header().Set("Content-Type", "application/json")
		if err == nil {
			res.Write([]byte("\n\nSuccess!\n\n"))
		} else {
			res.Write([]byte("\n\nFailure!\n\n"))
		}
	}).Methods("PUT")

	srv := &http.Server{
		Handler: r,
		Addr:    "0.0.0.0:19090",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		fmt.Println(err.Error())
	}
}
