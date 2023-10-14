package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

func restfullCliServer(toDpCh chan interface{}) {
	r := mux.NewRouter()
	r.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		bytes, err := io.ReadAll(req.Body)
		if err != nil {
			tk.LogIt(tk.LogError, "error restfull request: %v\n", err)
		} else {
			cliMeta := new(ArrayMeta)
			err = json.Unmarshal(bytes, cliMeta)
			if err != nil {
				tk.LogIt(tk.LogError, "error unmarshal restfull request: %v\n", err)
			} else {
				meta := NewMeta()
				for _, v := range cliMeta.PortDpWorkQ {
					meta.PortDpWorkQ[v.Key()] = v
				}
				for _, v := range cliMeta.L2AddrDpWorkQ {
					meta.L2AddrDpWorkQ[v.Key()] = v
				}
				for _, v := range cliMeta.RouteDpWorkQ {
					meta.RouteDpWorkQ[v.Key()] = v
				}
				for _, v := range cliMeta.RouterMacDpWorkQ {
					meta.RouterMacDpWorkQ[v.Key()] = v
				}
				for _, v := range cliMeta.NextHopDpWorkQ {
					meta.NextHopDpWorkQ[v.Key()] = v
				}
				for _, v := range cliMeta.NatDpWorkQ {
					meta.NatDpWorkQ[v.Key()] = v
				}
				bytes, _ = json.MarshalIndent(meta, "", " ")
				fmt.Println(string(bytes))
				syncDatapathMeta(toDpCh, func() (*MapMeta, bool) {
					return meta, true
				})
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
