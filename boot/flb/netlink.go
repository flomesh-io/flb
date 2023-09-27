package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/cnf/structhash"

	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

func syncDatapathMeta(toDpCh chan interface{}, f func() (*MapMeta, bool)) {
	keepNetlinkMeta := NewMeta()
	for {
		latestNetlinkMeta, once := f()
		updates, deletes := getNetlinkUpdates(keepNetlinkMeta, latestNetlinkMeta)

		if updates != nil {
			for _, v := range updates.MirrDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.PolDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.PortDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.L2AddrDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.RouterMacDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.NextHopDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.RouteDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.NatDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.UlClDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.StatDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.TableDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.FwDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range updates.PeerDpWorkQ {
				shadow := v
				toDpCh <- &shadow
			}
		}

		if deletes != nil {
			for _, v := range deletes.MirrDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.PolDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.PortDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.L2AddrDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.RouterMacDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.NextHopDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.RouteDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.NatDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.UlClDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.StatDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.TableDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.FwDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
			for _, v := range deletes.PeerDpWorkQ {
				v.Work = DpRemove
				shadow := v
				toDpCh <- &shadow
			}
		}
		if once {
			break
		}
		time.Sleep(time.Second)
	}
}

func getNetlinkMeta() (*MapMeta, bool) {
	resp, err := http.Get(NetlinkMetaURI)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	meta := NewMeta()

	err = json.Unmarshal(bytes, meta)
	if err != nil {
		arrayMeta := new(ArrayMeta)
		err = json.Unmarshal(bytes, arrayMeta)
		if err != nil {
			log.Fatal(err)
		} else {
			for _, v := range arrayMeta.PortDpWorkQ {
				meta.PortDpWorkQ[v.Key()] = v
			}
			for _, v := range arrayMeta.L2AddrDpWorkQ {
				meta.L2AddrDpWorkQ[v.Key()] = v
			}
			for _, v := range arrayMeta.RouteDpWorkQ {
				meta.RouteDpWorkQ[v.Key()] = v
			}
			for _, v := range arrayMeta.RouterMacDpWorkQ {
				meta.RouterMacDpWorkQ[v.Key()] = v
			}
			for _, v := range arrayMeta.NextHopDpWorkQ {
				meta.NextHopDpWorkQ[v.Key()] = v
			}
			for _, v := range arrayMeta.NatDpWorkQ {
				meta.NatDpWorkQ[v.Key()] = v
			}
		}
	}

	return meta, false
}

func getNetlinkUpdates(keepMeta, latestMeta *MapMeta) (updates, deletes *MapMeta) {
	updates = NewMeta()
	deletes = NewMeta()

	compareMaps(keepMeta.MirrDpWorkQ, latestMeta.MirrDpWorkQ, updates.MirrDpWorkQ, deletes.MirrDpWorkQ)
	compareMaps(keepMeta.PolDpWorkQ, latestMeta.PolDpWorkQ, updates.PolDpWorkQ, deletes.PolDpWorkQ)
	compareMaps(keepMeta.PortDpWorkQ, latestMeta.PortDpWorkQ, updates.PortDpWorkQ, deletes.PortDpWorkQ)
	compareMaps(keepMeta.L2AddrDpWorkQ, latestMeta.L2AddrDpWorkQ, updates.L2AddrDpWorkQ, deletes.L2AddrDpWorkQ)
	compareMaps(keepMeta.RouterMacDpWorkQ, latestMeta.RouterMacDpWorkQ, updates.RouterMacDpWorkQ, deletes.RouterMacDpWorkQ)
	compareMaps(keepMeta.NextHopDpWorkQ, latestMeta.NextHopDpWorkQ, updates.NextHopDpWorkQ, deletes.NextHopDpWorkQ)
	compareMaps(keepMeta.RouteDpWorkQ, latestMeta.RouteDpWorkQ, updates.RouteDpWorkQ, deletes.RouteDpWorkQ)
	compareMaps(keepMeta.NatDpWorkQ, latestMeta.NatDpWorkQ, updates.NatDpWorkQ, deletes.NatDpWorkQ)
	compareMaps(keepMeta.UlClDpWorkQ, latestMeta.UlClDpWorkQ, updates.UlClDpWorkQ, deletes.UlClDpWorkQ)
	compareMaps(keepMeta.StatDpWorkQ, latestMeta.StatDpWorkQ, updates.StatDpWorkQ, deletes.StatDpWorkQ)
	compareMaps(keepMeta.TableDpWorkQ, latestMeta.TableDpWorkQ, updates.TableDpWorkQ, deletes.TableDpWorkQ)
	compareMaps(keepMeta.FwDpWorkQ, latestMeta.FwDpWorkQ, updates.FwDpWorkQ, deletes.FwDpWorkQ)
	compareMaps(keepMeta.PeerDpWorkQ, latestMeta.PeerDpWorkQ, updates.PeerDpWorkQ, deletes.PeerDpWorkQ)

	return
}

func hashEqual(a, b interface{}) bool {
	aMd5 := structhash.Md5(a, 3)
	bMd5 := structhash.Md5(b, 3)
	if !bytes.Equal(aMd5, bMd5) {
		tk.Debug(a)
		tk.Debug(b)
	}
	return bytes.Equal(aMd5, bMd5)
}

func compareMaps[T any](keepMap, latestMap, updates, deletes map[string]T) {
	if len(keepMap) > 0 {
		for k, keep := range keepMap {
			if len(latestMap) > 0 {
				_, exists := latestMap[k]
				if !exists {
					deletes[k] = keep
					delete(keepMap, k)
				}
			} else {
				deletes[k] = keep
				delete(keepMap, k)
			}
		}
	}
	if len(latestMap) > 0 {
		for k, latest := range latestMap {
			if len(keepMap) > 0 {
				keep, exists := keepMap[k]
				if !exists {
					updates[k] = latest
					keepMap[k] = latest
				} else if !hashEqual(latest, keep) {
					updates[k] = latest
					keepMap[k] = latest
				}
			} else {
				updates[k] = latest
				keepMap[k] = latest
			}
		}
	}
}
