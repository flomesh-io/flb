package bpf

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf"
)

func LoadMap(mapName string) (*ebpf.Map, error) {
	pinFile := fmt.Sprintf("%s/%s", FLB_DB_MAP_PDIR, mapName)
	opts := new(ebpf.LoadPinOptions)
	return ebpf.LoadPinnedMap(pinFile, opts)
}

func GetMap(mapName string, key, value interface{}) error {
	pinMap, err := LoadMap(mapName)
	if err != nil {
		return err
	}
	return pinMap.Lookup(key, value)
}

func DeleteMap(mapName string, key interface{}) error {
	pinMap, err := LoadMap(mapName)
	if err != nil {
		return err
	}
	return pinMap.Delete(key)
}

func UpdateMap(mapName string, key, value interface{}) error {
	pinMap, err := LoadMap(mapName)
	if err != nil {
		return err
	}
	return pinMap.Update(key, value, ebpf.UpdateAny)
}

func ShowMap(mapName string, key, value interface{}) {
	pinMap, err := LoadMap(mapName)
	if err != nil {
		fmt.Println(err)
		return
	}
	if value != nil {
		entries := pinMap.Iterate()
		for entries.Next(key, value) {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(value, "", " ")
			fmt.Println(mapName, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		}
	} else {
		for pinMap.NextKey(key, key) == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := pinMap.LookupBytes(key)
			fmt.Println(mapName, "key:", string(keyBytes), "=", "value:", valueBytes)
		}
	}
}

func DescMap(mapName string) {
	pinMap, loadErr := LoadMap(mapName)
	if loadErr != nil {
		fmt.Println(loadErr)
		return
	}
	info, infoErr := pinMap.Info()
	if infoErr != nil {
		fmt.Println(infoErr)
		return
	}
	infoBytes, _ := json.MarshalIndent(info, "", " ")
	fmt.Println(string(infoBytes))
}
