package bpf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.comflomesh-io/flb/internal"
)

var (
	BpfFs = "/opt/fsmxlb/dp/bpf"
)

func GetMap(mapName string, key, value interface{}) error {
	pinFile := fmt.Sprintf("%s/%s", BpfFs, mapName)
	opts := new(ebpf.LoadPinOptions)
	pinMap, err := ebpf.LoadPinnedMap(pinFile, opts)
	if err != nil {
		return err
	}
	return pinMap.Lookup(key, value)
}

func DeleteMap(mapName string, key interface{}) error {
	pinFile := fmt.Sprintf("%s/%s", BpfFs, mapName)
	opts := new(ebpf.LoadPinOptions)
	pinMap, err := ebpf.LoadPinnedMap(pinFile, opts)
	if err != nil {
		return err
	}
	return pinMap.Delete(key)
}

func UpdateMap(mapName string, key, value interface{}) error {
	pinFile := fmt.Sprintf("%s/%s", BpfFs, mapName)
	opts := new(ebpf.LoadPinOptions)
	pinMap, err := ebpf.LoadPinnedMap(pinFile, opts)
	if err != nil {
		return err
	}
	return pinMap.Update(key, value, ebpf.UpdateAny)
}

func ShowMap(mapName string, key, value interface{}) {
	pinFile := fmt.Sprintf("%s/%s", BpfFs, mapName)
	opts := new(ebpf.LoadPinOptions)
	pinMap, err := ebpf.LoadPinnedMap(pinFile, opts)
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
	pinFile := fmt.Sprintf("%s/%s", BpfFs, mapName)
	opts := new(ebpf.LoadPinOptions)
	pinMap, loadErr := ebpf.LoadPinnedMap(pinFile, opts)
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

var bytesReaderPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Reader)
	},
}

// UnmarshalBytes converts a byte buffer into an arbitrary value.
// Prefer using Map.unmarshalKey and Map.unmarshalValue if possible, since
// those have special cases that allow more types to be encoded.
//
// The common int32 and int64 types are directly handled to avoid
// unnecessary heap allocations as happening in the default case.
func UnmarshalBytes(data interface{}, buf []byte) error {
	switch value := data.(type) {
	case unsafe.Pointer:
		dst := unsafe.Slice((*byte)(value), len(buf))
		copy(dst, buf)
		runtime.KeepAlive(value)
		return nil
	case encoding.BinaryUnmarshaler:
		return value.UnmarshalBinary(buf)
	case *string:
		*value = string(buf)
		return nil
	case *[]byte:
		*value = buf
		return nil
	case *int32:
		if len(buf) < 4 {
			return errors.New("int32 requires 4 bytes")
		}
		*value = int32(internal.NativeEndian.Uint32(buf))
		return nil
	case *uint32:
		if len(buf) < 4 {
			return errors.New("uint32 requires 4 bytes")
		}
		*value = internal.NativeEndian.Uint32(buf)
		return nil
	case *int64:
		if len(buf) < 8 {
			return errors.New("int64 requires 8 bytes")
		}
		*value = int64(internal.NativeEndian.Uint64(buf))
		return nil
	case *uint64:
		if len(buf) < 8 {
			return errors.New("uint64 requires 8 bytes")
		}
		*value = internal.NativeEndian.Uint64(buf)
		return nil
	case string:
		return errors.New("require pointer to string")
	case []byte:
		return errors.New("require pointer to []byte")
	default:
		rd := bytesReaderPool.Get().(*bytes.Reader)
		rd.Reset(buf)
		defer bytesReaderPool.Put(rd)
		if err := binary.Read(rd, internal.NativeEndian, value); err != nil {
			return fmt.Errorf("decoding %T: %v", value, err)
		}
		return nil
	}
}
