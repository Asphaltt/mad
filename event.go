// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	madEventFlagsIndexKeyOrValue = iota
	madEventFlagsIndexUpdateOrDelete
	madEventFlagsIndexMapOrVmlinux
)

type madEventMeta struct {
	Seq      uint32
	Retval   int32
	Pid      uint32
	Comm     [16]byte
	MapID    uint32
	MapBtfID uint32
	BtfID    uint32
	Flags    uint16
	Len      uint16
}

type madEvent struct {
	madEventMeta
	Data [2048 - 44]byte
}

const sizeofMadEvent = uint32(unsafe.Sizeof(madEvent{})) /* sizeof(struct mad_buff) */

func (e *madEvent) isValue() bool {
	return e.Flags&(1<<madEventFlagsIndexKeyOrValue) != 0
}

func (e *madEvent) isDelete() bool {
	return e.Flags&(1<<madEventFlagsIndexUpdateOrDelete) != 0
}

func (e *madEvent) isVmlinux() bool {
	return e.Flags&(1<<madEventFlagsIndexMapOrVmlinux) != 0
}

func readEvents(reader *ringbuf.Reader, maps *bpfMaps) error {
	var rec ringbuf.Record
	rec.RawSample = make([]byte, sizeofMadEvent)

	var sb strings.Builder

	for {
		err := reader.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read record: %w", err)
		}

		outputEvent(rec.RawSample, maps, &sb)

		fmt.Println(sb.String())
		sb.Reset()
	}
}

func nullTermStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}

	if len(b) == 0 {
		return ""
	}

	return unsafe.String(&b[0], len(b))
}

func outputEvent(buff []byte, maps *bpfMaps, sb *strings.Builder) {
	event := (*madEvent)(unsafe.Pointer(&buff[0]))

	info, ok := maps.mapInfo(event.MapID, event.MapBtfID)
	if !ok {
		return
	}

	fmt.Fprintf(sb, "%d: ", event.Seq)

	fmt.Fprintf(sb, "map(%d:%s:%s) ", event.MapID, info.Name, info.Type.String())

	action := "update"
	if event.isDelete() {
		action = "delete"
	}

	fmt.Fprintf(sb, "is %sd by process(%d:%s)\n", action, event.Pid, nullTermStr(event.Comm[:]))

	if event.isValue() {
		fmt.Fprintf(sb, "value: ")
	} else {
		fmt.Fprintf(sb, "key: ")
	}

	eventData := event.Data[:min(event.Len, uint16(len(event.Data)))]
	if hexdump || event.BtfID == 0 {
		fmt.Fprintf(sb, "%s [%d bytes]", hex.EncodeToString(eventData), len(eventData))
	} else {
		spec := info.spec
		if event.isVmlinux() {
			spec = maps.kernel
		}

		typ, err := spec.TypeByID(btf.TypeID(event.BtfID))
		if err != nil {
			fmt.Fprintf(sb, "failed to get type: %v", err)
		} else {
			data, err := mybtf.DumpData(typ, eventData)
			if err != nil {
				fmt.Fprintf(sb, "%s / with err: %v", data, err)
			} else {
				fmt.Fprintf(sb, "%s", data)
			}
		}
	}

	fmt.Fprintln(sb)
}
