// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

type bpfMapInfo struct {
	*ebpf.MapInfo
	spec *btf.Spec
}

type bpfMaps struct {
	maps map[uint32]*bpfMapInfo

	kernel *btf.Spec
}

func newBpfMaps(kernel *btf.Spec) *bpfMaps {
	return &bpfMaps{
		maps:   make(map[uint32]*bpfMapInfo),
		kernel: kernel,
	}
}

func (m *bpfMaps) retrieveInfo(id, btfID uint32) error {
	mp, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		return err
	}
	defer mp.Close()

	info, err := mp.Info()
	if err != nil {
		return err
	}

	handle, err := btf.NewHandleFromID(btf.ID(btfID))
	if err != nil {
		return err
	}
	defer handle.Close()

	spec, err := handle.Spec(nil)
	if err != nil {
		return err
	}

	m.maps[id] = &bpfMapInfo{
		MapInfo: info,
		spec:    spec,
	}

	return nil
}

func (m *bpfMaps) mapInfo(id, btfID uint32) (*bpfMapInfo, bool) {
	info, ok := m.maps[id]
	if !ok {
		if err := m.retrieveInfo(id, btfID); err != nil {
			log.Printf("Failed to retrieve map info for ID(%d): %v", id, err)
			return nil, false
		}

		info, ok = m.maps[id]
	}

	return info, ok
}
