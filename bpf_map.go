// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/cilium/ebpf"

type bpfMaps struct {
	maps map[uint32]*ebpf.MapInfo
}

func newBpfMaps() *bpfMaps {
	return &bpfMaps{
		maps: make(map[uint32]*ebpf.MapInfo),
	}
}

func (m bpfMaps) retrieveInfo(id uint32) error {
	mp, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		return err
	}
	defer mp.Close()

	info, err := mp.Info()
	if err != nil {
		return err
	}

	m.maps[id] = info

	return nil
}

func (m *bpfMaps) mapInfo(id uint32) (*ebpf.MapInfo, bool) {
	info, ok := m.maps[id]
	if !ok {
		if err := m.retrieveInfo(id); err != nil {
			return nil, false
		}

		info, ok = m.maps[id]
	}

	return info, ok
}
