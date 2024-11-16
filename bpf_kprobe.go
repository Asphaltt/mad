// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	kprobeUpdateMapProgName = "kprobe_update_elem"
	kprobeDeleteMapProgName = "kprobe_delete_elem"
)

type bpfKprobe struct {
	links []link.Link
}

func (bk *bpfKprobe) close() {
	for _, l := range bk.links {
		_ = l.Close()
	}
}

func kprobeFuncs(hooks []string, spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map) (*bpfKprobe, error) {
	var updateMapHooks, deleteMapHooks []string

	for _, hook := range hooks {
		if strings.HasSuffix(hook, "_map_update_elem") {
			updateMapHooks = append(updateMapHooks, hook)
		} else {
			deleteMapHooks = append(deleteMapHooks, hook)
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return nil, err
	}
	defer coll.Close()

	var bk bpfKprobe
	var l link.Link

	defer func() {
		if err != nil {
			bk.close()
		}
	}()

	if len(updateMapHooks) > 0 {
		prog := coll.Programs[kprobeUpdateMapProgName]
		l, err = link.KprobeMulti(prog, link.KprobeMultiOptions{
			Symbols: updateMapHooks,
		})
		if err != nil {
			return nil, err
		}

		bk.links = append(bk.links, l)
	}

	if len(deleteMapHooks) > 0 {
		prog := coll.Programs[kprobeDeleteMapProgName]
		l, err = link.KprobeMulti(prog, link.KprobeMultiOptions{
			Symbols: deleteMapHooks,
		})
		if err != nil {
			return nil, err
		}

		bk.links = append(bk.links, l)
	}

	return &bk, nil
}
