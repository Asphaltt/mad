// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

type bpfTracings struct {
	llock sync.Mutex
	links []link.Link
}

func (t *bpfTracings) close() {
	t.llock.Lock()
	defer t.llock.Unlock()

	// Note: do not close the links in parallel, as there's a mutex lock in the
	// kernel.
	for _, l := range t.links {
		_ = l.Close()
	}
}

func (t *bpfTracings) traceFunc(fnName string, spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map) error {
	spec = spec.Copy()

	isDelete := strings.HasSuffix(fnName, "_delete_elem")

	const fexitUpdateElem = "fexit_update_elem"
	const fexitDeleteElem = "fexit_delete_elem"

	progName := fexitUpdateElem
	if isDelete {
		progName = fexitDeleteElem
		delete(spec.Programs, fexitUpdateElem)
	} else {
		delete(spec.Programs, fexitDeleteElem)
	}

	progSpec := spec.Programs[progName]
	progSpec.AttachTo = fnName
	progSpec.AttachType = ebpf.AttachTraceFExit

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return err
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		return fmt.Errorf("failed to attach %s: %w", fnName, err)
	}

	t.llock.Lock()
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}

func traceFuncs(hooks []string, spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map) (*bpfTracings, error) {
	var t bpfTracings
	var err error

	defer func() {
		if err != nil {
			t.close()
		}
	}()

	var errg errgroup.Group

	slices.Sort(hooks)
	for _, hook := range hooks {
		hook := hook
		if verbose {
			log.Printf("tracing %s", hook)
		}
		errg.Go(func() error {
			return t.traceFunc(hook, spec, reusedMaps)
		})
	}

	if err := errg.Wait(); err != nil {
		return nil, err
	}

	return &t, nil
}
