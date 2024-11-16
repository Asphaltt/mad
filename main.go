// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"

	"github.com/Asphaltt/mad/internal/assert"
)

var (
	verbose bool
	hexdump bool
)

func main() {
	flag.BoolVar(&hexdump, "hexdump", false, "Print hexdump of key/value")
	flag.BoolVar(&verbose, "verbose", false, "Print verbose output")
	flag.Parse()

	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock rlimit: %v")

	btfSpec, err := btf.LoadKernelSpec()
	assert.NoErr(err, "Failed to load kernel BTF: %v")

	hooks, err := retrieveHooks(btfSpec)
	assert.NoErr(err, "Failed to retrieve hooks: %v")
	assert.SliceNotEmpty(hooks, "No hooks found")

	spec, err := loadMad()
	assert.NoErr(err, "Failed to load mad bpf spec: %v")

	madBuffers, err := ebpf.NewMap(spec.Maps["mad_buffers"])
	assert.NoErr(err, "Failed to create mad_buffers map: %v")

	events, err := ebpf.NewMap(spec.Maps["events"])
	assert.NoErr(err, "Failed to create events map: %v")
	eventsInfo, err := events.Info()
	assert.NoErr(err, "Failed to get events map info: %v")
	eventsMapID, ok := eventsInfo.ID()
	assert.True(ok, "Failed to get events map ID")

	err = spec.RewriteConstants(map[string]interface{}{
		"EVENTS_MAP_ID": uint32(eventsMapID),
		"MY_PID":        uint32(os.Getpid()),
	})
	assert.NoErr(err, "Failed to rewrite constants: %v")

	reusedMaps := map[string]*ebpf.Map{
		"mad_buffers": madBuffers,
		"events":      events,
	}

	t, err := traceFuncs(hooks, spec, reusedMaps)
	assert.NoVerifierErr(err, "Failed to trace functions: %v")
	defer t.close()

	maps := newBpfMaps(btfSpec)

	reader, err := ringbuf.NewReader(events)
	assert.NoErr(err, "Failed to create ringbuf reader: %v")

	log.Printf("mad is running ..")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		return readEvents(reader, maps)
	})

	assert.NoErr(errg.Wait(), "Error: %v")
}
