// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"

	"github.com/Asphaltt/mad/internal/assert"
	"github.com/Asphaltt/mybtf"
)

var (
	verbose bool
	hexdump bool
)

func main() {
	var pid, mapID uint32
	var probe string
	flag.BoolVar(&hexdump, "hexdump", false, "Print hexdump of key/value")
	flag.BoolVar(&verbose, "verbose", false, "Print verbose output")
	flag.Uint32Var(&pid, "pid", 0, "Filter a specific PID")
	flag.Uint32Var(&mapID, "map-id", 0, "Filter a specific map ID")
	flag.StringVar(&probe, "probe", "", "Specify a specific probe method (kprobe, kprobe.multi, fexit)")
	flag.Parse()

	if probe != "" && !slices.Contains([]string{"kprobe", "kprobe.multi", "fexit"}, probe) {
		log.Fatalf("Invalid probe method: %s", probe)
	}

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

	type madCfgs struct {
		EventsMapID uint32
		MyPID       uint32
		PID         uint32
		MapID       uint32
	}

	err = spec.RewriteConstants(map[string]interface{}{
		"CFG": madCfgs{
			EventsMapID: uint32(eventsMapID),
			MyPID:       uint32(os.Getpid()),
			PID:         pid,
			MapID:       mapID,
		},
	})
	assert.NoErr(err, "Failed to rewrite constants: %v")

	reusedMaps := map[string]*ebpf.Map{
		"mad_buffers": madBuffers,
		"events":      events,
	}

	slices.Sort(hooks)
	haveFexit := mybtf.HaveEnumValue(btfSpec, "bpf_attach_type", "BPF_TRACE_FEXIT")
	haveKprobeMulti := mybtf.HaveEnumValue(btfSpec, "bpf_attach_type", "BPF_TRACE_KPROBE_MULTI")
	if probe == "fexit" && !haveFexit {
		log.Fatalf("fexit is not supported by the kernel")
	} else if probe == "kprobe.multi" && !haveKprobeMulti {
		log.Fatalf("kprobe.multi is not supported by the kernel")
	}
	if probe == "" {
		if haveKprobeMulti {
			probe = "kprobe.multi"
		} else if haveFexit {
			probe = "fexit"
		} else {
			probe = "kprobe"
		}
	}
	useFexit := probe == "fexit"
	if useFexit {
		delete(spec.Programs, kprobeUpdateMapProgName)
		delete(spec.Programs, kprobeDeleteMapProgName)
		if verbose {
			log.Printf("Tracing functions with fexit:")
			for _, hook := range hooks {
				fmt.Printf("  %s\n", hook)
			}
		}
		t, err := traceFuncs(hooks, spec, reusedMaps)
		assert.NoVerifierErr(err, "Failed to trace functions with fexit: %v")
		defer t.close()
	} else {
		delete(spec.Programs, fexitUpdateMapProgName)
		delete(spec.Programs, fexitDeleteMapProgName)
		if verbose {
			log.Printf("Tracing functions with %s:", probe)
			for _, hook := range hooks {
				fmt.Printf("  %s\n", hook)
			}
		}
		bk, err := kprobeFuncs(hooks, spec, reusedMaps, probe == "kprobe.multi")
		assert.NoVerifierErr(err, "Failed to trace functions with %s: %v", probe)
		defer bk.close()
	}

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
		return readEvents(reader, maps, useFexit)
	})

	assert.NoErr(errg.Wait(), "Error: %v")
}
