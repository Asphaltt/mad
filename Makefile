# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

GOGEN := go generate
GOBUILD := go build -v -trimpath

BPF_SRC := $(wildcard bpf/*.c bpf/*.h bpf/headers/*.h)
BPF_OBJ := mad_bpfel.o mad_bpfeb.o

.DEFAULT_GOAL := build

$(BPF_OBJ): $(BPF_SRC)
	$(GOGEN)

.PHONY: build
build: $(BPF_OBJ)
	$(GOBUILD) .
