// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

//go:generate bpf2go -cc clang mad ./bpf/mad.c -- -g -mcpu=v3 -D__TARGET_ARCH_x86 -I./bpf/headers -Wall
