// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"

	"github.com/cilium/ebpf/btf"
)

func isBpfMap(typ btf.Type) bool {
	ptr, ok := typ.(*btf.Pointer)
	if !ok {
		return false
	}

	strct, ok := ptr.Target.(*btf.Struct)
	if !ok {
		return false
	}

	return strct.Name == "bpf_map"
}

func isVoid(typ btf.Type) bool {
	ptr, ok := typ.(*btf.Pointer)
	if !ok {
		return false
	}

	_, ok = ptr.Target.(*btf.Void)
	return ok
}

func isTgtFunc(typ btf.Type) (string, bool) {
	fn, ok := typ.(*btf.Func)
	if !ok {
		return "", false
	}

	fnName := fn.Name
	fnProto := fn.Type.(*btf.FuncProto)

	if strings.HasSuffix(fnName, "_map_update_elem") && len(fnProto.Params) == 4 {
		if isBpfMap(fnProto.Params[0].Type) && isVoid(fnProto.Params[1].Type) && isVoid(fnProto.Params[2].Type) {
			return fnName, true
		}
	} else if strings.HasSuffix(fnName, "_map_delete_elem") && len(fnProto.Params) == 2 {
		if isBpfMap(fnProto.Params[0].Type) && isVoid(fnProto.Params[1].Type) {
			return fnName, true
		}
	}

	return "", false
}

func retrieveHooks(spec *btf.Spec) ([]string, error) {
	var hooks []string

	iter := spec.Iterate()
	for iter.Next() {
		if name, ok := isTgtFunc(iter.Type); ok {
			hooks = append(hooks, name)
		}
	}

	return hooks, nil
}
