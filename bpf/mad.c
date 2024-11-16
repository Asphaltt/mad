// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

volatile const __u32 EVENTS_MAP_ID;
volatile const __u32 MY_PID;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} events SEC(".maps");

struct mad_buff {
    __s32 retval;
    __u32 pid;
    __u8 comm[16];
    __u32 map_id;
    __u32 map_btf_id;
    __u32 btf_id;
    __u16 is_value:1;
    __u16 is_delete:1;
    __u16 is_vmlinux:1;
    __u16 pad:13;
    __u16 nr_bytes;
    __u8 data[2048 - 40];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mad_buff);
} mad_buffers SEC(".maps");

static __always_inline struct mad_buff *
get_mad_buff(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&mad_buffers, &key);
}

struct mad_map_info {
    __u32 id;
    __u32 btf_id;
    __u32 key_size;
    __u32 value_size;
    __u32 key_btf_id;
    __u32 value_btf_id;
    __u32 vmlinux_value_btf_id;
};

static __always_inline void
emit_ringbuf(struct mad_buff *buff, void *data, __u32 btf_id, __u32 data_size)
{
    long ret = -1;
    __u64 size;

    if (data_size <= sizeof(buff->data))
        ret = bpf_probe_read_kernel(&buff->data, data_size, data);
    if (ret < 0)
        return;

    buff->btf_id = btf_id;
    buff->nr_bytes = data_size;
    size = sizeof(*buff) - sizeof(buff->data) + buff->nr_bytes;
    size &= sizeof(*buff) - 1;
    bpf_ringbuf_output(&events, buff, size, 0);
}

static __always_inline void
emit_mad_event(struct mad_map_info *info, bool is_delete, void *key, void *value, __s32 retval)
{
    struct mad_buff *buff;

    buff = get_mad_buff();
    if (!buff)
        return;

    buff->retval = retval;
    buff->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(buff->comm, sizeof(buff->comm));
    buff->map_id = info->id;
    buff->map_btf_id = info->btf_id;
    buff->is_value = 0; /* key */
    buff->is_delete = is_delete;
    buff->is_vmlinux = info->vmlinux_value_btf_id != 0;
    emit_ringbuf(buff, key, info->key_btf_id, info->key_size);

    if (value) {
        buff->is_value = true; /* value */
        emit_ringbuf(buff, value, info->value_btf_id, info->value_size);
    }
}

static __always_inline void
read_bpf_map_info(struct bpf_map *map, struct mad_map_info *info)
{
    BPF_CORE_READ_INTO(&info->btf_id, map, btf, id);
    BPF_CORE_READ_INTO(&info->key_size, map, key_size);
    BPF_CORE_READ_INTO(&info->value_size, map, value_size);
    BPF_CORE_READ_INTO(&info->key_btf_id, map, btf_key_type_id);
    BPF_CORE_READ_INTO(&info->value_btf_id, map, btf_value_type_id);
    BPF_CORE_READ_INTO(&info->vmlinux_value_btf_id, map, btf_vmlinux_value_type_id);
}

static __noinline int
fexit_fn(struct bpf_map *map, void *key, void *value, bool is_delete, long retval)
{
    struct mad_map_info info;
    __u32 map_id, pid;

    if (!key)
        return BPF_OK;

    pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == MY_PID)
        return BPF_OK;

    BPF_CORE_READ_INTO(&map_id, map, id);
    if (map_id == EVENTS_MAP_ID)
        return BPF_OK;

    info.id = map_id;
    read_bpf_map_info(map, &info);
    // bpf_printk("mad, map_id: %u, map_btf_id: %u, key_size: %u, value_size: %u, key_btf_id: %u, value_btf_id: %u, vmlinux_value_btf_id: %u\n",
    //            info.id, info.btf_id, info.key_size, info.value_size, info.key_btf_id, info.value_btf_id, info.vmlinux_value_btf_id);
    emit_mad_event(&info, is_delete, key, value, retval);

    return BPF_OK;
}

SEC("fexit/map_update_elem")
int BPF_PROG(fexit_update_elem, struct bpf_map *map, void *key, void *value, __u64 flags, long retval)
{
    return fexit_fn(map, key, value, false, retval);
}

SEC("fexit/map_delete_elem")
int BPF_PROG(fexit_delete_elem, struct bpf_map *map, void *key, long retval)
{
    return fexit_fn(map, key, NULL, true, retval);
}

char __license[] SEC("license") = "GPL";
