/*
 * Copyright (c) 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BPF_H__
#define BPF_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h>

struct ds;

struct bpf_ops {
    bool (*load)(size_t offset, uint64_t *value, size_t n, void *aux);
    bool (*store)(size_t offset, uint64_t value, size_t n, void *aux);
};

bool bpf_execute(const struct bpf_insn[], size_t n,
                 const struct bpf_ops *, void *aux,
                 uint64_t regs[10]);
void bpf_disassemble(const struct bpf_insn[], size_t n,
                     char **notes, size_t n_notes, struct ds *);

#endif /* bpf.h */
