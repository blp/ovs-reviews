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

#include <config.h>
#include "p4-bpf.h"
#include <linux/bpf.h>
#include "dynamic-string.h"
#include "ofpbuf.h"
#include "p4-parse.h"
#include "shash.h"

struct p4_bpf_stack {
    struct ovs_list list_node;  /* In stack of instances. */

    const struct p4_state *state;
    const struct p4_instance *instance;
    /* int index; */            /* XXX not implemented yet */

    /* The offset to the beginning of the instance is 'base + offset'. */
    int base;                   /* Base register number, -1 if no base reg. */
    int offset;                 /* Offset in bytes from base register. */
};

static struct p4_bpf_stack *
p4_bpf_tos(struct ovs_list *stack)
{
    if (list_is_empty(stack)) {
        return NULL;
    } else {
        return CONTAINER_OF(list_front(stack), struct p4_bpf_stack, list_node);
    }
}

struct p4_bpf_context {
    struct ovs_list stack;
    struct ofpbuf *bpf;
    char **notes;
    size_t n_notes;
    size_t allocated_notes;
    unsigned int regs;
    char *error;
};

static void OVS_PRINTF_FORMAT(2, 3)
p4_bpf_error(struct p4_bpf_context *ctx, const char *format, ...)
{
    if (ctx->error) {
        /* Already have an error, suppress this one since the cascade seems
         * unlikely to be useful. */
        return;
    }

    va_list args;
    va_start(args, format);
    ctx->error = xvasprintf(format, args);
    va_end(args);
}

static void OVS_PRINTF_FORMAT(2, 3)
emit_comment(struct p4_bpf_context *ctx, const char *format, ...)
{
    size_t idx = ctx->bpf->size / sizeof(struct bpf_insn);
    while (idx >= ctx->allocated_notes) {
        ctx->notes = x2nrealloc(ctx->notes, &ctx->allocated_notes,
                                sizeof *ctx->notes);
    }
    while (idx >= ctx->n_notes) {
        ctx->notes[ctx->n_notes++] = NULL;
    }

    va_list args;
    va_start(args, format);
    char *new_note = xvasprintf(format, args);
    va_end(args);

    char *old_note = ctx->notes[idx];
    if (old_note) {
        ctx->notes[idx] = xasprintf("%s\n%s", old_note, new_note);
        free(old_note);
        free(new_note);
    } else {
        ctx->notes[idx] = new_note;
    }
}

static size_t
emit(struct p4_bpf_context *ctx,
     uint8_t code, int dst_reg, int src_reg, int16_t off, int32_t imm)
{
    size_t pos = ctx->bpf->size;
    struct bpf_insn *insn = ofpbuf_put_uninit(ctx->bpf, sizeof *insn);
    insn->code = code;
    insn->dst_reg = dst_reg;
    insn->src_reg = src_reg;
    insn->off = off;
    insn->imm = imm;
    return pos;
}

static void
patch_jump(struct p4_bpf_context *ctx, size_t position)
{
    struct bpf_insn *insn = ofpbuf_at(ctx->bpf, position, sizeof *insn);

    ovs_assert(BPF_CLASS(insn->code) == BPF_JMP);
    ovs_assert(!insn->off);

    emit_comment(ctx, "# jump target from %"PRIuSIZE, position / sizeof *insn);
    insn->off = (ctx->bpf->size - position) / sizeof *insn - 1;
}

static const struct p4_field *
p4_bpf_len_field(const struct p4_instance *instance)
{
    const struct p4_header *header = instance->header;
    ovs_assert(header->length);
    ovs_assert(header->length->type == P4_LEN_MUL);

    const struct p4_field *field;
    if (header->length->subs[0]->type == P4_LEN_CONST &&
        header->length->subs[0]->integer == 4 &&
        header->length->subs[1]->type == P4_LEN_FIELD) {
        field = header->length->subs[1]->field;
    } else if (header->length->subs[1]->type == P4_LEN_CONST &&
        header->length->subs[1]->integer == 4 &&
        header->length->subs[0]->type == P4_LEN_FIELD) {
        field = header->length->subs[0]->field;
    } else {
        OVS_NOT_REACHED();
    }

    ovs_assert(!field->is_signed);
    ovs_assert(!field->is_saturating);
    ovs_assert(field->offset % 8 + field->width <= 8);

    return field;
}

/* Emits "ld #x, r(reg). */
static void
emit_ld_imm(struct p4_bpf_context *ctx, uint64_t x, int reg)
{
    emit(ctx, BPF_LD | BPF_IMM | BPF_DW, reg, 0, 0, x);
    emit(ctx, 0, 0, 0, 0, x >> 32);
}

static int
name_to_reg(const char *name)
{
    return (!strncmp(name, "l2_5", 4) ? 0
            : !strncmp(name, "l3", 2) ? 1
            : !strncmp(name, "l4", 2) ? 2
            : -1);
}

static const char *
reg_to_layer(int reg)
{
    switch (reg) {
    case 0: return " (L2.5 pointer)";
    case 1: return " (L3 pointer)";
    case 2: return " (L4 pointer)";
    default: return "";
    }
}

static void
load_data_ref(struct p4_bpf_context *ctx, const struct p4_state *state,
              const struct p4_data_ref *ref, int reg)
{
    if (ref->type == P4_REF_CONSTANT) {
        /* ld #(constant), r5. */
        emit_ld_imm(ctx, ntohll(ref->constant.value.integer), reg);
        return;
    }

    const struct p4_bpf_stack *s;
    int field_offset;

    if (ref->type == P4_REF_FIELD) {
        const struct p4_field *field = ref->field.field;
        const struct p4_instance *instance = ref->field.instance;

        emit_comment(ctx, "# r%d = %s.%s", reg, instance->name, field->name);

        /* Find the stack node 's' for this field. */
        LIST_FOR_EACH (s, list_node, &ctx->stack) {
            if (s->instance == instance) {
                goto found;
            }
        }
        p4_bpf_error(ctx, "parser %s refers to unextracted instance %s",
                     state->name, instance->name);
        return;

    found:
        field_offset = field->offset;
    } else if (ref->type == P4_REF_CURRENT) {
        emit_comment(ctx, "# r%d = current(%d,%d)",
                     reg, ref->current.offset, ref->width);

        s = p4_bpf_tos(&ctx->stack);
        field_offset = (s->instance->header->min_length * 8
                        + ref->current.offset);

        ovs_assert(!s->instance->header->length);
    } else {
        OVS_NOT_REACHED();
    }

    /* Load the unit containing the field into reg. */
    int min_size = field_offset % 8 + ref->width;
    ovs_assert(min_size <= 64);

    int load_size = (min_size <= 8 ? 8
                     : min_size <= 16 ? 16
                     : min_size <= 32 ? 32
                     : 64);
    int base = s->base;
    if (s->base < 0) {
        /* ld #0, reg. */
        emit_ld_imm(ctx, 0, reg);
        base = reg;
    }

    /* ld disp[base], reg. */
    int disp = field_offset / 8 + s->offset;
    int bpf_size = (load_size == 8 ? BPF_B
                    : load_size == 16 ? BPF_H
                    : load_size == 32 ? BPF_W
                    : BPF_DW);
    emit(ctx, BPF_LDX | BPF_MEM | bpf_size, reg, base, disp, 0);

    /* Shift 'reg' around to get the field in the low bits.  We can
     * only mask 31 bits with an immediate operand so use a pair of
     * shifts instead of shift-and-mask:
     *
     * lshw #lsh, reg.
     * rshw #rsh, reg. */
    int lsh = field_offset % 8;
    int rsh = load_size - (field_offset % 8 + ref->width) + lsh;
    if (lsh) {
        emit(ctx, BPF_ALU64 | BPF_LSH | BPF_K, reg, 0, 0, lsh);
    }
    if (rsh) {
        emit(ctx, BPF_ALU64 | BPF_RSH | BPF_K, reg, 0, 0, rsh);
    }
}

static void
emit_state(struct p4_bpf_context *ctx, const struct p4_state *state)
{
    struct ovs_list *old_tos = ctx->stack.next;
    unsigned int old_regs = ctx->regs;

    const struct p4_statement *statement;
    LIST_FOR_EACH (statement, list_node, &state->statements) {
        if (statement->type == P4_STMT_EXTRACT) {
            struct p4_bpf_stack *tos = p4_bpf_tos(&ctx->stack);

            /* ovs.p4 doesn't use arrays, don't bother to support them yet. */
            ovs_assert(!statement->extract.instance->n);

            /* Check for duplicates. */
            struct p4_bpf_stack *s;
            LIST_FOR_EACH (s, list_node, &ctx->stack) {
                if (s->instance == statement->extract.instance) {
                    p4_bpf_error(ctx, "Duplicate extraction of %s in parse "
                                 " state %s (already extracted in parse state "
                                 "%s)", s->instance->name, state->name,
                                 s->state->name);
                    return;
                }
            }

            s = xzalloc(sizeof *s);
            list_push_front(&ctx->stack, &s->list_node);
            s->state = state;
            s->instance = statement->extract.instance;

            struct ds stack_s = DS_EMPTY_INITIALIZER;
            const struct p4_bpf_stack *node;
            LIST_FOR_EACH_REVERSE (node, list_node, &ctx->stack) {
                ds_put_format(&stack_s, " %s", node->instance->name);
                if (node != s && node->base >= 0 && !node->offset) {
                    ds_put_format(&stack_s, "(r%d)", node->base);
                }
            }
            emit_comment(ctx, "# header stack:%s", ds_cstr(&stack_s));
            ds_destroy(&stack_s);

            /* Figure the layer we're in (if any) based on the instance name,
             * and map that to the output register that reports the start of
             * that layer.  */
            int reg = name_to_reg(s->instance->name);
            if (reg >= 0) {
                if (ctx->regs & (1u << reg)) {
                    /* Not the first encounter with this layer. */
                    reg = -1;
                } else {
                    ctx->regs |= 1u << reg;
                }
            }

            /* Calculate the offset. */
            if (!tos) {
                /* First instance to be parsed. */
                s->base = -1;
                s->offset = 0;

                if (reg >= 0) {
                    emit_comment(ctx, "# r%d%s = 0", reg, reg_to_layer(reg));

                    /* ld #0, reg. */
                    emit_ld_imm(ctx, 0, reg);
                }
            } else if (tos->instance->header->length) {
                /* Previous instance was variable-length. */

                /* Pick a register if we don't already have one. */
                if (reg < 0) {
                    for (reg = 3; ctx->regs & (1u << reg); reg++) {
                        if (reg >= 5) {
                            p4_bpf_error(ctx, "too many variable-length "
                                         "instances");
                            return;
                        }
                    }
                }

                s->base = reg;
                s->offset = 0;

                /* ------------------------------- */
                /* Emit code to compute 's->base'. */
                /* ------------------------------- */

                const struct p4_field *len_field
                    = p4_bpf_len_field(tos->instance);

                /* Add explanatory comment. */
                emit_comment(ctx, "# r%d = offset of %s",
                             reg, s->instance->name);

                /* 1. Compute offset of length field into reg. */
                if (tos->base >= 0) {
                    /* movw r(tos->base), reg. */
                    emit(ctx, BPF_ALU | BPF_MOV | BPF_X, s->base, tos->base,
                         0, 0);
                }
                unsigned int offset = tos->offset + len_field->offset / 8;
                if (offset) {
                    /* addw #(offset), reg.  (Use movw if there's no base.) */
                    int op = tos->base >= 0 ? BPF_ADD : BPF_MOV;
                    emit(ctx, BPF_ALU | op | BPF_K, s->base, 0, 0,
                         offset);
                }

                /* 2. Load the byte containing the length field:
                 * ldb [reg], reg. */
                emit(ctx, BPF_LDX | BPF_MEM | BPF_B, s->base, s->base, 0, 0);

                /* 3. Shift and mask to isolate the length field in the
                 * least-significant bits. */
                int shift = 8 - (len_field->offset % 8 + len_field->width);
                if (shift != 0) {
                    /* rshw #(shift), reg. */
                    emit(ctx, BPF_ALU | BPF_RSH | BPF_K, s->base, 0, 0, shift);
                }
                if (len_field->offset % 8) {
                    /* andw #(mask), reg. */
                    emit(ctx, BPF_ALU | BPF_AND | BPF_K, s->base, 0, 0,
                         (1u << (len_field->width % 8)) - 1);
                }

                /* 4. Multiply by 4: lshw #2, reg. */
                emit(ctx, BPF_ALU | BPF_LSH | BPF_K, s->base, 0, 0, 2);

                /* 5. Add previous base register and offset. */
                if (tos->base >= 0) {
                    /* addw r(tos->base), reg. */
                    emit(ctx, BPF_ALU | BPF_ADD | BPF_X, s->base, tos->base,
                         0, 0);
                }
                if (tos->offset) {
                    /* addw #(tos->offset), reg. */
                    emit(ctx, BPF_ALU | BPF_ADD | BPF_K, s->base, 0, 0,
                         tos->offset);
                }
            } else {
                /* Previous instance was fixed-length. */
                s->base = tos->base;
                s->offset = tos->offset + tos->instance->header->min_length;
                if (reg >= 0) {
                    if (s->base >= 0) {
                        emit_comment(ctx, "# r%d%s = r%d + %d",
                                     reg, reg_to_layer(reg),
                                     s->base, s->offset);

                        /* movw r(s->base), reg. */
                        emit(ctx, BPF_ALU | BPF_MOV | BPF_X, reg, s->base,
                             0, 0);
                        if (s->offset) {
                            /* addw #(s->offset), reg. */
                            emit(ctx, BPF_ALU | BPF_ADD | BPF_K, reg, 0, 0,
                                 s->offset);
                        }
                    } else {
                        emit_comment(ctx, "# r%d%s = %d",
                                     reg, reg_to_layer(reg), s->offset);

                        /* ld #(s->offset), reg. */
                        emit_ld_imm(ctx, s->offset, reg);
                    }

                    s->base = reg;
                    s->offset = 0;
                }
            }
        } else if (statement->type == P4_STMT_SET) {
            const struct p4_instance *instance = statement->set.instance;
            const struct p4_field *field = statement->set.field;

            emit_comment(ctx, "# set_metadata(%s.%s)",
                         instance->name, field->name);

            /* Load source into low bits of r5. */
            load_data_ref(ctx, state, &statement->set.source, 5);

            /* Shift r5 to correct position for metadata: lsh #(lsh), r5. */
            int lsh = 64 - (field->offset % 8 + field->width);
            emit(ctx, BPF_ALU64 | BPF_LSH | BPF_K, 5, 0, 0, lsh);

            /* Load r6 with address of metadata unit: ld #(address), r6. */
            unsigned int address = 0x10000 + field->offset / 8;
            emit_ld_imm(ctx, address, 6);

            /* Load r7 with metadata unit: ld [r6], r7. */
            emit(ctx, BPF_LDX | BPF_MEM | BPF_DW, 7, 6, 0, 0);

            /* Zero 'field' within r7:
             *
             * ld #(mask), r8
             * andd r8, r7 */
            uint64_t mask = ~(((UINT64_C(1) << field->width) - 1) << lsh);
            emit_ld_imm(ctx, mask, 8);
            emit(ctx, BPF_ALU64 | BPF_AND | BPF_X, 8, 7, 0, 0);

            /* Put the new metadata into r7: ord r5, r7. */
            emit(ctx, BPF_ALU64 | BPF_OR | BPF_X, 7, 5, 0, 0);

            /* Store the metadata unit back: std r7, [r6]. */
            emit(ctx, BPF_STX | BPF_MEM | BPF_DW, 6, 7, 0, 0);
        } else {
            OVS_NOT_REACHED();
        }
    }

    /* Load the "select" variables into registers r5, r6, r7, r8. */
    if (state->n_selects > 4) {
        p4_bpf_error(ctx, "too many selects");
        return;
    }
    for (size_t i = 0; i < state->n_selects; i++) {
        load_data_ref(ctx, state, &state->selects[i], 5 + i);
    }

    const struct p4_select_case *c;
    size_t positions[16];
    int n_positions = 0;
    bool saw_default = false;
    LIST_FOR_EACH (c, list_node, &state->cases) {
        if (c->value) {
            int ofs = 0;
            for (size_t i = 0; i < state->n_selects; i++) {
                int reg = i + 5;
                const struct p4_data_ref *ref = &state->selects[i];
                uint64_t value = bitwise_get(c->value, state->select_bytes,
                                             ofs, ref->width);
                uint64_t mask = bitwise_get(c->mask, state->select_bytes,
                                            ofs, ref->width);

                /* Only simple cases are implemented. */
                ovs_assert(!(value >> 31));
                ovs_assert(mask == (UINT64_C(1) << ref->width) - 1);

                /* if (reg != value) jmp next_case. */
                emit(ctx, BPF_JMP | BPF_JNE | BPF_K, reg, 0, state->n_selects - i, value);
                ofs += ref->width;
            }
        } else {
            saw_default = true;
        }

        switch (c->type) {
        case P4_RET_INGRESS:
            emit_comment(ctx, "# ingress");
            emit(ctx, BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
            break;

        case P4_RET_EXCEPTION:
            emit_comment(ctx, "# parse_error");
            emit(ctx, BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
            break;

        case P4_RET_STATE:
            ovs_assert(n_positions < ARRAY_SIZE(positions));
            positions[n_positions++] = emit(ctx, BPF_JMP | BPF_JA, 0, 0, 0, 0);
            break;
        }
    }
    if (!saw_default) {
        /* Emit "exit" as fall through for parse error. */
        emit_comment(ctx, "# fall-through parse_error");
        emit(ctx, BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
    }

    int i = 0;
    LIST_FOR_EACH (c, list_node, &state->cases) {
        if (c->type == P4_RET_STATE) {
            patch_jump(ctx, positions[i++]);
            emit_state(ctx, c->state);
        }
    }

    ctx->regs = old_regs;
    while (old_tos != ctx->stack.next) {
        struct p4_bpf_stack *tos = p4_bpf_tos(&ctx->stack);
        list_remove(&tos->list_node);
        free(tos);
    }
}

char *
p4_bpf_from_parser(const struct p4_parser *parser, struct ofpbuf *bpf,
                   char ***notesp, size_t *n_notesp)
{
    const struct p4_state *state = shash_find_data(&parser->states, "start");
    if (!state) {
        return xstrdup("parser has no start state");
    }

    struct p4_bpf_context ctx;
    list_init(&ctx.stack);
    ctx.bpf = bpf;
    ctx.notes = NULL;
    ctx.n_notes = 0;
    ctx.allocated_notes = 0;
    ctx.regs = 0;
    ctx.error = NULL;

    emit_state(&ctx, state);

    if (notesp) {
        *notesp = ctx.notes;
        *n_notesp = ctx.n_notes;
    } else {
        for (size_t i = 0; i < ctx.n_notes; i++) {
            free(ctx.notes[i]);
        }
        free(ctx.notes);
    }

    return ctx.error;
}
