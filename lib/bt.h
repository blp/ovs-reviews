/* PSPP - a program for statistical analysis.
   Copyright (C) 2007, 2009, 2010, 2011 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#ifndef LIBPSPP_BT_H
#define LIBPSPP_BT_H 1

/* Balanced tree (BT) data structure.

   The client should not need to be aware of the form of
   balancing applied to the balanced tree, as its operation is
   fully encapsulated. */

#include <stdbool.h>
#include <stddef.h>

/* Like BT_DATA, except that a null NODE yields a null pointer result. */
#define BT_NULLABLE_DATA(NODE, STRUCT, MEMBER) \
  ((STRUCT *) bt_nullable_data__ (NODE, offsetof (STRUCT, MEMBER)))

/* Node in a balanced binary tree. */
struct bt_node
  {
    struct bt_node *up;        /* Parent (NULL for root). */
    struct bt_node *down[2];   /* Left child, right child. */
  };

/* Compares nodes A and B, with the tree's AUX.
   Returns a strcmp-like result. */
typedef int bt_compare_func (const struct bt_node *a,
                             const struct bt_node *b,
                             const void *aux);

/* A balanced binary tree. */
struct bt
  {
    struct bt_node *root;       /* Tree's root, NULL if empty. */
    bt_compare_func *compare;   /* To compare nodes. */
    const void *aux;            /* Auxiliary data. */
    size_t size;                /* Current node count. */
    size_t max_size;            /* Max size since last complete rebalance. */
  };
#define BT_INITIALIZER(COMPARE, AUX) { .compare = COMPARE, .aux = AUX }

void bt_init (struct bt *, bt_compare_func *, const void *aux);

struct bt_node *bt_insert (struct bt *, struct bt_node *);
void bt_delete (struct bt *, struct bt_node *);

struct bt_node *bt_find (const struct bt *, const struct bt_node *);
struct bt_node *bt_find_ge (const struct bt *, const struct bt_node *);
struct bt_node *bt_find_le (const struct bt *, const struct bt_node *);

struct bt_node *bt_first (const struct bt *);
struct bt_node *bt_last (const struct bt *);
struct bt_node *bt_find (const struct bt *, const struct bt_node *);
struct bt_node *bt_next (const struct bt *, const struct bt_node *);
struct bt_node *bt_prev (const struct bt *, const struct bt_node *);

struct bt_node *bt_changed (struct bt *, struct bt_node *);
void bt_moved (struct bt *, struct bt_node *);

/* Convenience macros for iteration.

   These macros automatically use BT_DATA to obtain the data elements that
   encapsulate bt nodes, which often saves typing and can make code easier to
   read.  Refer to the large comment near the top of this file for an example.

   These macros evaluate their arguments many times. */
#define BT_FIRST(STRUCT, MEMBER, BT)                        \
  BT_NULLABLE_DATA (bt_first (BT), STRUCT, MEMBER)
#define BT_NEXT(DATA, STRUCT, MEMBER, BT)                           \
  BT_NULLABLE_DATA (bt_next (BT, &(DATA)->MEMBER), STRUCT, MEMBER)
#define BT_FOR_EACH(DATA, STRUCT, MEMBER, BT)       \
  for ((DATA) = BT_FIRST (STRUCT, MEMBER, BT);      \
       (DATA) != NULL;                                  \
       (DATA) = BT_NEXT (DATA, STRUCT, MEMBER, BT))
#define BT_FOR_EACH_SAFE(DATA, NEXT, STRUCT, MEMBER, BT)    \
  for ((DATA) = BT_FIRST (STRUCT, MEMBER, BT);              \
       ((DATA) != NULL                                          \
        ? ((NEXT) = BT_NEXT (DATA, STRUCT, MEMBER, BT), 1)  \
        : 0);                                                   \
       (DATA) = (NEXT))

/* Returns the number of nodes currently in BT. */
static inline size_t bt_count (const struct bt *bt)
{
  return bt->size;
}

/* Return true if BT contains no nodes,
   false if BT contains at least one node. */
static inline bool bt_is_empty (const struct bt *bt)
{
  return bt->size == 0;
}

/* Helper for BT_NULLABLE_DATA (to avoid evaluating its NODE argument more than
   once).  */
static inline void *
bt_nullable_data__ (struct bt_node *node, size_t member_offset)
{
  return node != NULL ? (char *) node - member_offset : NULL;
}

#endif /* libpspp/bt.h */
