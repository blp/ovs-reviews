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

/* Balanced tree (BT) data structure.

   The client should not need to be aware of the form of
   balancing applied to the balanced tree, as its operation is
   fully encapsulated.  The current implementation is a scapegoat
   tree.  Scapegoat trees have the advantage over many other
   forms of balanced trees that they do not store any additional
   information in each node; thus, they are slightly more
   space-efficient than, say, red-black or AVL trees.  Compared
   to splay trees, scapegoat trees provide guaranteed logarithmic
   worst-case search time and do not restructure the tree during
   a search.

   For information on scapegoat trees, see Galperin and Rivest,
   "Scapegoat Trees", Proc. 4th ACM-SIAM Symposium on Discrete
   Algorithms, or <http://en.wikipedia.org/wiki/Scapegoat_tree>,
   which includes source code and links to other resources, such
   as the Galperin and Rivest paper.

   One potentially tricky part of scapegoat tree design is the
   choice of alpha, which is a real constant that must be greater
   than 0.5 and less than 1.  We must be able to efficiently
   calculate h_alpha = floor(log(n)/log(1/alpha)) for integer n >
   0.  One way to do so would be to maintain a table relating
   h_alpha to the minimum value of n that yields that h_alpha.
   Then, we can track the value of h_alpha(n) in the number of
   nodes in the tree n as nodes are inserted and deleted.

   This implementation uses a different approach.  We choose
   alpha = sqrt(2)/2 = 1/sqrt(2) ~= .707.  Then, computing
   h_alpha is a matter of computing a logarithm in base sqrt(2).
   This is easy: we simply compute twice the base-2 logarithm,
   then adjust upward by 1 if necessary.  See calculate_h_alpha
   for details. */

/* These library routines have no external dependencies other
   than the standard C library.

   If you add routines in this file, please add a corresponding
   test to bt-test.c.  This test program should achieve 100%
   coverage of lines and branches in this code, as reported by
   "gcov -b". */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bt.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "util.h"

static void rebalance_subtree (struct bt *, struct bt_node *, size_t);

static struct bt_node **down_link (struct bt *, struct bt_node *);
static inline struct bt_node *sibling (struct bt_node *p);
static size_t count_nodes_in_subtree (const struct bt_node *);

static inline int floor_log2 (size_t);
static inline int calculate_h_alpha (size_t);

/* Initializes BT as an empty BT that uses the given COMPARE
   function, passing in AUX as auxiliary data. */
void
bt_init (struct bt *bt, bt_compare_func *compare, const void *aux)
{
  bt->root = NULL;
  bt->compare = compare;
  bt->aux = aux;
  bt->size = 0;
  bt->max_size = 0;
}

/* Inserts the given NODE into BT.
   Returns a null pointer if successful.
   Returns the existing node already in BT equal to NODE, on
   failure. */
struct bt_node *
bt_insert (struct bt *bt, struct bt_node *node)
{
  int depth = 0;

  node->down[0] = NULL;
  node->down[1] = NULL;

  if (bt->root == NULL)
    {
      bt->root = node;
      node->up = NULL;
    }
  else
    {
      struct bt_node *p = bt->root;
      for (;;)
        {
          int cmp, dir;

          cmp = bt->compare (node, p, bt->aux);
          if (cmp == 0)
            return p;
          depth++;

          dir = cmp > 0;
          if (p->down[dir] == NULL)
            {
              p->down[dir] = node;
              node->up = p;
              break;
            }
          p = p->down[dir];
        }
    }

  bt->size++;
  if (bt->size > bt->max_size)
    bt->max_size = bt->size;

  if (depth > calculate_h_alpha (bt->size))
    {
      /* We use the "alternative" method of finding a scapegoat
         node described by Galperin and Rivest. */
      struct bt_node *s = node;
      size_t size = 1;
      int i;

      for (i = 1; ; i++)
        if (i < depth)
          {
            size += 1 + count_nodes_in_subtree (sibling (s));
            s = s->up;
            if (i > calculate_h_alpha (size))
              {
                rebalance_subtree (bt, s, size);
                break;
              }
          }
        else
          {
            rebalance_subtree (bt, bt->root, bt->size);
            bt->max_size = bt->size;
            break;
          }
    }

  return NULL;
}

/* Deletes P from BT. */
void
bt_delete (struct bt *bt, struct bt_node *p)
{
  struct bt_node **q = down_link (bt, p);
  struct bt_node *r = p->down[1];
  if (r == NULL)
    {
      *q = p->down[0];
      if (*q)
        (*q)->up = p->up;
    }
  else if (r->down[0] == NULL)
    {
      r->down[0] = p->down[0];
      *q = r;
      r->up = p->up;
      if (r->down[0] != NULL)
        r->down[0]->up = r;
    }
  else
    {
      struct bt_node *s = r->down[0];
      while (s->down[0] != NULL)
        s = s->down[0];
      r = s->up;
      r->down[0] = s->down[1];
      s->down[0] = p->down[0];
      s->down[1] = p->down[1];
      *q = s;
      if (s->down[0] != NULL)
        s->down[0]->up = s;
      s->down[1]->up = s;
      s->up = p->up;
      if (r->down[0] != NULL)
        r->down[0]->up = r;
    }
  bt->size--;

  /* We approximate .707 as .75 here.  This is conservative: it
     will cause us to do a little more rebalancing than strictly
     necessary to maintain the scapegoat tree's height
     invariant. */
  if (bt->size < bt->max_size * 3 / 4 && bt->size > 0)
    {
      rebalance_subtree (bt, bt->root, bt->size);
      bt->max_size = bt->size;
    }
}

/* Returns the node with minimum value in BT, or a null pointer
   if BT is empty. */
struct bt_node *
bt_first (const struct bt *bt)
{
  struct bt_node *p = bt->root;
  if (p != NULL)
    while (p->down[0] != NULL)
      p = p->down[0];
  return p;
}

/* Returns the node with maximum value in BT, or a null pointer
   if BT is empty. */
struct bt_node *
bt_last (const struct bt *bt)
{
  struct bt_node *p = bt->root;
  if (p != NULL)
    while (p->down[1] != NULL)
      p = p->down[1];
  return p;
}

/* Searches BT for a node equal to TARGET.
   Returns the node if found, or a null pointer otherwise. */
struct bt_node *
bt_find (const struct bt *bt, const struct bt_node *target)
{
  const struct bt_node *p;
  int cmp;

  for (p = bt->root; p != NULL; p = p->down[cmp > 0])
    {
      cmp = bt->compare (target, p, bt->aux);
      if (cmp == 0)
        return CONST_CAST (struct bt_node *, p);
    }

  return NULL;
}

/* Searches BT for, and returns, the first node in in-order whose
   value is greater than or equal to TARGET.  Returns a null
   pointer if all nodes in BT are less than TARGET.

   Another way to look at the return value is that it is the node
   that would be returned by "bt_next (BT, TARGET)" if TARGET
   were inserted in BT (assuming that TARGET would not be a
   duplicate). */
struct bt_node *
bt_find_ge (const struct bt *bt, const struct bt_node *target)
{
  const struct bt_node *p = bt->root;
  const struct bt_node *q = NULL;
  while (p != NULL)
    {
      int cmp = bt->compare (target, p, bt->aux);
      if (cmp > 0)
        p = p->down[1];
      else
        {
          q = p;
          if (cmp < 0)
            p = p->down[0];
          else
            break;
        }
    }
  return CONST_CAST (struct bt_node *, q);
}

/* Searches BT for, and returns, the last node in in-order whose
   value is less than or equal to TARGET, which should not be in
   BT.  Returns a null pointer if all nodes in BT are greater
   than TARGET.

   Another way to look at the return value is that it is the node
   that would be returned by "bt_prev (BT, TARGET)" if TARGET
   were inserted in BT (assuming that TARGET would not be a
   duplicate). */
struct bt_node *
bt_find_le (const struct bt *bt, const struct bt_node *target)
{
  const struct bt_node *p = bt->root;
  const struct bt_node *q = NULL;
  while (p != NULL)
    {
      int cmp = bt->compare (target, p, bt->aux);
      if (cmp < 0)
        p = p->down[0];
      else
        {
          q = p;
          if (cmp > 0)
            p = p->down[1];
          else
            break;
        }
    }
  return CONST_CAST (struct bt_node *, q);
}

/* Returns the node in BT following P in in-order.
   If P is null, returns the minimum node in BT.
   Returns a null pointer if P is the maximum node in BT or if P
   is null and BT is empty. */
struct bt_node *
bt_next (const struct bt *bt, const struct bt_node *p)
{
  if (p == NULL)
    return bt_first (bt);
  else if (p->down[1] == NULL)
    {
      struct bt_node *q;
      for (q = p->up; ; p = q, q = q->up)
        if (q == NULL || p == q->down[0])
          return q;
    }
  else
    {
      p = p->down[1];
      while (p->down[0] != NULL)
        p = p->down[0];
      return CONST_CAST (struct bt_node *, p);
    }
}

/* Returns the node in BT preceding P in in-order.
   If P is null, returns the maximum node in BT.
   Returns a null pointer if P is the minimum node in BT or if P
   is null and BT is empty. */
struct bt_node *
bt_prev (const struct bt *bt, const struct bt_node *p)
{
  if (p == NULL)
    return bt_last (bt);
  else if (p->down[0] == NULL)
    {
      struct bt_node *q;
      for (q = p->up; ; p = q, q = q->up)
        if (q == NULL || p == q->down[1])
          return q;
    }
  else
    {
      p = p->down[0];
      while (p->down[1] != NULL)
        p = p->down[1];
      return CONST_CAST (struct bt_node *, p);
    }
}

/* Moves P around in BT to compensate for its key having
   changed.  Returns a null pointer if successful.  If P's new
   value is equal to that of some other node in BT, returns the
   other node after removing P from BT.

   This function is an optimization only if it is likely that P
   can actually retain its relative position in BT, e.g. its key
   has only been adjusted slightly.  Otherwise, it is more
   efficient to simply remove P from BT, change its key, and
   re-insert P.

   It is not safe to update more than one node's key, then to
   call this function for each node.  Instead, update a single
   node's key, call this function, update another node's key, and
   so on.  Alternatively, remove all affected nodes from the
   tree, update their keys, then re-insert all of them. */
struct bt_node *
bt_changed (struct bt *bt, struct bt_node *p)
{
  struct bt_node *prev = bt_prev (bt, p);
  struct bt_node *next = bt_next (bt, p);

  if ((prev != NULL && bt->compare (prev, p, bt->aux) >= 0)
      || (next != NULL && bt->compare (p, next, bt->aux) >= 0))
    {
      bt_delete (bt, p);
      return bt_insert (bt, p);
    }
  return NULL;
 }

/* BT nodes may be moved around in memory as necessary, e.g. as
   the result of an realloc operation on a block that contains a
   node.  Once this is done, call this function passing node P
   that was moved and its BT before attempting any other
   operation on BT.

   It is not safe to move more than one node, then to call this
   function for each node.  Instead, move a single node, call
   this function, move another node, and so on.  Alternatively,
   remove all affected nodes from the tree, move them, then
   re-insert all of them. */
void
bt_moved (struct bt *bt, struct bt_node *p)
{
  if (p->up != NULL)
    {
      int d = p->up->down[0] == NULL || bt->compare (p, p->up, bt->aux) > 0;
      p->up->down[d] = p;
    }
  else
    bt->root = p;
  if (p->down[0] != NULL)
    p->down[0]->up = p;
  if (p->down[1] != NULL)
    p->down[1]->up = p;
}

/* Tree rebalancing.

   This algorithm is from Q. F. Stout and B. L. Warren, "Tree
   Rebalancing in Optimal Time and Space", CACM 29(1986):9,
   pp. 902-908.  It uses O(N) time and O(1) space to rebalance a
   subtree that contains N nodes. */

static void tree_to_vine (struct bt_node **);
static void vine_to_tree (struct bt_node **, size_t count);

/* Rebalances the subtree in BT rooted at SUBTREE, which contains
   exactly COUNT nodes. */
static void
rebalance_subtree (struct bt *bt, struct bt_node *subtree, size_t count)
{
  struct bt_node *up = subtree->up;
  struct bt_node **q = down_link (bt, subtree);
  tree_to_vine (q);
  vine_to_tree (q, count);
  (*q)->up = up;
}

/* Converts the subtree rooted at *Q into a vine (a binary search
   tree in which all the right links are null), and updates *Q to
   point to the new root of the subtree. */
static void
tree_to_vine (struct bt_node **q)
{
  struct bt_node *p = *q;
  while (p != NULL)
    if (p->down[1] == NULL)
      {
        q = &p->down[0];
        p = *q;
      }
    else
      {
        struct bt_node *r = p->down[1];
        p->down[1] = r->down[0];
        r->down[0] = p;
        p = r;
        *q = r;
      }
}

/* Performs a compression transformation COUNT times, starting at
   *Q, and updates *Q to point to the new root of the subtree. */
static void
compress (struct bt_node **q, unsigned long count)
{
  while (count--)
    {
      struct bt_node *red = *q;
      struct bt_node *black = red->down[0];

      *q = black;
      red->down[0] = black->down[1];
      black->down[1] = red;
      red->up = black;
      if (red->down[0] != NULL)
        red->down[0]->up = red;
      q = &black->down[0];
    }
}

/* Converts the vine rooted at *Q, which contains exactly COUNT
   nodes, into a balanced tree, and updates *Q to point to the
   new root of the balanced tree. */
static void
vine_to_tree (struct bt_node **q, size_t count)
{
  size_t leaf_nodes = count + 1 - ((size_t) 1 << floor_log2 (count + 1));
  size_t vine_nodes = count - leaf_nodes;

  compress (q, leaf_nodes);
  while (vine_nodes > 1)
    {
      vine_nodes /= 2;
      compress (q, vine_nodes);
    }
  while ((*q)->down[0] != NULL)
    {
      (*q)->down[0]->up = *q;
      q = &(*q)->down[0];
    }
}

/* Other binary tree helper functions. */

/* Returns the address of the pointer that points down to P
   within BT. */
static struct bt_node **
down_link (struct bt *bt, struct bt_node *p)
{
  struct bt_node *q = p->up;
  return q != NULL ? &q->down[q->down[0] != p] : &bt->root;
}

/* Returns node P's sibling; that is, the other child of its
   parent.  P must not be the root. */
static inline struct bt_node *
sibling (struct bt_node *p)
{
  struct bt_node *q = p->up;
  return q->down[q->down[0] == p];
}

/* Returns the number of nodes in the given SUBTREE. */
static size_t
count_nodes_in_subtree (const struct bt_node *subtree)
{
  /* This is an in-order traversal modified to iterate only the
     nodes in SUBTREE. */
  size_t count = 0;
  if (subtree != NULL)
    {
      const struct bt_node *p = subtree;
      while (p->down[0] != NULL)
        p = p->down[0];
      for (;;)
        {
          count++;
          if (p->down[1] != NULL)
            {
              p = p->down[1];
              while (p->down[0] != NULL)
                p = p->down[0];
            }
          else
            {
              for (;;)
                {
                  const struct bt_node *q;
                  if (p == subtree)
                    goto done;
                  q = p;
                  p = p->up;
                  if (p->down[0] == q)
                    break;
                }
            }
        }
    }
 done:
  return count;
}

/* Arithmetic. */

/* Returns the number of high-order 0-bits in X.
   Undefined if X is zero. */
static inline int
count_leading_zeros (size_t x)
{
#if __GNUC__ >= 4
#if SIZE_MAX > ULONG_MAX
  return __builtin_clzll (x);
#elif SIZE_MAX > UINT_MAX
  return __builtin_clzl (x);
#else
  return __builtin_clz (x);
#endif
#else
  /* This algorithm is from _Hacker's Delight_ section 5.3. */
  size_t y;
  int n;

#define COUNT_STEP(BITS)                        \
        y = x >> BITS;                          \
        if (y != 0)                             \
          {                                     \
            n -= BITS;                          \
            x = y;                              \
          }

  n = sizeof (size_t) * CHAR_BIT;
#if SIZE_MAX >> 31 >> 31 >> 2
  COUNT_STEP (64);
#endif
#if SIZE_MAX >> 31 >> 1
  COUNT_STEP (32);
#endif
  COUNT_STEP (16);
  COUNT_STEP (8);
  COUNT_STEP (4);
  COUNT_STEP (2);
  y = x >> 1;
  return y != 0 ? n - 2 : n - x;
#endif
}

/* Returns floor(log2(x)).
   Undefined if X is zero. */
static inline int
floor_log2 (size_t x)
{
  return sizeof (size_t) * CHAR_BIT - 1 - count_leading_zeros (x);
}

/* Returns floor(pow(sqrt(2), x * 2 + 1)).
   Defined for X from 0 up to the number of bits in size_t minus
   1. */
static inline size_t
pow_sqrt2 (int x)
{
  /* These constants are sqrt(2) multiplied by 2**63 or 2**31,
     respectively, and then rounded to nearest. */
#if SIZE_MAX >> 31 >> 1
  return (UINT64_C(0xb504f333f9de6484) >> (63 - x)) + 1;
#else
  return (0xb504f334 >> (31 - x)) + 1;
#endif
}

/* Returns floor(log(n)/log(sqrt(2))).
   Undefined if N is 0. */
static inline int
calculate_h_alpha (size_t n)
{
  int log2 = floor_log2 (n);

  /* The correct answer is either 2 * log2 or one more.  So we
     see if n >= pow(sqrt(2), 2 * log2 + 1) and if so, add 1. */
  return (2 * log2) + (n >= pow_sqrt2 (log2));
}

