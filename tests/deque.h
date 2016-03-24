/* PSPP - a program for statistical analysis.
   Copyright (C) 2007, 2011 Free Software Foundation, Inc.

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

/* Deque data structure.

   This code slightly simplifies the implementation of a deque as
   a circular queue.  To use it, declare a "struct deque" and a
   pointer to the element type.  For example, for a deque of
   "int"s:

        struct deque deque;
        int *data;

   To initialize the deque with a initial capacity of 0:

        deque_init_null (&deque);
        data = NULL;

   Alternatively, to initialize the deque with an initial minimum
   capacity of, e.g., 4:

        data = deque_init (&deque, 4, sizeof *data);

   Functions that access elements in the deque return array
   indexes.  This is fairly convenient:

        // Push X at the back of the deque.
        data[deque_push_back (&deque)] = x;

        // Pop off the front of the deque into X.
        x = data[deque_pop_front (&deque)];

        // Obtain the element just past the back of the deque as X.
        x = data[deque_back (&deque, 1)];

   The push functions will not expand the deque on their own.
   Use the deque_expand function if necessary, as in:

        // Push X at the back of the deque, first expanding the
        // deque if necessary.
        if (deque_is_full (&deque))
          data = deque_expand (&deque, data, sizeof *data);
        data[deque_push_back (&deque)] = x;

   Expanding a deque will copy its elements from one memory
   region to another using memcpy.  Thus, your deque elements
   must tolerate copying if their deque is to be expanded. */

#ifndef LIBPSPP_DEQUE_H
#define LIBPSPP_DEQUE_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include "util.h"

/* A deque implemented as a circular buffer. */
struct deque
  {
    size_t capacity;    /* Capacity, which must be a power of 2. */
    size_t front;       /* One past the front of the queue. */
    size_t back;        /* The back of the queue. */
  };

void deque_init_null (struct deque *);
void *deque_init (struct deque *, size_t capacity, size_t elem_size);
void *deque_expand (struct deque *, void *, size_t elem_size);

/* Returns the number of elements currently in DEQUE. */
static inline size_t
deque_count (const struct deque *deque)
{
  return deque->front - deque->back;
}

/* Returns the maximum number of elements that DEQUE can hold at
   any time.  (Use deque_expand to increase a deque's
   capacity.) */
static inline size_t
deque_capacity (const struct deque *deque)
{
  return deque->capacity;
}

/* Returns true if DEQUE is currently empty (contains no
   elements), false otherwise. */
static inline bool
deque_is_empty (const struct deque *deque)
{
  return deque_count (deque) == 0;
}

/* Returns true if DEQUE is currently full (cannot take any more
   elements), false otherwise. */
static inline bool
deque_is_full (const struct deque *deque)
{
  return deque_count (deque) >= deque_capacity (deque);
}

/* Returns the index of the element in DEQUE that is OFFSET
   elements from its front.  A value 0 for OFFSET requests the
   element at the front, a value of 1 the element just behind the
   front, and so on.  OFFSET must be less than the current number
   of elements in DEQUE. */
static inline size_t
deque_front (const struct deque *deque, size_t offset)
{
  ovs_assert (deque_count (deque) > offset);
  return (deque->front - offset - 1) & (deque->capacity - 1);
}

/* Returns the index of the element in DEQUE that is OFFSET
   elements from its back.  A value 0 for OFFSET requests the
   element at the back, a value of 1 the element just ahead of
   the back, and so on.  OFFSET must be less than the current
   number of elements in DEQUE. */
static inline size_t
deque_back (const struct deque *deque, size_t offset)
{
  ovs_assert (deque_count (deque) > offset);
  return (deque->back + offset) & (deque->capacity - 1);
}

/* Adds a new element at the front of DEQUE, which must not be
   full, and returns the index of the new element.  The caller is
   responsible for assigning a value to the returned element. */
static inline size_t
deque_push_front (struct deque *deque)
{
  ovs_assert (!deque_is_full (deque));
  return deque->front++ & (deque->capacity - 1);
}

/* Adds a new element at the back of DEQUE, which must not be
   full, and returns the index of the new element.  The caller is
   responsible for assigning a value to the returned element. */
static inline size_t
deque_push_back (struct deque *deque)
{
  ovs_assert (!deque_is_full (deque));
  return --deque->back & (deque->capacity - 1);
}

/* Pops the front element off DEQUE (which must not be empty) and
   returns its index.  The element may be reused the next time an
   element is pushed into DEQUE or when DEQUE is expanded. */
static inline size_t
deque_pop_front (struct deque *deque)
{
  ovs_assert (!deque_is_empty (deque));
  return --deque->front & (deque->capacity - 1);
}

/* Pops the back element off DEQUE (which must not be empty) and
   returns its index.  The element may be reused the next time
   an element is pushed into DEQUE or when DEQUE is expanded. */
static inline size_t
deque_pop_back (struct deque *deque)
{
  ovs_assert (!deque_is_empty (deque));
  return deque->back++ & (deque->capacity - 1);
}

#endif /* libpspp/deque.h */
