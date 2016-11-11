/*
 * Copyright (c) 2009, 2010, 2016 Nicira, Inc.
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

#ifndef UNICODE_H
#define UNICODE_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "compiler.h"

/* Returns true if 'c' is a Unicode code point, otherwise false. */
static inline bool
uc_is_code_point(int c)
{
    return c >= 0 && c <= 0x10ffff;
}

/* Returns true if 'c' is a Unicode code point for a leading surrogate. */
static inline bool
uc_is_leading_surrogate(int c)
{
    return c >= 0xd800 && c <= 0xdbff;
}

/* Returns true if 'c' is a Unicode code point for a trailing surrogate. */
static inline bool
uc_is_trailing_surrogate(int c)
{
    return c >= 0xdc00 && c <= 0xdfff;
}

/* Returns true if 'c' is a Unicode code point for a leading or trailing
 * surrogate. */
static inline bool
uc_is_surrogate(int c)
{
    return c >= 0xd800 && c <= 0xdfff;
}

/* Returns true if 'byte' is valid as the 2nd or later byte in a UTF-8
 * multibyte sequence.
 *
 * Continuation bytes have the form 10xxxxxx. */
static inline bool
utf8_is_continuation_byte(uint8_t byte)
{
    return (byte & 0xc0) == 0x80;
}

/* Returns true if 'byte' can be the initial (or only) byte in a UTF-8
 * multibyte sequence.
 *
 * (This function will mis-identify bytes that may not appear in UTF-8 at all
 * as initial bytes.  However, it will always return a correct answer if 'byte'
 * is part of a valid UTF-8 sequence.)
 *
 * Valid initial bytes have one of the forms 0xxxxxxx, 110xxxxx, 1110xxxx, or
 * 11110xxx. */
static inline bool
utf8_is_initial_byte(uint8_t byte)
{
    return !utf8_is_continuation_byte(byte);
}

int utf16_decode_surrogate_pair(int leading, int trailing);

size_t utf8_length(const char *);
char *utf8_validate(const char *, size_t *lengthp) OVS_WARN_UNUSED_RESULT;

#endif /* unicode.h */
