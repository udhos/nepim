/*-GNU-GPL-BEGIN-*
nepim - network pipemeter - measuring network bandwidth between hosts
Copyright (C) 2005  Everton da Silva Marques

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING; if not, write to the
Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
MA 02110-1301 USA
*-GNU-GPL-END-*/

/* $Id: int.c,v 1.6 2006/06/05 15:52:01 evertonm Exp $ */


#include <assert.h>

#include "int.h"


static void uint16_sanity(const uint16_t u16)
{
  uint8_t buf[8];
  nepim_uint16_write(buf, u16);
  
  assert(nepim_uint16_read(buf) == u16);
}

static void uint32_sanity(const uint32_t u32)
{
  uint8_t buf[8];
  nepim_uint32_write(buf, u32);
  
  assert(nepim_uint32_read(buf) == u32);
}

static void uint64_sanity(const uint64_t u64)
{
  uint8_t buf[8];
  nepim_uint64_write(buf, u64);
  
  assert(nepim_uint64_read(buf) == u64);
}

void nepim_int_sanity()
{
  assert(sizeof(uint8_t)  == 1);
  assert(sizeof(uint16_t) == 2);
  assert(sizeof(uint32_t) == 4);
  assert(sizeof(uint64_t) == 8);

  uint16_sanity(0x1122);
  uint16_sanity(0x2211);
  uint16_sanity(0x00FF);
  uint16_sanity(0xFF00);
  uint32_sanity(0x11223344);
  uint32_sanity(0x44332211);
  uint32_sanity(0x00FF00FF);
  uint32_sanity(0xFF00FF00);
  uint64_sanity(0x1122334455667788LL);
  uint64_sanity(0x8877665544332211LL);
  uint64_sanity(0x00FF00FF00FF00FFLL);
  uint64_sanity(0xFF00FF00FF00FF00LL);
}

uint16_t nepim_uint16_read(const void * const buf)
{
  uint16_t value;

  value = ((const uint8_t *) buf)[0];
  value *= 256;
  value += ((const uint8_t *) buf)[1];

  return value;
}

uint32_t nepim_uint32_read(const void * const buf)
{
  uint32_t value;

  value = ((const uint8_t *) buf)[0];
  value *= 256;
  value += ((const uint8_t *) buf)[1];
  value *= 256;
  value += ((const uint8_t *) buf)[2];
  value *= 256;
  value += ((const uint8_t *) buf)[3];

  return value;
}

uint64_t nepim_uint64_read(const void * const buf)
{
  const uint8_t * i = buf;
  const uint8_t * const past_end = i + 8;
  uint64_t value;

  value = *i;

  for (++i; i < past_end; ++i) {
    value *= 256;
    value += *i;
  }

  return value;
}

void nepim_uint16_write(void *buf, uint16_t value)
{
  ((uint8_t *) buf)[0] = value / 256;
  ((uint8_t *) buf)[1] = value % 256;
}

void nepim_uint32_write(void *buf, uint32_t value)
{
  int i;

  for (i = 3; i >= 0; --i, value /= 256)
    ((uint8_t *) buf)[i] = value % 256;
}

void nepim_uint64_write(void *buf, uint64_t value)
{
  int i;

  for (i = 7; i >= 0; --i, value /= 256)
    ((uint8_t *) buf)[i] = value % 256;
}
