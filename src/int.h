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

/* $Id: int.h,v 1.6 2006/06/05 15:52:01 evertonm Exp $ */


#ifndef NEPIM_INT_H
#define NEPIM_INT_H

#ifdef HAVE_STDINT
#include <stdint.h>
#elif HAVE_INTTYPES
#include <inttypes.h>
#else

#ifndef __uint8_t_defined
#define __uint8_t_defined
typedef unsigned char           uint8_t;
#endif

#ifndef __uint16_t_defined
#define __uint16_t_defined
typedef unsigned short          uint16_t;
#endif

#ifndef __uint32_t_defined
#define __uint32_t_defined
typedef unsigned int            uint32_t;
#endif

#ifndef __uint64_t_defined
#define __uint64_t_defined
typedef unsigned long long      uint64_t;
#endif

#endif /* HAVE_STDINT */

void nepim_int_sanity();

uint16_t nepim_uint16_read(const void * const buf);
uint32_t nepim_uint32_read(const void * const buf);
uint64_t nepim_uint64_read(const void * const buf);
void nepim_uint16_write(void *buf, uint16_t value);
void nepim_uint32_write(void *buf, uint32_t value);
void nepim_uint64_write(void *buf, uint64_t value);

#endif /* NEPIM_INT_H */
