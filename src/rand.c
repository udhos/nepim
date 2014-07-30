/*-GNU-GPL-BEGIN-*
nepim - network pipemeter - measuring network bandwidth between hosts
Copyright (C) 2007  Everton da Silva Marques

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

/* $Id: rand.c,v 1.1 2007/08/17 17:12:48 evertonm Exp $ */

#include <assert.h>

#include "rand.h"

uint32_t nepim_urand_next(long *ctx)
{
  /* FIXME: better generator ? */

  return QRANDOM(*ctx); 
}

int nepim_rand_next(long *ctx, int min, int max)
{
  long rand;

  assert(min <= max);

  /* FIXME: better generator ? */

  rand = QRANDOM(*ctx); 
  if (rand < 0)
    rand = -rand;
  rand = rand % (1 + max - min) + min;

  assert(rand >= min);
  assert(rand <= max);

  return rand;
}
