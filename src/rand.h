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

/* $Id: rand.h,v 1.1 2007/08/17 17:12:48 evertonm Exp $ */

#ifndef NEPIM_RAND_H
#define NEPIM_RAND_H

#include "int.h"

/* Quick and dirty random number generator from NUMERICAL RECIPES IN C:
   THE ART OF SCIENTIFIC COMPUTING (ISBN 0-521-43108-5). */
/* BEWARE: '_qseed_' is assigned! */
#define QRANDOM(_qseed_)  ((_qseed_) = (((_qseed_) * 1664525L) + 1013904223L))

uint32_t nepim_urand_next(long *ctx);
int nepim_rand_next(long *ctx, int min, int max);

#endif /* NEPIM_RAND_H */

