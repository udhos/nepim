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

/* $Id: usock.h,v 1.9 2010/12/20 13:06:57 evertonm Exp $ */

#ifndef NEPIM_USOCK_H
#define NEPIM_USOCK_H

#include "array.h"

typedef struct nepim_usock_t nepim_usock_t;

typedef struct nepim_usock_set_t nepim_usock_set_t;

/*
  UDP socket info
 */
struct nepim_usock_t {
  int     readers;
  int     writers;
  int     write_soft_errors;
  int     read_soft_errors;
  int64_t good_writes_full;
  int64_t good_writes_partial;
  int64_t good_reads;
};

struct nepim_usock_set_t {
  nepim_array_t array;
};

void nepim_usock_set_init(nepim_usock_set_t *set);

nepim_usock_t *nepim_usock_set_get(const nepim_usock_set_t *set, int index);

void nepim_usock_set_add(nepim_usock_set_t *set, int index);

void nepim_usock_set_del(nepim_usock_set_t *set, int index);

int nepim_usock_writer_add(nepim_usock_set_t *set, int index);
int nepim_usock_writer_del(nepim_usock_set_t *set, int index);
int nepim_usock_reader_add(nepim_usock_set_t *set, int index);
int nepim_usock_reader_del(nepim_usock_set_t *set, int index);

void nepim_usock_write_error(nepim_usock_set_t *set, int index,
			     int local_slot, int remote_slot,
			     int err_no, int verbose);
void nepim_usock_read_error(nepim_usock_set_t *set, int index,
			    int err_no, int verbose);
void nepim_usock_write_good_full(nepim_usock_set_t *set, int index);
void nepim_usock_write_good_partial(nepim_usock_set_t *set, int index);
void nepim_usock_read_good(nepim_usock_set_t *set, int index);

#endif /* NEPIM_USOCK_H */

