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

/* $Id: usock.c,v 1.13 2014/07/10 06:55:44 evertonm Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "usock.h"

void nepim_usock_set_init(nepim_usock_set_t *set)
{
  nepim_array_init(&set->array);
}

nepim_usock_t *nepim_usock_set_get(const nepim_usock_set_t *set, int index)
{
  return nepim_array_get(&set->array, index);
}

void nepim_usock_set_add(nepim_usock_set_t *set, int index)
{
  nepim_usock_t *us = malloc(sizeof(*us));
  assert(us);

  us->readers = 0;
  us->writers = 0;
  us->write_soft_errors = 0;
  us->read_soft_errors = 0;
  us->good_writes_full = 0;
  us->good_writes_partial = 0;
  us->good_reads = 0;

  nepim_array_add(&set->array, index, us);
}

void nepim_usock_set_del(nepim_usock_set_t *set, int index)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  free(us);
  nepim_array_del(&set->array, index);
}

int nepim_usock_writer_add(nepim_usock_set_t *set, int index)
{
  int w;
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->writers >= 0);

  w = us->writers;

  ++us->writers;

  return w;
}

int nepim_usock_writer_del(nepim_usock_set_t *set, int index)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->writers > 0);

  --us->writers;

  return us->writers;
}

int nepim_usock_reader_add(nepim_usock_set_t *set, int index)
{
  int w;
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->readers >= 0);

  w = us->readers;

  ++us->readers;

  return w;
}

int nepim_usock_reader_del(nepim_usock_set_t *set, int index)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->readers > 0);

  --us->readers;

  return us->readers;
}

void nepim_usock_write_error(nepim_usock_set_t *set, int index,
			     int local_slot, int remote_slot,
			     int err_no, int verbose)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->write_soft_errors >= 0);
  
  ++us->write_soft_errors;
  
  if (verbose)
    fprintf(stderr, 
	    "%d %d-%d: sendto: wr_soft_errors=%d wr_ok_full=%" PRId64 " wr_ok_partial=%" PRId64 " errno=%d: %s\n", 
	    index, local_slot, remote_slot,
	    us->write_soft_errors,
	    us->good_writes_full, us->good_writes_partial,
	    err_no, strerror(err_no));
}

void nepim_usock_read_error(nepim_usock_set_t *set, int index,
			    int err_no, int verbose)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->read_soft_errors >= 0);
  
  ++us->read_soft_errors;
  
  if (verbose)
    fprintf(stderr, 
	    "%d: recvfrom: read_soft_errors=%d good_reads=%" PRId64 " errno=%d: %s\n", 
	    index, us->read_soft_errors, us->good_reads,
	    err_no, strerror(err_no));
}

void nepim_usock_write_good_full(nepim_usock_set_t *set, int index)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->good_writes_full >= 0);
  
  ++us->good_writes_full;
}

void nepim_usock_write_good_partial(nepim_usock_set_t *set, int index)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->good_writes_partial >= 0);
  
  ++us->good_writes_partial;
}

void nepim_usock_read_good(nepim_usock_set_t *set, int index)
{
  nepim_usock_t *us = nepim_usock_set_get(set, index);
  assert(us);
  assert(us->good_reads >= 0);
  
  ++us->good_reads;
}
