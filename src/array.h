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

/* $Id: array.h,v 1.3 2005/11/04 09:56:14 evertonm Exp $ */

#ifndef NEPIM_ARRAY_H
#define NEPIM_ARRAY_H

typedef struct nepim_array_t nepim_array_t;

struct nepim_array_t {
  void **head;
  int  capacity;
};

void nepim_array_init(nepim_array_t *array);
void nepim_array_delete(nepim_array_t *array);

void *nepim_array_get(const nepim_array_t *array, int index);
void *nepim_array_search(const nepim_array_t *array, int index);
void *nepim_array_find(const nepim_array_t *array,
		       int (*detector)(const void *context,
				       const void *element),
		       const void *context);
int nepim_array_find_free(nepim_array_t *array);

void nepim_array_add(nepim_array_t *array, int index, void *value);
void nepim_array_del(nepim_array_t *array, int index);

#endif /* NEPIM_ARRAY_H */
