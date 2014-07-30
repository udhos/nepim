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

/* $Id: array.c,v 1.3 2005/11/04 09:56:14 evertonm Exp $ */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "array.h"

void nepim_array_init(nepim_array_t *array)
{
  array->head = malloc(sizeof(void *));
  assert(array->head);
  array->capacity = 1;
  array->head[0] = 0;
}

void nepim_array_delete(nepim_array_t *array)
{
  assert(array->head);
  free(array->head);
  array->head = 0;
}

void *nepim_array_get(const nepim_array_t *array, int index)
{
  assert(index >= 0);
  assert(index < array->capacity);

  return array->head[index];
}

void *nepim_array_search(const nepim_array_t *array, int index)
{
  if (index < 0)
    return 0;

  if (index >= array->capacity)
    return 0;

  return nepim_array_get(array, index);
}

void *nepim_array_find(const nepim_array_t *array,
		       int (*detector)(const void *context,
				       const void *element),
		       const void *context)
{
  int i;
  
  for (i = 0; i < array->capacity; ++i) {
    void *element = nepim_array_get(array, i);
    if (detector(context, element))
      return element;
  }

  return 0;
}

static void grow(nepim_array_t *array, int index)
{
  int new_cap;

  assert(index >= array->capacity);

  new_cap = index + 1;
  array->head = realloc(array->head, new_cap * sizeof(nepim_array_t*));

  assert(array->head);

  {
    int i;
    for (i = array->capacity; i < new_cap; ++i)
      array->head[i] = 0;
  }

  assert(!array->head[index]);

  array->capacity = new_cap;
}

int nepim_array_find_free(nepim_array_t *array)
{
  int i;

  for (i = 0; i < array->capacity; ++i)
    if (!array->head[i])
      return i;

  i = array->capacity;

  grow(array, i);

  assert(!array->head[i]);

  return i;
}

void nepim_array_add(nepim_array_t *array, int index, void *value)
{
  assert(index >= 0);
  assert(value);

  if (index >= array->capacity)
    grow(array, index);

  assert(!array->head[index]);

  array->head[index] = value;
}

void nepim_array_del(nepim_array_t *array, int index)
{
  assert(index >= 0);
  assert(index < array->capacity);
  assert(array->head[index]);

  array->head[index] = 0;
}

