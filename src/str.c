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

/* $Id: str.c,v 1.10 2008/07/11 15:26:33 evertonm Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include "str.h"

static int addr_list_sep(int c)
{
  return isspace(c);
}

int addr_list_size(const char *list)
{
  int size = 0;
  int spc = 1;

  assert(list);

  for (; *list; ++list) {
    int hit_spc = addr_list_sep(*list);
    if (spc) {
      /* inside space */
      if (!hit_spc) {
	spc = 0; /* word found */
	++size;
      }
    }
    else {
      /* inside word */
      if (hit_spc)
	spc = 1; /* space found */
    }
  }

  return size;
}

static int addr_copy(const char *list, const char *word, char *buf, int buf_size)
{
  int word_len;

  assert(word);
  assert(list > word);

  word_len = list - word;
  if (word_len >= buf_size)
    return -1;
  
  memcpy(buf, word, word_len);
  buf[word_len] = '\0';
  
  return 0;
}

int addr_list_get(const char *list, int i, char *buf, int buf_size)
{
  int index = -1;
  int spc = 1;
  const char *word = 0;

  assert(list);
  assert(i >= 0);
  assert(buf_size > 0);

  for (; *list; ++list) {
    int hit_spc = addr_list_sep(*list);
    if (spc) {
      /* inside space */
      if (!hit_spc) {
	 /* word found */
	spc = 0;
	word = list; /* save begin of most recent word */
	++index;
      }
    }
    else {
      /* inside word */
      if (hit_spc) {
	/* space found */
	spc = 1; 
	if (index == i)
	  return addr_copy(list, word, buf, buf_size);
      } /* space found */
    } /* inside word */
  } /* for loop: scan string */

  /* consider unended last word */
  if (!spc && (index == i))
    return addr_copy(list, word, buf, buf_size);
      
  return -1;
}

char *addr_list_append(char *list, const char *tail)
{
  assert(tail);

  if (!list) {
    list = strdup(tail);
    assert(list);
    return list;
  }

  list = realloc(list, strlen(list) + strlen(tail) + 2);
  assert(list);
  
  strcat(list, " ");
  strcat(list, tail);

  return list;
}

int nepim_str_split(char sep, char *buf, int buf_size, char **next)
{
  const char *eos;
  char *p;
  int len;

  assert(buf_size > 0);
  
  eos = memchr(buf, '\0', buf_size);
  assert(eos);

  len = eos - buf;
  assert(len > 0);

  p = memchr(buf, sep, len);
  if (p) {
    *p = '\0';
    *next = p + 1;
    return 0;
  }

  return -1;
}

int nepim_str_split_comma(char *buf, int buf_size, char **next)
{
  return nepim_str_split(',', buf, buf_size, next);
}

int nepim_str_split_plus(char *buf, int buf_size, char **next)
{
  return nepim_str_split('+', buf, buf_size, next);
}

int nepim_str_split_at(char *buf, int buf_size, char **next)
{
  return nepim_str_split('@', buf, buf_size, next);
}

int addr_split_port(char *buf, int buf_size, char **port)
{
  return nepim_str_split_comma(buf, buf_size, port);
}

int addr_split_sourcegroup(char *buf, int buf_size, char **group)
{
  return nepim_str_split_plus(buf, buf_size, group);
}

int addr_split_iface(char *buf, int buf_size, char **iface)
{
  return nepim_str_split_at(buf, buf_size, iface);
}

static int multiplier_affix(const char *str)
{
  const char *i;
  int multiplier = 1;

  assert(str);

  for (i = str; ; ++i) {
    char c = *i;
    if (!c)
      break;
    switch (c) {
    case 'k':
    case 'K':
      multiplier *= 1000;
      break;
    case 'm':
    case 'M':
      multiplier *= 1000000;
      break;
    case 'g':
    case 'G':
      multiplier *= 1000000000;
      break;
    }
  }

  return multiplier;
}

static int parse_float(float *f, const char *str)
{
  return (sscanf(str, "%f", f) != 1);
}

long long nepim_unit_ll(const char *str)
{
  float f;

  if (parse_float(&f, str))
    return strtoll(str, 0, 10) * (long long) multiplier_affix(str);

  return f * multiplier_affix(str);
}

int nepim_unit_int(const char *str)
{
  float f;

  if (parse_float(&f, str))
    return atoi(str) * multiplier_affix(str);

  return f * multiplier_affix(str);
}

static int time_affix(const char *str)
{
  const char *i;
  int multiplier = 1;

  assert(str);

  for (i = str; ; ++i) {
    char c = *i;
    if (!c)
      break;
    switch (c) {
    case 'm':
    case 'M':
      multiplier *= 60;
      break;
    case 'h':
    case 'H':
      multiplier *= 3600;
      break;
    case 'd':
    case 'D':
      multiplier *= 86400;
      break;
    }
  }

  return multiplier;
}

int nepim_time_unit(const char *str)
{
  float f;

  if (parse_float(&f, str))
    return atoi(str) * time_affix(str);

  return f * time_affix(str);
}
