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

/* $Id: str.h,v 1.8 2008/07/11 15:26:33 evertonm Exp $ */

#ifndef NEPIM_STR_H
#define NEPIM_STR_H

int nepim_str_split(char sep, char *buf, int buf_size, char **next);
int nepim_str_split_comma(char *buf, int buf_size, char **next);

int addr_list_size(const char *list);
int addr_list_get(const char *list, int i, char *buf, int buf_size);
char *addr_list_append(char *list, const char *tail);
int addr_split_port(char *buf, int buf_size, char **port);
int addr_split_sourcegroup(char *buf, int buf_size, char **group);
int addr_split_iface(char *buf, int buf_size, char **iface);

long long nepim_unit_ll(const char *str);
int nepim_unit_int(const char *str);
int nepim_time_unit(const char *str);

#endif /* NEPIM_STR_H */
