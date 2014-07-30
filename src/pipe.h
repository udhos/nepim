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

/* $Id: pipe.h,v 1.8 2006/04/18 12:10:15 evertonm Exp $ */

#ifndef NEPIM_PIPE_H
#define NEPIM_PIPE_H

#include <oop.h>

#include "array.h"
#include "session.h"

typedef struct nepim_pipe_t nepim_pipe_t;
typedef struct nepim_pipe_set_t nepim_pipe_set_t;

struct nepim_pipe_t {
  int             sd;
  nepim_session_t session;
};

struct nepim_pipe_set_t {
  nepim_array_t array;
};

void nepim_pipe_set_init(nepim_pipe_set_t *set);

nepim_pipe_t *nepim_pipe_set_get(const nepim_pipe_set_t *set, int sd);

void nepim_pipe_set_add(nepim_pipe_set_t *set, int sd, 
			const struct sockaddr *remote,
			socklen_t remote_len,
			const nepim_greet_t *opt);

void nepim_pipe_set_del(nepim_pipe_set_t *set, int sd);

void nepim_pipe_schedule_keepalive_timer(nepim_pipe_t *pipe,
					 oop_call_time *on_tcp_keepalive_require);

#endif /* NEPIM_PIPE_H */
