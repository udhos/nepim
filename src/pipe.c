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

/* $Id: pipe.c,v 1.9 2007/03/22 21:56:53 evertonm Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "pipe.h"
#include "common.h"
#include "conf.h"

void nepim_pipe_set_init(nepim_pipe_set_t *set)
{
  nepim_array_init(&set->array);
}

nepim_pipe_t *nepim_pipe_set_get(const nepim_pipe_set_t *set, int sd)
{
  return nepim_array_get(&set->array, sd);
}

void nepim_pipe_set_add(nepim_pipe_set_t *set, int sd, 
			const struct sockaddr *remote,
			socklen_t remote_len,
			const nepim_greet_t *opt)
{
  nepim_pipe_t *pipe = malloc(sizeof(*pipe));
  assert(pipe);

  pipe->sd = sd;
  nepim_session_init(&pipe->session, opt, 
		     remote, remote_len,
		     SESSION_PIPE, sd);

  nepim_array_add(&set->array, sd, pipe);
}

void nepim_pipe_set_del(nepim_pipe_set_t *set, int sd)
{
  nepim_pipe_t *pipe = nepim_pipe_set_get(set, sd);
  assert(pipe);
  free(pipe);
  nepim_array_del(&set->array, sd);
}

void nepim_pipe_schedule_keepalive_timer(nepim_pipe_t *pipe,
					 oop_call_time *on_tcp_keepalive_require)
{
  nepim_session_t *session = &pipe->session;

  assert(session->keepalive_require);

#ifdef NEPIM_DEBUG_KEEPALIVE
  fprintf(stderr,
          "NEPIM_DEBUG_KEEPALIVE %s %s: keepalive_timeout=%ld\n",
          __FILE__, __PRETTY_FUNCTION__,
          session->keepalive_timeout);
#endif

  {
    int result = gettimeofday(&session->tv_keepalive_recv_timer, 0);
    assert(!result);
  }
  nepim_timer_usec_add(&session->tv_keepalive_recv_timer, 
                       session->keepalive_timeout);

  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                session->tv_keepalive_recv_timer,
                                on_tcp_keepalive_require, pipe);
}
