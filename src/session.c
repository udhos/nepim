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

/* $Id: session.c,v 1.18 2007/10/18 21:51:44 evertonm Exp $ */

#include <string.h>
#include <assert.h>
#include <time.h>
#include <float.h>

#include "session.h"
#include "common.h"
#include "rand.h"

void nepim_session_init(nepim_session_t *session, const nepim_greet_t *opt,
                        const struct sockaddr *remote, socklen_t remote_len,
                        nepim_session_type type, int index)
{
  switch(type) {
  case SESSION_PIPE:
    session->index.pipe_sd = index;
    break;
  case SESSION_SLOT:
    session->index.slot = index;
    break;
  default:
    assert(0);
  }

  session->type = type;

  assert(sizeof(session->remote) >= remote_len);
  memcpy(&session->remote, remote, remote_len);
  session->remote_len = remote_len;

  session->must_send               = opt->must_send;
  session->max_bit_rate            = opt->bit_rate;
  session->max_pkt_rate            = opt->pkt_rate;
  session->stat_interval           = opt->stat_interval;
  session->test_duration           = opt->test_duration;
  session->write_delay             = opt->write_delay;
  session->keepalive_must_send     = opt->keepalive_must_send;
  session->keepalive_require       = opt->keepalive_require;
  session->keepalive_timeout       = opt->keepalive_timeout;
  session->keepalive_send_delay    = opt->keepalive_send_delay;
  session->seed                    = opt->seed;
  session->check_seed              = opt->seed;        /* see tcp_check_data() */
  session->verify_data             = opt->verify_data;
  session->random_fill             = opt->random_fill;
  session->fill_byte               = opt->fill_byte;
  session->pause_duration          = opt->pause_duration;
  session->overhead                = opt->overhead;
  session->sweep_random            = opt->sweep_random;
  session->sweep_step              = opt->sweep_step;
  session->write_floor             = opt->write_floor;
  session->write_ceil              = opt->write_ceil;
  session->report_partial_min_max  = opt->report_partial_min_max;

  session->duration_done        = 0;
  session->total_reads          = 0;
  session->total_writes         = 0;
  session->interval_reads       = 0;
  session->interval_writes      = 0;
  session->byte_total_sent      = 0;
  session->byte_total_recv      = 0;
  session->byte_interval_sent   = 0;
  session->byte_interval_recv   = 0;
  session->keepalives_recv      = 0;
  session->write_sweep_rand_ctx = time(0); /* random seed (see rand.c) */
  session->udp_dst_random_ctx   = session->write_sweep_rand_ctx;
  session->write_sweep_current  = session->write_floor;

  session->min.kbps_in   = FLT_MAX;
  session->min.kbps_out  = FLT_MAX;
  session->min.pps_in    = FLT_MAX;
  session->min.pps_out   = FLT_MAX;
  session->min.pkt_loss  = FLT_MAX;
  session->min.pkt_ooo   = FLT_MAX;

  session->max.kbps_in   = FLT_MIN;
  session->max.kbps_out  = FLT_MIN;
  session->max.pps_in    = FLT_MIN;
  session->max.pps_out   = FLT_MIN;
  session->max.pkt_loss  = FLT_MIN;
  session->max.pkt_ooo   = FLT_MIN;
}

void nepim_session_write_add(nepim_session_t *session, int len)
{
  assert(len >= 0);

  session->byte_total_sent    += len;
  session->byte_interval_sent += len;
  ++session->total_writes;
  ++session->interval_writes;
}

void nepim_session_read_add(nepim_session_t *session, int len)
{
  assert(len >= 0);

  session->byte_total_recv    += len;
  session->byte_interval_recv += len;
  ++session->total_reads;
  ++session->interval_reads;
}

int nepim_write_sweep(nepim_session_t *session)
{
  int to_write = session->write_sweep_current;

  assert(session->write_floor <= session->write_ceil);

  if (session->sweep_random) {
    session->write_sweep_current = nepim_rand_next(&session->write_sweep_rand_ctx,
						   session->write_floor,
						   session->write_ceil);
  }
  else {
    session->write_sweep_current += session->sweep_step;

    /* underflow? */
    if (session->write_sweep_current < session->write_floor)
      session->write_sweep_current = session->write_ceil;

    /* overflow? */
    else if (session->write_sweep_current > session->write_ceil)
      session->write_sweep_current = session->write_floor;
  }
  
  assert(session->write_sweep_current >= session->write_floor);
  assert(session->write_sweep_current <= session->write_ceil);

  return to_write;
}
