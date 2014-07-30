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

#include <assert.h>

#include "conf.h"
#include "udp_header.h"

nepim_global_t nepim_global = {
  0,        /* FILE *verbose_stderr */
  "nepim",  /* prog_name */
  0,        /* hostname */
  0,        /* client_mode */
  0,        /* udp_mode */
  0,        /* simplex_client_send */
  0,        /* duplex_mode */
  1,        /* pipes */
  -1,       /* bit_rate */
  -1,       /* pkt_rate */
  2,        /* stat_interval */
  10,       /* test_duration */
  32768,    /* tcp_write_size */
  32768,    /* tcp_read_size */
  4096,     /* udp_write_size */
  4096,     /* udp_read_size */
  "1234",   /* portname */
  0,        /* no_inet4 */
  0,        /* no_inet6 */
  250000,   /* write_delay (usec, bit_rate > 0) */
  100,      /* listen_backlog */
  -1,       /* pmtu_mode */
  0,        /* bind_list */
  0,        /* join_list */
  0,        /* unix_list */
  0,        /* unix_dgram_list */
  -1,       /* ttl */
  -1,       /* mcast_ttl */
  500000,   /* udp_greet_delay (usec) */
  5,        /* max_greetings */
  2000000,  /* udp_keepalive_recv_timer (usec, receivers, 2 sec) */
  500000,   /* udp_keepalive_send_delay (usec, non-senders, .5 sec) */
  1,        /* udp_keepalive_require (boolean, receivers) */
  1,        /* udp_keepalive_must_send (boolean, non-senders) */
  4000,     /* udp_win_max */
  -1,       /* win_recv */
  -1,       /* win_send */
  1,        /* udp_require_greet_reply (boolean, client) */
  1,        /* seed */
  0,        /* verify_data */
  1,        /* random_fill */
  0x00,     /* fill_byte */
  0,        /* pause_duration */
  0,        /* password */
  0,        /* tcpwrap */
  -1,       /* search_unix_socket (boolean) */
  -1,       /* soft_error_verbose (boolean) */
  -1,       /* debug_error_verbose (boolean) */
  -1,       /* ip tos (default: don't change) */
  1,        /* socket keepalive (client, boolean, -1 is don't change */
  20000000, /* tcp_keepalive_recv_timer (usec, receivers, 20 sec) */
  10000000, /* tcp_keepalive_send_delay (usec, non-senders, 10 sec) */
  0,        /* tcp_keepalive_require (boolean, receivers) */
  0,        /* tcp_keepalive_must_send (boolean, non-senders) */
  -1,       /* nagle (client, boolean, -1 is don't change) */
  0,        /* udp_overhead (bytes) */
  0,        /* tcp_overhead (bytes) */
  0,        /* sweep_random (boolean) */
  1,        /* sweep_step (bytes) */
  -1,       /* write_floor (bytes) */
  -1,       /* write_ceil (bytes) */
  -1,       /* server_write_floor (bytes) */
  -1,       /* server_write_ceil (bytes) */
  1,        /* udp_accumulative_loss (boolean) */
  0,        /* udp_dst_random_addr (0=fixed,1=random) */
  0,        /* udp_dst_random_port (0=fixed,1=random) */
  0,        /* report_partial_min_max (boolean) */
  -1,       /* client_tcp_mss */
  -1,       /* server_tcp_mss */
  0,        /* router_alert (boolean) */

  0, /* oop source */
  0  /* source interface */
};

void nepim_conf_write_sweep_auto(int is_udp,
				 int *write_floor,
				 int *write_ceil)
{
  /*
    -1: fixed: floor=max ceil=max
    -2: auto:  floor=min ceil=max
  */

  if (is_udp) {
      if (*write_floor == -1)
	*write_floor = nepim_global.udp_write_size;

      if (*write_floor < 0)
	*write_floor = UDP_HEADER_LEN;

      if (*write_ceil < 0)
	*write_ceil = nepim_global.udp_write_size;

    return;
  }

  if (*write_floor == -1)
    *write_floor = nepim_global.tcp_write_size;

  if (*write_floor < 0)
    *write_floor = 0;

  if (*write_ceil < 0)
    *write_ceil = nepim_global.tcp_write_size;
}

void nepim_conf_write_sweep_fit(int is_udp,
				int *write_floor,
				int *write_ceil)
{
  if (is_udp) {
      if (*write_floor < UDP_HEADER_LEN)
	*write_floor = UDP_HEADER_LEN;

      if (*write_ceil > nepim_global.udp_write_size)
	*write_ceil = nepim_global.udp_write_size;

      if (*write_floor > *write_ceil)
	*write_floor = *write_ceil;

      assert(*write_floor >= UDP_HEADER_LEN);
      assert(*write_ceil <= nepim_global.udp_write_size);
      assert(*write_floor <= *write_ceil);

    return;
  }

  if (*write_floor < 0)
    *write_floor = 0;

  if (*write_ceil > nepim_global.tcp_write_size)
    *write_ceil = nepim_global.tcp_write_size;

  if (*write_floor > *write_ceil)
    *write_floor = *write_ceil;

  assert(*write_floor >= 0);
  assert(*write_ceil <= nepim_global.tcp_write_size);
  assert(*write_floor <= *write_ceil);
}
