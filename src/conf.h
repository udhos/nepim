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

#ifndef NEPIM_CONF_H
#define NEPIM_CONF_H

#include <stdio.h>
#include <oop.h>

#include "usec.h"

typedef struct nepim_global_t nepim_global_t;

struct nepim_global_t {
  FILE         *verbose_stderr; /* stream for verbose error messages */
  const char   *prog_name;
  char         *hostname;
  int           client_mode;
  int           udp_mode;
  int           simplex_client_send;
  int           duplex_mode;
  int           pipes;
  long long     bit_rate;
  int           pkt_rate;
  int           stat_interval;
  int           test_duration;
  int           tcp_write_size;
  int           tcp_read_size;
  int           udp_write_size;
  int           udp_read_size;
  const char   *portname;
  int           no_inet4;
  int           no_inet6;
  susec_t       write_delay;
  int           listen_backlog;
  int           pmtu_mode;
  char         *bind_list;
  char         *join_list;
  char         *unix_list;
  char         *unix_dgram_list;
  int           ttl;
  int           mcast_ttl;
  susec_t       udp_greet_delay;         /* usec */
  int           max_greetings;
  susec_t       udp_keepalive_recv_timer; /* usec, receivers */
  susec_t       udp_keepalive_send_delay; /* usec, non-senders */
  int           udp_keepalive_require;    /* boolean, receivers */
  int           udp_keepalive_must_send;  /* boolean, non-senders */
  int           udp_win_max;
  int           win_recv;
  int           win_send;
  int           udp_require_greet_reply; /* boolean, client */
  unsigned      seed;
  int           verify_data;           /* boolean */
  int           random_fill;           /* boolean, client */
  unsigned char fill_byte;             /* client */
  int           pause_duration;
  const char   *password;
  const char   *tcpwrap;
  int           search_unix_socket; /* boolean */
  int           soft_error_verbose; /* boolean */
  int           debug_error_verbose; /* boolean */
  int           tos;
  int           socket_keepalive; /* client, boolean, -1 is don't change */
  susec_t       tcp_keepalive_recv_timer; /* usec, receivers */
  susec_t       tcp_keepalive_send_delay; /* usec, non-senders */
  int           tcp_keepalive_require;    /* boolean, receivers */
  int           tcp_keepalive_must_send;  /* boolean, non-senders */
  int           nagle; /* client, boolean, -1 is don't change */
  int           udp_overhead;       /* bytes */
  int           tcp_overhead;       /* bytes */
  int           sweep_random;       /* boolean */
  int           sweep_step;         /* bytes */
  int           write_floor;        /* bytes */
  int           write_ceil;         /* bytes */
  int           server_write_floor; /* bytes */
  int           server_write_ceil;  /* bytes */
  int           udp_accumulative_loss; /* boolean */
  int           udp_dst_random_addr;   /* 0=fixed,1=random */
  int           udp_dst_random_port;   /* 0=fixed,1=random */
  int           report_partial_min_max; /* boolean */
  int           client_tcp_mss; /* bytes */
  int           server_tcp_mss; /* bytes */
  int           router_alert;   /* boolean */

  oop_source_sys *oop_sys;
  oop_source     *oop_src;
};

extern nepim_global_t nepim_global;

void nepim_conf_write_sweep_auto(int is_udp,
				 int *write_floor,
				 int *write_ceil);

void nepim_conf_write_sweep_fit(int is_udp,
				int *write_floor,
				int *write_ceil);

#endif /* NEPIM_CONF_H */
