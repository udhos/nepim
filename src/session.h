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

/* $Id: session.h,v 1.25 2007/10/18 21:51:44 evertonm Exp $ */

#ifndef NEPIM_SESSION_H
#define NEPIM_SESSION_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "greet.h"
#include "usec.h"

typedef enum { SESSION_PIPE, SESSION_SLOT } nepim_session_type;

typedef struct nepim_session_t nepim_session_t;

typedef struct {
  float kbps_in;
  float kbps_out;
  float pps_in;
  float pps_out;
  float pkt_loss;
  float pkt_ooo;
} nepim_mark_t;

struct nepim_session_t {

  nepim_session_type type;
  union {
    int pipe_sd; /* map socket descriptor to pipe */
    int slot;    /* map slot index        to slot */
  } index;

  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
    struct sockaddr_un un;
  }         remote;
  socklen_t remote_len;

  int must_send;
  long long max_bit_rate;
  int max_pkt_rate;
  int stat_interval;
  int test_duration;
  susec_t write_delay;         /* usec, used when max_bit_rate > 0 */
  int duration_done;           /* boolean */
  int keepalive_must_send;     /* boolean, non-senders */
  int keepalive_require;       /* boolean, receivers */
  susec_t keepalive_timeout;   /* usec, receivers */
  susec_t keepalive_send_delay; /* usec, non-senders */
  int keepalives_recv;         /* counter, receivers */
  unsigned seed;
  unsigned check_seed;	       /* used only by tcp_check_data() */
  int verify_data;	       /* boolean, client */
  int random_fill;	       /* boolean, client */
  unsigned char fill_byte;
  int pause_duration;
  int overhead;                /* bytes */
  int sweep_random;            /* boolean */
  int sweep_step;              /* bytes */
  int write_floor;             /* bytes */
  int write_ceil;              /* bytes */

  long write_sweep_rand_ctx;  /* see rand.c */
  int write_sweep_current;    /* bytes */

  int rate_remaining;          /* bytes, used when max_bit_rate > 0 */
  int pkt_remaining;           /* pkts, used when max_pkt_rate > 0 */

  int total_reads;
  int total_writes;
  int interval_reads;
  int interval_writes;

  long long byte_total_sent;
  long long byte_total_recv;

  long long byte_interval_sent;
  long long byte_interval_recv;

  nepim_mark_t min;
  nepim_mark_t max;
  int report_partial_min_max;

  struct timeval tv_duration;
  struct timeval tv_interval;
  struct timeval tv_start;
  struct timeval tv_send_rate;
  struct timeval tv_greet_rate;           /* udp client */
  struct timeval tv_keepalive_send_next;  /* non-sender keepalive sending period */
  struct timeval tv_keepalive_recv_timer; /* receiver keepalive timeout */

  long udp_dst_random_ctx; /* random addr,port (rand ctx in rand.c) */
};

void nepim_session_init(nepim_session_t *session, const nepim_greet_t *opt,
			const struct sockaddr *remote, socklen_t remote_len,
			nepim_session_type type, int index);

void nepim_session_write_add(nepim_session_t *session, int len);
void nepim_session_read_add(nepim_session_t *session, int len);

int nepim_write_sweep(nepim_session_t *session);

#endif /* NEPIM_SESSION_H */

