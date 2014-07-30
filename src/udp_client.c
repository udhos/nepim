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

/* $Id: udp_client.c,v 1.87 2008/08/22 02:01:19 evertonm Exp $ */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

#include "conf.h"
#include "sock.h"
#include "pipe.h"
#include "common.h"
#include "usock.h"
#include "udp_header.h"
#include "str.h"

extern nepim_slot_set_t slots;    /* from server.c */
extern nepim_usock_set_t udp_tab; /* from server.c */

static void *on_udp_rate_delay(oop_source *src, struct timeval tv, void *user);
static void *on_udp_write(oop_source *src, int sd,
                          oop_event event, void *user);
static void udp_slot_cancel_stat_timers(nepim_slot_t *slot);
static void schedule_stat_interval(nepim_slot_t *slot);
static void udp_slot_kill(nepim_slot_t *slot);
static void *on_udp_duration(oop_source *src, struct timeval tv, void *user);
static void *on_udp_time_greet(oop_source *src, struct timeval tv,
                               void *user);
static void soft_cancel_slot_greet_writer(nepim_slot_t *slot);
static void cancel_slot_greet_writer(nepim_slot_t *slot);
static void cancel_slot_greet_timer(nepim_slot_t *slot);
static void cancel_slot_segment_read(nepim_slot_t *slot);

static void will_slot_write(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;
  int sd = slot->udp_sd;

  assert(session->max_bit_rate < 1);
  assert(session->max_pkt_rate < 1);

  assert(!slot->want_write);
  ++slot->want_write;

  if (nepim_usock_writer_add(&udp_tab, sd))
    return;

  nepim_global.oop_src->on_fd(nepim_global.oop_src, sd,
                              OOP_WRITE, on_udp_write, 0);
}

static void *on_udp_keepalive_require(oop_source *src, struct timeval tv, void *user)
{
  nepim_slot_t *slot = user;
  nepim_session_t *session = &slot->session;

  assert(session->keepalive_require);
  assert(session->keepalives_recv >= 0);

  if (session->keepalives_recv < 1) {
    fprintf(stderr, 
            "%d %d-%d: broken slot: %s\n",
            slot->udp_sd, slot->index, slot->index_remote,
	    NEPIM_MSG_KEEPALIVES_MISS);

    if (!session->duration_done)
      report_broken_slot_stat(stdout, slot);

    udp_slot_kill(slot);

    return OOP_CONTINUE;
  }

  session->keepalives_recv = 0;

  nepim_schedule_keepalive_timer(slot, on_udp_keepalive_require);

  return OOP_CONTINUE;
}

static void *on_udp_keepalive_time(oop_source *src, struct timeval tv, void *user)
{
  nepim_slot_t *slot = user;
  nepim_session_t *session = &slot->session;

  assert(timercmp(&tv, &session->tv_keepalive_send_next, ==));
  assert(!session->must_send);
  assert(session->keepalive_must_send);

#ifdef NEPIM_DEBUG_KEEPALIVE
  fprintf(stderr,
          "NEPIM_DEBUG_KEEPALIVE %s %s: keepalive_send_delay=%ld\n",
          __FILE__, __PRETTY_FUNCTION__,
          session->keepalive_send_delay);
#endif

  /* save next scheduling time */
  {
    int result = gettimeofday(&session->tv_keepalive_send_next, 0);
    assert(!result);
  }
  nepim_timer_usec_add(&session->tv_keepalive_send_next,
		       session->keepalive_send_delay);

  /* start to write */
  nepim_will_slot_keepalive(slot, on_udp_write);

  return OOP_CONTINUE;
}

static void *on_sigint(oop_source *src, int sig, void *user)
{
  nepim_slot_t *slot = user;

  assert(sig == SIGINT);
  assert(slot);

  fprintf(stderr,
	  "%d %d-%d: %s %s: interrupted by user\n",
	  slot->udp_sd, slot->index, slot->index_remote,
	  __FILE__, __PRETTY_FUNCTION__);

  if (!slot->session.duration_done)
    report_broken_slot_stat(stdout, slot);

  udp_slot_kill(slot);

  return OOP_CONTINUE;
}

static void *on_sigterm(oop_source *src, int sig, void *user)
{
  nepim_slot_t *slot = user;

  assert(sig == SIGTERM);
  assert(slot);

  fprintf(stderr,
	  "%d %d-%d: %s %s: interrupted by user\n",
	  slot->udp_sd, slot->index, slot->index_remote,
	  __FILE__, __PRETTY_FUNCTION__);

  if (!slot->session.duration_done)
    report_broken_slot_stat(stdout, slot);

  udp_slot_kill(slot);

  return OOP_CONTINUE;
}

static void udp_slot_start(nepim_slot_t *slot)
{
  nepim_session_t *session;

  session = &slot->session;

  if (session->must_send) {
    if ((session->max_bit_rate > 0) || (session->max_pkt_rate > 0)) {
      session->tv_send_rate = OOP_TIME_NOW;
      nepim_global.oop_src->on_time(nepim_global.oop_src,
                                    session->tv_send_rate,
                                    on_udp_rate_delay, slot);
    }
    else {
      will_slot_write(slot);
    }
  }
  else {
    if (session->keepalive_must_send) {

#if 0
      fprintf(stderr, 
              "DEBUG %s %s: %d %d-%d: %s\n",
              __FILE__, __PRETTY_FUNCTION__,
              slot->udp_sd, slot->index, slot->index_remote,
	      NEPIM_MSG_KEEPALIVES_SCHED);
#endif
      
      session->tv_keepalive_send_next = OOP_TIME_NOW;
      nepim_global.oop_src->on_time(nepim_global.oop_src,
                                    session->tv_keepalive_send_next,
                                    on_udp_keepalive_time, slot);
    }
  }

  {
    int result = gettimeofday(&session->tv_start, 0);
    assert(!result);
    session->tv_duration = session->tv_start;
  }
  session->tv_duration.tv_sec += session->test_duration;
  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                session->tv_duration,
                                on_udp_duration, slot);

  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, slot->udp_sd);

  schedule_stat_interval(slot);

  if (session->keepalive_require)
    nepim_schedule_keepalive_timer(slot, on_udp_keepalive_require);

  nepim_global.oop_src->on_signal(nepim_global.oop_src,
				  SIGINT, on_sigint, slot);
  nepim_global.oop_src->on_signal(nepim_global.oop_src,
				  SIGTERM, on_sigterm, slot);
}

static void *on_udp_slot_start(oop_source *src, struct timeval tv, void *user)
{
  nepim_slot_t *slot = user;

  udp_slot_start(slot);

  return OOP_CONTINUE;
}

static void schedule_udp_slot_start(nepim_slot_t *slot)
{
  nepim_session_t *session;
  struct timeval pause;

  session = &slot->session;

  {
    int result = gettimeofday(&pause, 0);
    assert(!result);
  }
  pause.tv_sec += session->pause_duration;
  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                pause,
                                on_udp_slot_start, slot);
}

static void udp_consume(nepim_slot_t *slot, size_t len,
			const nepim_udp_hdr_t *hdr)
{
  nepim_session_t *session = &slot->session;

  /* any valid input traffic accounted as keepalive */
  ++session->keepalives_recv;

  if (hdr->type == UDP_TYPE_DATA)
    nepim_slot_seq_recv(slot, hdr->seq);

  nepim_session_read_add(session, len + session->overhead);
}

static void *on_udp_read_segment(oop_source *src, int sd,
                                 oop_event event, void *user)
{
  int rd;
  char buf[nepim_global.udp_read_size];
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
    struct sockaddr_un un;
  } from;
  socklen_t fromlen = sizeof(from);
  nepim_udp_hdr_t hdr;

  assert(sizeof(buf) == nepim_global.udp_read_size);
  assert(event == OOP_READ);
  assert(!user);

  rd = recvfrom(sd, buf, nepim_global.udp_read_size, 0, 
                (struct sockaddr *) &from, &fromlen);
  if (rd < 0) {
    switch (errno) {
    case EINTR:
    case EAGAIN:
    case ECONNREFUSED:
      nepim_usock_read_error(&udp_tab, sd, errno,
			     nepim_global.soft_error_verbose);
      return OOP_CONTINUE;
    }

    fprintf(stderr, 
            "%d: recvfrom: unexpected failure: errno=%d: %s\n",
            sd, errno, strerror(errno));

    assert(0);

    return OOP_CONTINUE;
  }

  assert(rd >= 0);
  assert(rd <= sizeof(buf));

  nepim_usock_read_good(&udp_tab, sd);

  if (nepim_udp_hdr_parse(&hdr, buf, rd)) {
    fprintf(stderr, 
            "%d: recvfrom: could not parse header from UDP segment: %d/%d bytes\n",
            sd, rd, nepim_global.udp_read_size);
    return OOP_CONTINUE;
  }

  if (hdr.version != UDP_VERSION) {
    fprintf(stderr, "%d %d-%d: recvfrom: ignoring unknown UDP header version: %d\n",
            sd, hdr.dst_slot, hdr.src_slot, hdr.version);
    return OOP_CONTINUE;
  }

  {
    nepim_slot_t *slot = nepim_slot_set_search(&slots, hdr.dst_slot);

    if (!slot) {
      fprintf(stderr, "%d: recvfrom: unknown local slot: %d\n",
              sd, hdr.dst_slot);
      return OOP_CONTINUE;
    }

#if 0
    fprintf(stderr, 
            "DEBUG FIXME %s %s: %d %d-%d in_seq=%d\n",
            __FILE__, __PRETTY_FUNCTION__,
            slot->udp_sd, hdr.dst_slot, hdr.src_slot, hdr.seq);
#endif

    if (slot->session.remote_len != fromlen) {
      fprintf(stderr, 
              "%d %d-%d: recvfrom: bad address length: expected=%d got=%d\n",
              sd, hdr.dst_slot, hdr.src_slot, 
              slot->session.remote_len, fromlen);
      return OOP_CONTINUE;
    }

    if (memcmp(&slot->session.remote, &from, fromlen)) {
      fprintf(stderr, 
              "%d %d-%d: recvfrom: address mismatch\n",
              sd, hdr.dst_slot, hdr.src_slot);
      return OOP_CONTINUE;
    }

    if (slot->client_writer_status == NEPIM_SLOT_CLIENT_GREET) {

      assert(slot->index_remote == 0xFFFF);
      slot->index_remote = hdr.src_slot;

      cancel_slot_greet_timer(slot);
      soft_cancel_slot_greet_writer(slot);

      slot->client_writer_status = NEPIM_SLOT_CLIENT_SEND;
    
      schedule_udp_slot_start(slot);
    }

    assert(slot->index_remote < 0xFFFF);
    assert(slot->client_writer_status == NEPIM_SLOT_CLIENT_SEND);

    if (slot->index_remote != hdr.src_slot) {
      fprintf(stderr, 
              "%d %d-%d: recvfrom: remote index mismatch: expected=%d got=%d\n",
              sd, hdr.dst_slot, hdr.src_slot, slot->index_remote, hdr.src_slot);
      return OOP_CONTINUE;
    }

    udp_consume(slot, rd, &hdr);

    udp_check_packet_data(sd, &hdr, &(slot->session),
			  (unsigned char *) buf, UDP_HEADER_LEN, rd);
  }

  return OOP_CONTINUE;
}

static int slot_greet_write(nepim_slot_t *slot)
{
  char buf[1024];
  nepim_greet_t opt;
  int pr;
  int wr;
  int buf_avail_len;
  int write_len;
  char *tmp = "";

  assert(sizeof(buf) > UDP_HEADER_LEN);

  opt.must_send               = nepim_global.duplex_mode ||
    !nepim_global.simplex_client_send;
  opt.bit_rate                = nepim_global.bit_rate;
  opt.pkt_rate                = nepim_global.pkt_rate;
  opt.stat_interval           = nepim_global.stat_interval;
  opt.test_duration           = nepim_global.test_duration;
  opt.write_delay             = nepim_global.write_delay;
  opt.keepalive_must_send     = nepim_global.udp_keepalive_require;
  opt.keepalive_require       = nepim_global.udp_keepalive_must_send;
  opt.keepalive_timeout       = nepim_global.udp_keepalive_recv_timer;
  opt.keepalive_send_delay    = nepim_global.udp_keepalive_send_delay;
  opt.seed                    = nepim_global.seed;
  opt.verify_data             = nepim_global.verify_data;
  opt.random_fill             = nepim_global.random_fill;
  opt.fill_byte               = nepim_global.fill_byte;
  opt.pause_duration          = nepim_global.pause_duration;
  opt.socket_keepalive        = nepim_global.socket_keepalive;
  opt.overhead                = nepim_global.udp_overhead;
  opt.sweep_random            = nepim_global.sweep_random;
  opt.sweep_step              = nepim_global.sweep_step;
  opt.write_floor             = nepim_global.server_write_floor;
  opt.write_ceil              = nepim_global.server_write_ceil;
  opt.report_partial_min_max  = nepim_global.report_partial_min_max;
  opt.mss                     = nepim_global.server_tcp_mss;

  if (nepim_global.password) {
    opt.password_buf      = (char *) nepim_global.password;
    opt.password_buf_size = strlen(nepim_global.password) + 1;
  }
  else {
    opt.password_buf      = tmp;
    opt.password_buf_size = strlen(tmp) + 1;
  }

  buf_avail_len = sizeof(buf) - UDP_HEADER_LEN;
  assert(buf_avail_len > 0);

  pr = nepim_write_greetings(&opt, buf + UDP_HEADER_LEN, buf_avail_len);
  if (pr < 0)
    return -1;
  if (pr >= buf_avail_len)
    return -2;
  assert(pr > 0);

  write_len = UDP_HEADER_LEN + pr;

  wr = nepim_slot_buf_write(slot, buf, write_len, UDP_TYPE_HELLO);
  if (wr < 0) {
    switch (errno) {
    case EINTR:
    case EAGAIN:
    case ECONNREFUSED:
      nepim_usock_write_error(&udp_tab, slot->udp_sd, 
                              slot->index, slot->index_remote,
                              errno, nepim_global.soft_error_verbose);
      return 0; /* ignore as soft error (caller always resend) */
    default:
      fprintf(stderr, 
              "greet_write: error on UDP socket %d (%d-%d): %d: %s\n", 
              slot->udp_sd, slot->index, slot->index_remote, errno,
              strerror(errno));
    }
    assert(0); /* treat unexpected failures as fatal */
    return -3;
  }

#if 0
  fprintf(stderr, 
          "%d %d-%d: sending: hdr_len=%d greet_len=%d total=%d wrote=%d\n", 
          slot->udp_sd, slot->index, slot->index_remote,
          UDP_HEADER_LEN, pr, write_len, wr);
#endif

  if (wr != write_len) {
    nepim_usock_write_good_partial(&udp_tab, slot->udp_sd);
    return -4;
  }

  nepim_usock_write_good_full(&udp_tab, slot->udp_sd);

  return 0;
}

static void *on_udp_interval(oop_source *src, struct timeval tv, void *user)
{
  nepim_slot_t *slot = user;
  nepim_session_t *session = &slot->session;

  assert(timercmp(&tv, &session->tv_interval, ==));

  nepim_slot_update_pkt_stat(slot);

  nepim_slot_stat(stdout, tv,
		  NEPIM_LABEL_PARTIAL, 
                  slot->udp_sd,
                  slot->index,
                  slot->index_remote,
                  session->byte_interval_recv,
                  session->byte_interval_sent,
                  session->stat_interval,
                  session->tv_start.tv_sec,
                  session->test_duration,
                  session->interval_reads,
                  session->interval_writes,
		  slot->seq_highest_recv - slot->interval_last_highest_seq,
                  slot->interval_pkt_lost,
                  slot->interval_pkt_ooo,
		  slot->total_pkt_lost,
		  &session->min,
		  &session->max,
		  session->report_partial_min_max);

  session->byte_interval_recv = 0;
  session->byte_interval_sent = 0;
  session->interval_reads     = 0;
  session->interval_writes    = 0;

  slot->interval_last_highest_seq = slot->seq_highest_recv;

  slot->interval_pkt_recv = 0;
  slot->interval_pkt_lost = 0;
  slot->interval_pkt_ooo  = 0;

  schedule_stat_interval(slot);

  return OOP_CONTINUE;
}

static void schedule_stat_interval(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;

  {
    int result = gettimeofday(&session->tv_interval, 0);
    assert(!result);
  }

  session->tv_interval.tv_sec += session->stat_interval;

  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                session->tv_interval,
                                on_udp_interval, slot);
}

static void *on_udp_duration(oop_source *src, struct timeval tv, void *user)
{
  nepim_slot_t *slot = user;
  nepim_session_t *session = &slot->session;
  int sd = slot->udp_sd;

  assert(timercmp(&tv, &session->tv_duration, ==));

  nepim_slot_update_pkt_stat(slot);

  nepim_slot_stat(stdout, tv,
		  NEPIM_LABEL_TOTAL, 
                  sd, 
                  slot->index,
                  slot->index_remote,
                  session->byte_total_recv,
                  session->byte_total_sent,
                  session->test_duration,
                  session->tv_start.tv_sec,
                  session->test_duration,
                  session->total_reads,
                  session->total_writes,
		  slot->seq_highest_recv,
                  slot->total_pkt_lost,
                  slot->total_pkt_ooo,
		  slot->total_pkt_lost,
		  &session->min,
		  &session->max,
		  1 /* report_min_max = true */);

  session->byte_total_recv = 0;
  session->byte_total_sent = 0;
  session->total_reads     = 0;
  session->total_writes    = 0;
  session->duration_done   = 1;

  slot->subtotal_pkt_lost = 0;
  slot->total_pkt_lost    = 0;
  slot->total_pkt_recv    = 0;
  slot->total_pkt_ooo     = 0;

  udp_slot_kill(slot);

  return OOP_CONTINUE;
}

static void udp_slot_cancel_stat_timers(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;

  nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                    session->tv_duration,
                                    on_udp_duration, slot);

  nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                    session->tv_interval,
                                    on_udp_interval, slot);
}

static void cancel_slot_rate_write(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;
  int sd = slot->udp_sd;

#ifndef NDEBUG
  {
    if (session->max_bit_rate <= 0) {
      assert(session->max_pkt_rate > 0);
    }
    if (session->max_pkt_rate <= 0) {
      assert(session->max_bit_rate > 0);
    }
  }
#endif /* NDEBUG */

  assert(slot->want_write == 1);
  --slot->want_write;

  if (nepim_usock_writer_del(&udp_tab, sd))
    return;

  nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                  sd, OOP_WRITE);
}

static void udp_write_greet(nepim_slot_t *slot)
{
  nepim_session_t *session;
  int result;
  int sd = slot->udp_sd;

  assert(slot->client_writer_status == NEPIM_SLOT_CLIENT_GREET);

  /* stop writing */
  assert(slot->want_write == 1);
  cancel_slot_greet_writer(slot);

  if (slot->greetings_sent >= nepim_global.max_greetings) {

    if (!nepim_global.udp_require_greet_reply) {

      cancel_slot_greet_timer(slot);
      soft_cancel_slot_greet_writer(slot);

      slot->client_writer_status = NEPIM_SLOT_CLIENT_SEND;
    
      schedule_udp_slot_start(slot);

      return;
    }

    fprintf(stderr, 
            "%d %d-%d: max. greetings reached (%d/%d) - server not responding (see option -g)\n",
            sd, slot->index, slot->index_remote,
            slot->greetings_sent, nepim_global.max_greetings);

    udp_slot_kill(slot);

    return;
  }

  fprintf(stderr, "%d %d-%d: sending greetings (%d/%d)\n",
          sd, slot->index, slot->index_remote,
	  slot->greetings_sent, nepim_global.max_greetings);

  result = slot_greet_write(slot);
  if (result) {
    fprintf(stderr, 
            "%d %d-%d: greet writing failed: %d\n", 
            sd, slot->index, slot->index_remote, result);

    udp_slot_kill(slot);

    return;
  }

  ++slot->greetings_sent;

  session = &slot->session;

  /* schedule for next time saved by on_udp_time_greet() */
  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                session->tv_greet_rate,
                                on_udp_time_greet, slot);
}

static void udp_write_rate(nepim_slot_t *slot) 
{
  char buf[nepim_global.udp_write_size];
  int wr;                   /* payload only */
  int full_wr;              /* payload plus overhead */
  nepim_session_t *session;
  int sweep_write;
  int to_write;
  int sd;

  assert(sizeof(buf) == nepim_global.udp_write_size);
  assert(slot);

  sd = slot->udp_sd;

  session = &slot->session;

#ifndef NDEBUG
  {
    if (session->max_bit_rate <= 0) {
      assert(session->max_pkt_rate > 0);
    }
    if (session->max_pkt_rate <= 0) {
      assert(session->max_bit_rate > 0);
    }
  }
#endif /* NDEBUG */
  
#ifndef NDEBUG
  {
    if (session->rate_remaining <= 0) {
      assert(session->pkt_remaining > 0);
    }
    if (session->pkt_remaining <= 0) {
      assert(session->rate_remaining > 0);
    }
  }
#endif /* NDEBUG */

  sweep_write = nepim_write_sweep(session);
  assert(sweep_write >= UDP_HEADER_LEN);
  assert(sweep_write <= (sizeof buf));

  if (session->rate_remaining > 0)
    to_write = NEPIM_RANGE(session->rate_remaining - session->overhead, 
                           UDP_HEADER_LEN, 
                           sweep_write);
  else
    to_write = sweep_write;

  assert(to_write >= 0);
  assert(to_write >= UDP_HEADER_LEN);
  assert(to_write <= sweep_write);

  /* _write() is nicer, but only _sendto() 
     can perform address randomization */

  if (nepim_global.udp_dst_random_addr ||
      nepim_global.udp_dst_random_port)
    wr = nepim_slot_buf_sendto(slot, buf, to_write, UDP_TYPE_DATA);
  else
    wr = nepim_slot_buf_write(slot, buf, to_write, UDP_TYPE_DATA);

  if (wr < 0) {
    switch (errno) {
    case EINTR:
    case EAGAIN:
    case ECONNREFUSED:
      nepim_usock_write_error(&udp_tab, sd, 
                              slot->index, slot->index_remote,
                              errno, nepim_global.soft_error_verbose);
      return;

    case EPIPE:
      fprintf(stderr, 
              "rate_write: EPIPE on UDP socket %d (%d-%d)\n", 
              sd, slot->index, slot->index_remote);
      break;
    default:
      fprintf(stderr, 
              "rate_write: error on UDP socket %d (%d-%d): %d: %s\n", 
              sd, slot->index, slot->index_remote, errno,
              strerror(errno));
    }

    fprintf(stderr,
            "rate_write: connection lost on UDP socket %d (%d-%d)\n",
            sd, slot->index, slot->index_remote);

    if (!session->duration_done)
      report_broken_slot_stat(stdout, slot);

    udp_slot_kill(slot);

    return;
  }

  assert(wr >= 0);
  assert(wr <= to_write);

  if (wr == to_write)
    nepim_usock_write_good_full(&udp_tab, slot->udp_sd);
  else
    nepim_usock_write_good_partial(&udp_tab, slot->udp_sd);

  full_wr = wr + session->overhead;

  session->rate_remaining -= full_wr;
  --session->pkt_remaining;

  nepim_session_write_add(session, full_wr);

  /* finished ? */
  if ( 
      ((session->max_bit_rate > 0) && (session->rate_remaining < 1))
      ||
      ((session->max_pkt_rate > 0) && (session->pkt_remaining < 1))
      ){

    /* stop writing */
    cancel_slot_rate_write(slot);

    /* schedule for next time saved by on_udp_rate_delay() */
    nepim_global.oop_src->on_time(nepim_global.oop_src,
                                  session->tv_send_rate,
                                  on_udp_rate_delay, slot);
  }
}

static void udp_write_full(nepim_slot_t *slot) 
{
  char buf[nepim_global.udp_write_size];
  int wr;                   /* payload only */
  nepim_session_t *session;
  int sd;
  int to_write;

  assert(nepim_global.udp_write_size == sizeof(buf));
  assert(slot);

  sd = slot->udp_sd;

  session = &slot->session;

  assert(session->max_bit_rate < 1);
  assert(session->max_pkt_rate < 1);

  to_write = nepim_write_sweep(session);
  assert(to_write >= UDP_HEADER_LEN);
  assert(to_write <= (sizeof buf));

  /* _write() is nicer, but only _sendto() 
     can perform address randomization */

  if (nepim_global.udp_dst_random_addr ||
      nepim_global.udp_dst_random_port)
    wr = nepim_slot_buf_sendto(slot, buf, to_write, UDP_TYPE_DATA);
  else
    wr = nepim_slot_buf_write(slot, buf, to_write, UDP_TYPE_DATA);

  if (wr < 0) {
    switch (errno) {
    case EINTR:
    case EAGAIN:
    case ECONNREFUSED:
      nepim_usock_write_error(&udp_tab, sd, 
                              slot->index, slot->index_remote,
                              errno, nepim_global.soft_error_verbose);
      return;

    case EPIPE:
      fprintf(stderr, 
              "write: EPIPE on UDP socket %d (%d-%d)\n", 
              sd, slot->index, slot->index_remote);
      break;
    default:
      fprintf(stderr, 
              "write: error on UDP socket %d (%d-%d): %d: %s\n", 
              sd, slot->index, slot->index_remote, errno,
              strerror(errno));
    }

    fprintf(stderr,
            "write: connection lost on UDP socket %d (%d-%d)\n",
            sd, slot->index, slot->index_remote);

    if (!session->duration_done)
      report_broken_slot_stat(stdout, slot);

    udp_slot_kill(slot);

    return;
  }

  assert(wr >= 0);
  assert(wr <= to_write);
  assert(to_write <= sizeof(buf));

  if (wr == to_write)
    nepim_usock_write_good_full(&udp_tab, sd);
  else
    nepim_usock_write_good_partial(&udp_tab, sd);

  nepim_session_write_add(session, wr + session->overhead);
}

static void *on_udp_write(oop_source *src, int sd,
                          oop_event event, void *user)
{
  char buf[nepim_global.udp_write_size];
  nepim_slot_t *slot;
  nepim_session_t *session;

  assert(nepim_global.udp_write_size == sizeof(buf));
  assert(!user);
  assert(event == OOP_WRITE);

  slot = nepim_slot_find_next_writer(&slots, sd);
  assert(slot);

  assert(sd == slot->udp_sd);

  if (slot->client_writer_status == NEPIM_SLOT_CLIENT_GREET) {
    udp_write_greet(slot);
    return OOP_CONTINUE;
  }

  session = &slot->session;

  if (!session->must_send) {
    if (session->keepalive_must_send) {
      /* should not send keepalive for random destinations */ 
      assert(!nepim_global.udp_dst_random_addr && !nepim_global.udp_dst_random_port);
      nepim_udp_write_keepalive(slot, nepim_slot_buf_write,
                                on_udp_keepalive_time, udp_slot_kill);
      return OOP_CONTINUE;
    }
  }

  if ((session->max_bit_rate > 0) || (session->max_pkt_rate > 0)) {
    udp_write_rate(slot);
    return OOP_CONTINUE;
  }

  udp_write_full(slot);

  return OOP_CONTINUE;
}

static void will_slot_rate_write(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;
  int sd = slot->udp_sd;

#ifndef NDEBUG
  {
    if (session->max_bit_rate <= 0) {
      assert(session->max_pkt_rate > 0);
    }
    if (session->max_pkt_rate <= 0) {
      assert(session->max_bit_rate > 0);
    }
  }
#endif /* NDEBUG */

  assert(!slot->want_write);
  ++slot->want_write;

  if (nepim_usock_writer_add(&udp_tab, sd))
    return;

  nepim_global.oop_src->on_fd(nepim_global.oop_src, sd,
                              OOP_WRITE, on_udp_write, 0);
}

static void *on_udp_rate_delay(oop_source *src, struct timeval tv, void *user)
{
  nepim_slot_t *slot = user;
  nepim_session_t *session = &slot->session;

  assert(timercmp(&tv, &session->tv_send_rate, ==));
#ifndef NDEBUG
  {
    if (session->max_bit_rate <= 0) {
      assert(session->max_pkt_rate > 0);
    }
    if (session->max_pkt_rate <= 0) {
      assert(session->max_bit_rate > 0);
    }
  }
#endif /* NDEBUG */

  /* save next scheduling time */
  {
    int result = gettimeofday(&session->tv_send_rate, 0);
    assert(!result);
  }
  nepim_timer_usec_add(&session->tv_send_rate, session->write_delay);

  /* calculate bytes to be written from rate */
  session->rate_remaining = nepim_bps2bytes(session->max_bit_rate,
                                            session->write_delay);
  session->pkt_remaining = nepim_pps2packets(session->max_pkt_rate,
                                             session->write_delay);

#ifndef NDEBUG
 {
   if (session->rate_remaining <= 0) {
     assert(session->pkt_remaining > 0);
   }
   if (session->pkt_remaining <= 0) {
     assert(session->rate_remaining > 0);
   }
 }
#endif /* NDEBUG */

  /* start to write */
  will_slot_rate_write(slot);

  return OOP_CONTINUE;
}

static void cancel_slot_write(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;
  int sd = slot->udp_sd;

  assert(session->max_bit_rate < 1);
  assert(session->max_pkt_rate < 1);

  assert(slot->want_write == 1);
  --slot->want_write;

  if (nepim_usock_writer_del(&udp_tab, sd))
    return;

  nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                  sd, OOP_WRITE);
}

static void udp_slot_cancel_io(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;

  if (slot->client_writer_status == NEPIM_SLOT_CLIENT_GREET) {
    cancel_slot_greet_timer(slot);
    soft_cancel_slot_greet_writer(slot);

    return;
  }

  if (session->must_send) {
    if ((session->max_bit_rate > 0) || (session->max_pkt_rate > 0)) {
      /* stop current writing, if any */
      if (slot->want_write) {
        assert(slot->want_write == 1);
        cancel_slot_rate_write(slot);
      }

      /* stop periodic write scheduler */
      nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                        session->tv_send_rate,
                                        on_udp_rate_delay, slot);
    }
    else {
      cancel_slot_write(slot);
    }
  }
  else {
    if (session->keepalive_must_send) {
      if (slot->want_write) {
        assert(slot->want_write == 1);
        nepim_cancel_slot_keepalive(slot); /* keepalive write */
      }
      
      /* stop periodic keepalive scheduler */
      nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                        session->tv_keepalive_send_next,
                                        on_udp_keepalive_time,
                                        slot);
    }
  }

  assert(!slot->want_write);
}

static void udp_slot_kill(nepim_slot_t *slot)
{
  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, slot->udp_sd);

  udp_slot_cancel_stat_timers(slot);
  udp_slot_cancel_io(slot);

  if (slot->session.keepalive_require)
    nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                      slot->session.tv_keepalive_recv_timer,
                                      on_udp_keepalive_require, slot);

  cancel_slot_segment_read(slot);

  nepim_global.oop_src->cancel_signal(nepim_global.oop_src,
				      SIGINT, on_sigint, slot);
  nepim_global.oop_src->cancel_signal(nepim_global.oop_src,
				      SIGTERM, on_sigterm, slot);

  nepim_slot_set_del(&slots, slot->index);
}

static void will_slot_greet_writer(nepim_slot_t *slot)
{
  int sd = slot->udp_sd;

  assert(!slot->want_write);
  ++slot->want_write;

  if (nepim_usock_writer_add(&udp_tab, sd))
    return;

  nepim_global.oop_src->on_fd(nepim_global.oop_src, sd,
                              OOP_WRITE, on_udp_write, 0);
}

static void cancel_slot_greet_writer(nepim_slot_t *slot)
{
  int sd = slot->udp_sd;

  assert(slot->want_write == 1);
  --slot->want_write;

  if (nepim_usock_writer_del(&udp_tab, sd))
    return;

  nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                  sd, OOP_WRITE);
}

static void soft_cancel_slot_greet_writer(nepim_slot_t *slot)
{
  if (slot->want_write) {
    assert(slot->want_write == 1);
    cancel_slot_greet_writer(slot);
  }
}

static void cancel_slot_greet_timer(nepim_slot_t *slot)
{
  nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                    slot->session.tv_greet_rate,
                                    on_udp_time_greet, slot);
}

static void will_slot_segment_read(nepim_slot_t *slot)
{
  int sd = slot->udp_sd;

  if (nepim_usock_reader_add(&udp_tab, sd))
    return;

  nepim_global.oop_src->on_fd(nepim_global.oop_src, sd,
                              OOP_READ, on_udp_read_segment, 0);
}

static void cancel_slot_segment_read(nepim_slot_t *slot)
{
  int sd = slot->udp_sd;

  if (nepim_usock_reader_del(&udp_tab, sd))
    return;

  nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                  sd, OOP_READ);
}

static void *on_udp_time_greet(oop_source *src, struct timeval tv,
                               void *user)
{
  nepim_slot_t *slot = user;
  nepim_session_t *session;
  assert(slot);
  
  session = &slot->session;

  assert(timercmp(&tv, &session->tv_greet_rate, ==));

  /* save next scheduling time */
  {
    int result = gettimeofday(&session->tv_greet_rate, 0);
    assert(!result);
  }
  nepim_timer_usec_add(&session->tv_greet_rate, nepim_global.udp_greet_delay);

  /* wait opportunity to write on shared socket */
  will_slot_greet_writer(slot);

  return OOP_CONTINUE;
}

static int spawn_udp_connection(const char *hostport,
				const struct sockaddr *bindaddr,
				int bindaddr_len,
				const char *hostname,
                                const char *portname,
                                struct sockaddr *remote, 
                                socklen_t *remote_len)
{
  struct addrinfo hints;
  struct addrinfo *ai_res;
  struct addrinfo *ai;
  struct sockaddr_un un_sock_addr;
  struct stat stat_buf;
  int gai_lookup; /* boolean */
  int result;
  int sd = -1;

  memset(&hints, 0, sizeof(hints));

  if (nepim_global.search_unix_socket) {
    gai_lookup = stat(hostport, &stat_buf);
    if (gai_lookup)
      fprintf(stderr, "not a UNIX domain path: %s: errno=%d: %s\n",
	      hostport, errno, strerror(errno));
  }
  else
    gai_lookup = -1;

  if (gai_lookup) {
    /*
      Lookup hostname
    */
    
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = PF_UNSPEC;
    hints.ai_addrlen = 0;
    hints.ai_addr = 0;
    hints.ai_canonname = 0;

    fprintf(stderr, 
	    "UDP socket solving %s,%s\n",
	    hostname, portname);

    result = getaddrinfo(hostname, portname,
			 &hints, &ai_res);
    if (result) {
      fprintf(stderr, "%s: getaddrinfo(%s,%s): %s\n",
	      __PRETTY_FUNCTION__, 
	      hostname, portname,
	      gai_strerror(result));
      return -1;
    }
  }
  else {
    /*
      Unix socket
    */
    
    int len = strlen(hostport);
    if (len >= (int) sizeof(un_sock_addr.sun_path)) {
      fprintf(stderr, "%s %s: unix socket path overly long: len=%d > max=%d\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      len, (int) sizeof(un_sock_addr.sun_path) - 1);
      return -1;
    }

    memset(&un_sock_addr, 0, sizeof(un_sock_addr));

    un_sock_addr.sun_family = AF_UNIX;
    strcpy(un_sock_addr.sun_path, hostport);

    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_family = AF_UNIX;
    hints.ai_addrlen = sizeof(un_sock_addr);
    hints.ai_addr = (struct sockaddr *) &un_sock_addr;
    hints.ai_canonname = 0;

    ai_res = &hints;
  }

  for (ai = ai_res; ai; ai = ai->ai_next) {
    char addr_str[500];

    nepim_sock_dump_addr(addr_str, sizeof addr_str,
			 ai->ai_addr, ai->ai_addrlen);

    if (ai->ai_family == PF_UNIX)
      fprintf(stderr, 
	      "UNIX datagram socket trying path=%s\n",
	      hostport);
    else
      fprintf(stderr, 
	      "UDP socket trying %s,%d\n",
	      addr_str, nepim_sock_get_port(ai->ai_addr));

    if (nepim_global.no_inet6 && (ai->ai_family == PF_INET6))
      continue;

    if (nepim_global.no_inet4 && (ai->ai_family == PF_INET))
      continue;

    sd = nepim_connect_client_socket(nepim_global.verbose_stderr,
				     bindaddr, bindaddr_len,
				     ai->ai_addr, ai->ai_addrlen,
                                     ai->ai_family, ai->ai_socktype, 
                                     ai->ai_protocol,
                                     nepim_global.pmtu_mode,
                                     nepim_global.ttl,
                                     nepim_global.win_recv,
                                     nepim_global.win_send,
				     0 /* tcp nodelay */,
				     nepim_global.tos,
				     nepim_global.socket_keepalive,
				     nepim_global.client_tcp_mss,
				     nepim_global.router_alert,
				     0 /* join iface */);
    if (sd < 0) {
      if (ai->ai_family == AF_UNIX)
	fprintf(stderr, 
		"could not connect UNIX datagram socket to path=%s: %d\n",
		hostport, sd);
      else
	fprintf(stderr, 
		"could not connect UDP socket to %s,%d: %d\n",
		addr_str, nepim_sock_get_port(ai->ai_addr), sd);
      continue;
    }

    result = nepim_socket_mcast_ttl(sd, nepim_global.mcast_ttl);
    if (result) {
      fprintf(stderr,
              "%d: failure setting mcast_ttl=%d: %d\n",
              sd, nepim_global.mcast_ttl, result);
    }

    /* save remote address */
    assert(*remote_len >= ai->ai_addrlen);
    memcpy(remote, ai->ai_addr, ai->ai_addrlen);
    *remote_len = ai->ai_addrlen;

    {
      union {
        struct sockaddr_in inet;
        struct sockaddr_in6 inet6;
	struct sockaddr_un un;
      } local_sockaddr;
      socklen_t local_sockaddr_len = sizeof(local_sockaddr);
      int result;
      char local[500];
      
      result = getsockname(sd, (struct sockaddr *) &local_sockaddr,
                           &local_sockaddr_len);
      assert(!result);

      nepim_sock_dump_addr(local, sizeof(local),
                           (const struct sockaddr *) &local_sockaddr,
			   local_sockaddr_len);

      if (ai->ai_family == AF_UNIX)
	fprintf(stderr, 
		"%d: UNIX datagram socket connected to: path=%s",
		sd, local);
      else
	  fprintf(stderr, 
		  "%d: UDP socket (%s,%d) connected to %s,%d\n",
		  sd, local,
		  nepim_sock_get_port((struct sockaddr *) &local_sockaddr),
		  addr_str, nepim_sock_get_port(ai->ai_addr));
    }

    break;
  }

  if (gai_lookup)
    freeaddrinfo(ai_res);

  return sd;
}

static void parse_hosts(const char *host_list)
{
  int size = addr_list_size(host_list);
  int i, j;
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
  } bind_buf;
  int bind_addr_len = sizeof bind_buf;
  struct sockaddr *bind_addr = 0;

  if (nepim_global.bind_list) {
    bind_addr = nepim_addrlist_findfirst(SOCK_DGRAM, IPPROTO_UDP,
					 nepim_global.bind_list,
					 (struct sockaddr *) &bind_buf,
					 &bind_addr_len);
    if (!bind_addr)
      return;
  }

  /* scan host_list */
  for (j = 0; j < size; ++j) {
    char hostport[100];
    char hostname[100];
    char *portname;

    /* get hostname */
    if (addr_list_get(host_list, j, hostname, sizeof(hostname))) {
      fprintf(stderr, 
              "%s: failure parsing address %d/%d from list: %s\n",
              nepim_global.prog_name, j, size, host_list);
      continue;
    }

    strcpy(hostport, hostname); /* save original "host,port" */

    /* split host/port */
    if (addr_split_port(hostname, sizeof(hostname), &portname))
      portname = (char *) nepim_global.portname;

    /* create sockets */
    for (i = 0; i < nepim_global.pipes; ++i) {
      union {
        struct sockaddr_in inet;
        struct sockaddr_in6 inet6;
	struct sockaddr_un un;
      } remote;
      socklen_t remote_len = sizeof(remote);
      int sd;
      nepim_greet_t opt;

      sd = spawn_udp_connection(hostport,
				bind_addr, bind_addr_len,
				hostname, portname, 
                                (struct sockaddr *) &remote, 
                                &remote_len);
      if (sd < 0)
        continue;

      /* add socket to table of readers/writers */
      nepim_usock_set_add(&udp_tab, sd);

      opt.must_send               = nepim_global.duplex_mode
        || nepim_global.simplex_client_send;
      opt.bit_rate                = nepim_global.bit_rate;
      opt.pkt_rate                = nepim_global.pkt_rate;
      opt.stat_interval           = nepim_global.stat_interval;
      opt.test_duration           = nepim_global.test_duration;
      opt.write_delay             = nepim_global.write_delay;
      opt.keepalive_must_send     = nepim_global.udp_keepalive_must_send;
      opt.keepalive_require       = nepim_global.udp_keepalive_require;
      opt.keepalive_timeout       = nepim_global.udp_keepalive_recv_timer;
      opt.keepalive_send_delay    = nepim_global.udp_keepalive_send_delay;
      opt.seed                    = nepim_global.seed;
      opt.verify_data             = nepim_global.verify_data;
      opt.random_fill             = nepim_global.random_fill;
      opt.fill_byte               = nepim_global.fill_byte;
      opt.pause_duration          = nepim_global.pause_duration;
      opt.overhead                = nepim_global.udp_overhead;
      opt.sweep_random            = nepim_global.sweep_random;
      opt.sweep_step              = nepim_global.sweep_step;
      opt.write_floor             = nepim_global.write_floor;
      opt.write_ceil              = nepim_global.write_ceil;
      opt.report_partial_min_max  = nepim_global.report_partial_min_max;
      
      /* create UDP slots */
      for (i = 0; i < nepim_global.pipes; ++i) {
        int local_slot = nepim_slot_find_free(&slots);
        int remote_slot = 0xFFFF;

        nepim_slot_set_add(&slots, sd, 
                           local_slot, remote_slot,
                           (const struct sockaddr *) &remote,
                           remote_len, &opt);
      }
    }

  } /* scan host_list */
}

void nepim_udp_clients(const char *host_list)
{
  int i;

  /* spawn sockets */
  parse_hosts(host_list);

  /* activate monitoring for UDP socket */

  for (i = 0; i < slots.array.capacity; ++i) {
    nepim_slot_t *slot = nepim_slot_set_get(&slots, i);
    nepim_session_t *session;

    if (!slot)
      continue;

    session = &slot->session;

    /* 
       schedule periodic greetings 
       (until answer from server)
    */
    session->tv_greet_rate = OOP_TIME_NOW;
    nepim_global.oop_src->on_time(nepim_global.oop_src,
                                  session->tv_greet_rate,
                                  on_udp_time_greet, slot);

    /* wait answers */
    will_slot_segment_read(slot);
  }
}
