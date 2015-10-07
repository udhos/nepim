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

/* $Id: udp_server.c,v 1.115 2014/07/10 06:55:44 evertonm Exp $ */


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <oop.h>
#include <assert.h>
#include <inttypes.h>

#include "conf.h"
#include "sock.h"
#include "common.h"
#include "slot.h"
#include "usock.h"
#include "udp_header.h"
#include "tcpwrap.h"

extern nepim_slot_set_t  slots;   /* from server.c */
extern nepim_usock_set_t udp_tab; /* from server.c */

static void schedule_stat_interval(int local_slot);
static void udp_slot_cancel_stat_timers(nepim_slot_t *slot);
static void *on_udp_rate_delay(oop_source *src, struct timeval tv,
			       void *user);
static void *on_udp_write(oop_source *src, int sd,
			  oop_event event, void *user);
static void cancel_slot_rate_write(nepim_slot_t *slot);
static void cancel_slot_write(nepim_slot_t *slot);
static void udp_slot_cancel_writers(nepim_slot_t *slot);
static void *on_udp_keepalive_time(oop_source *src, struct timeval tv,
				   void *user);
static void *on_udp_keepalive_require(oop_source *src, struct timeval tv,
				      void *user);
static void udp_slot_kill(nepim_slot_t *slot);


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

  schedule_stat_interval(slot->index);

  return OOP_CONTINUE;
}

static void schedule_stat_interval(int local_slot)
{
  nepim_slot_t *slot = nepim_slot_set_get(&slots, local_slot);
  nepim_session_t *session;
  assert(slot);

  session = &slot->session;

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
  slot->total_pkt_recv    = 0;
  slot->total_pkt_lost    = 0;
  slot->total_pkt_ooo     = 0;

#if 0
  udp_slot_cancel_stat_timers(slot);
  udp_slot_cancel_writers(slot);

  fprintf(stderr, 
	  "DEBUG FIXME %s %s: (%d-%d) finished, "
	  "not killed (beware possibly active remote sender)\n",
	  __FILE__, __PRETTY_FUNCTION__,
	  slot->index, slot->index_remote);
#else
  udp_slot_kill(slot);
#endif

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

static void udp_slot_cancel_writers(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;

  if (session->must_send) {
    if ((session->max_bit_rate > 0) || (session->max_pkt_rate > 0)) {
      /* stop current writing, if any */
      if (slot->want_write) {
	assert(slot->want_write == 1);
	cancel_slot_rate_write(slot); /* rate write */
      }
      
      /* stop periodic write scheduler */
      nepim_global.oop_src->cancel_time(nepim_global.oop_src,
					session->tv_send_rate,
					on_udp_rate_delay, slot);
    }
    else {
      cancel_slot_write(slot); /* full write */
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
					on_udp_keepalive_time, slot);
    }
  }

  assert(!slot->want_write);
}

static void udp_slot_cancel_io(nepim_slot_t *slot)
{
  udp_slot_cancel_writers(slot);
}

static void udp_slot_kill(nepim_slot_t *slot)
{
  int slot_index = slot->index;

  udp_slot_cancel_stat_timers(slot);
  udp_slot_cancel_io(slot);

  if (slot->session.keepalive_require)
    nepim_global.oop_src->cancel_time(nepim_global.oop_src,
				      slot->session.tv_keepalive_recv_timer,
				      on_udp_keepalive_require, slot);

  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, slot->udp_sd);

  nepim_slot_set_del(&slots, slot_index);
}

void nepim_slot_kill(nepim_slot_t *slot)
{
  udp_slot_kill(slot);
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

static void udp_write_rate(nepim_slot_t *slot)
{
  char buf[nepim_global.udp_write_size];
  int wr;                   /* payload only */
  int full_wr;              /* payload plus overhead */
  nepim_session_t *session;
  int sweep_write;
  int to_write;
  int sd;

  assert(nepim_global.udp_write_size == sizeof(buf));
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

  wr = nepim_slot_buf_sendto(slot, buf, to_write, UDP_TYPE_DATA);
  if (wr < 0) {
    switch (errno) {
    case EINTR:
    case EAGAIN:
      nepim_usock_write_error(&udp_tab, sd, 
			      slot->index, slot->index_remote,
			      errno, nepim_global.soft_error_verbose);

      return;
    case EPIPE:
      fprintf(stderr, "rate_write: EPIPE on UDP socket %d\n", sd);
      break;
    default:
      fprintf(stderr, "rate_write: UDP socket: sd=%d: errno=%d: %s\n",
	      sd, errno, strerror(errno));
    }

    fprintf(stderr, "rate_write: connection lost on UDP socket %d\n", sd);

    if (!session->duration_done)
      report_broken_slot_stat(stdout, slot);

    udp_slot_kill(slot);

    return;
  }

  assert(wr >= 0);
  assert(wr <= to_write);

  if (wr == to_write)
    nepim_usock_write_good_full(&udp_tab, sd);
  else
    nepim_usock_write_good_partial(&udp_tab, sd);

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
  int wr;
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

  wr = nepim_slot_buf_sendto(slot, buf, to_write, UDP_TYPE_DATA);
  if (wr < 0) {
    switch (errno) {
    case EINTR:
    case EAGAIN:
      nepim_usock_write_error(&udp_tab, sd, 
			      slot->index, slot->index_remote,
			      errno, nepim_global.soft_error_verbose);

      return;
    case EPIPE:
      fprintf(stderr, "write: EPIPE on UDP socket %d\n", sd);
      break;
    default:
      fprintf(stderr, "write: UDP socket: sd=%d errno=%d: %s\n",
	      sd, errno, strerror(errno));
    }

    fprintf(stderr, "write: connection lost on UDP socket %d\n", sd);

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
  nepim_slot_t *slot;
  nepim_session_t *session;

  assert(!user);
  assert(event == OOP_WRITE);

  slot = nepim_slot_find_next_writer(&slots, sd);
  assert(slot);

  session = &slot->session;

  if (!session->must_send) {
    if (session->keepalive_must_send) {
      nepim_udp_write_keepalive(slot, nepim_slot_buf_sendto,
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

static void udp_slot_start(int local_slot)
{
  nepim_slot_t *slot = nepim_slot_set_get(&slots, local_slot);
  nepim_session_t *session;
  int sd;
  assert(slot);

  session = &slot->session;
  sd = slot->udp_sd;

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

  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, sd);

  schedule_stat_interval(local_slot);

  if (session->keepalive_require)
    nepim_schedule_keepalive_timer(slot, on_udp_keepalive_require);
}

static void *on_udp_slot_start(oop_source *src, struct timeval tv, void *user)
{
  intptr_t i = 0xFFFF & (intptr_t) user;
  int local_slot = i;

  udp_slot_start(local_slot);

  return OOP_CONTINUE;
}

static void schedule_udp_slot_start(int local_slot)
{
  nepim_slot_t *slot = nepim_slot_set_get(&slots, local_slot);
  nepim_session_t *session;
  struct timeval pause;

  session = &slot->session;

  if (session->pause_duration > 0) {
    /* 
       HACK:
       Send back a packet as an ack,
       otherwise the client might exit
       with "server not responding"
       (due to our pause delay)
    */
    char buf[nepim_global.udp_write_size];
    (void) nepim_slot_buf_sendto(slot, buf, sizeof(buf), UDP_TYPE_DATA);
  }

  {
      int result = gettimeofday(&pause, 0);
      assert(!result);
  }
  pause.tv_sec += session->pause_duration;
  nepim_global.oop_src->on_time(nepim_global.oop_src,
				pause,
				on_udp_slot_start, (void *) (intptr_t) local_slot);
}

static int parse_greetings(nepim_greet_t *opt,
			   int sd, int local_slot, int remote_slot,
			   char *buf, const int buf_len,
			   const struct sockaddr *remote,
			   socklen_t remote_len)
{
  int result;
  char *eos;
  char *past_end;
  char peer[500];
  char password_buf[100];

  eos = memchr(buf, '\n', buf_len);
  if (eos) {
    past_end = eos;
    *past_end = '\0';
#if 0
    fprintf(stderr, 
	    "%d: %d-%d: %s: %s: minimum UDP read size (%d) needed for greeting.\n",
	    sd, local_slot, remote_slot,
	    __FILE__, __PRETTY_FUNCTION__,
	    (UDP_HEADER_LEN + strlen(buf) + 1));
#endif
  } else {

    /* 
       Prevent greeting from being garbled when the UDP read size is
       too small.
    */
    fprintf(stderr, 
	    "%d: %d-%d: %s: %s: UDP read size (%d) too small for greeting.\n",
	    sd, local_slot, remote_slot,
	    __FILE__, __PRETTY_FUNCTION__,
	    (UDP_HEADER_LEN + buf_len));
    return 1;
  }

  assert(past_end >= buf);
  assert(past_end <= (buf + buf_len));

  opt->password_buf = password_buf;
  opt->password_buf_size = sizeof(password_buf);

  result = nepim_parse_greetings(opt, 0 /* is_tcp=false */, buf, past_end);
  if (result)
    return result;

  nepim_sock_dump_addr(peer, sizeof(peer),
		       (const struct sockaddr *) remote,
		       remote_len);

  fprintf(stderr, 
	  "%d %d-%d: UDP from (%s,%d): send=%d bps=%lld pps=%d "
	  "interval=%d duration=%d delay=%ld ka_send=%d ka_req=%d ka_tmout=%d ka_delay=%d "
          "seed=0x%08x verify_data=%d random_fill=%d fill_byte=0x%02x pause_duration=%d "
	  "sock_ka=%d overhead=%d "
	  "sweep_random=%d sweep_step=%d write_floor=%d write_ceil=%d "
	  "p_minmax=%d mss=%d "
	  "password=%s\n", 
	  sd, 
	  local_slot, remote_slot,
	  peer,
	  nepim_sock_get_port((struct sockaddr *) remote),
	  opt->must_send, opt->bit_rate, opt->pkt_rate,
	  opt->stat_interval, opt->test_duration, 
	  opt->write_delay, opt->keepalive_must_send,
	  opt->keepalive_require, opt->keepalive_timeout, opt->keepalive_send_delay,
          opt->seed,
	  opt->verify_data, opt->random_fill, opt->fill_byte,
	  opt->pause_duration, opt->socket_keepalive,
	  opt->overhead,
	  opt->sweep_random, opt->sweep_step, opt->write_floor, opt->write_ceil,
	  opt->report_partial_min_max, opt->mss,
	  password_buf);

  nepim_conf_write_sweep_auto(1 /* udp=true */,
			      &(opt->write_floor),
			      &(opt->write_ceil));

  nepim_conf_write_sweep_fit(1 /* udp=true */,
			     &(opt->write_floor),
			     &(opt->write_ceil));

  fprintf(stderr, 
          "%d %d-%d: sweep write: floor=%d ceil=%d\n",
	  sd, 
	  local_slot, remote_slot,
	  opt->write_floor, opt->write_ceil);

  if (nepim_global.tcpwrap) {
    if (!nepim_hosts_ctl(nepim_global.tcpwrap,
			 nepim_global.prog_name,
			 peer)) {
      fprintf(stderr, 
	      "%d: %d-%d: %s: %s: TCP wrapper denied access from client=[%s] to service=[%s]\n",
	      sd, local_slot, remote_slot,
	      __FILE__, __PRETTY_FUNCTION__,
	      peer, nepim_global.prog_name);
      return 1;
    }
  }

  if (nepim_global.password)
    if (strcmp(nepim_global.password, password_buf)) {
      fprintf(stderr, "%d: bad client password=%s\n",
	      sd, password_buf);
      return 1;
    }

  return 0;
}

static void udp_consume(nepim_slot_t *slot, size_t len,
			const nepim_udp_hdr_t *hdr)
{
  nepim_session_t *session = &slot->session;

  /* any valid traffic accounted as keepalive */
  ++session->keepalives_recv;

  if (hdr->type == UDP_TYPE_DATA)
    nepim_slot_seq_recv(slot, hdr->seq);

  nepim_session_read_add(session, len + session->overhead);
}

static void *on_udp_segment(oop_source *src, int sd,
                            oop_event event, void *unnused)
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
  assert(!unnused);

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

  /*
    For UNIX-domain datagram sockets.
   */
  if (fromlen < 1) {
    fromlen = sizeof(from);
    if (getsockname(sd, (struct sockaddr *) &from, &fromlen)) {
      fprintf(stderr,
	      "%d: getsockname: errno=%d: %s\n",
	      sd, errno, strerror(errno));
    }
  }

  assert(fromlen > 0);

  nepim_usock_read_good(&udp_tab, sd);

  if (nepim_udp_hdr_parse(&hdr, buf, rd)) {
    fprintf(stderr, 
	    "%d: recvfrom: could not parse header from UDP segment: %d/%d bytes\n",
	    sd, rd, nepim_global.udp_read_size);
    return OOP_CONTINUE;
  }

  if (hdr.version != UDP_VERSION) {
    fprintf(stderr, "%d: recvfrom: ignoring unknown UDP header version: %d\n",
	    sd, hdr.version);
    return OOP_CONTINUE;
  }

  /* request for new slot? */
  if (hdr.type == UDP_TYPE_HELLO) {
    int result;
    int local_slot;
    nepim_greet_t opt;

#if 0
    fprintf(stderr, 
	    "DEBUG %s %s: new slot request: %d (%d-%d)\n",
	    __FILE__, __PRETTY_FUNCTION__, 
	    sd,
	    nepim_uint16_read(buf + 1),
	    nepim_uint16_read(buf + 3));
#endif

    if (hdr.seq) {
      fprintf(stderr, "%d %d-%d: warn: ignoring invalid UDP hello header sequence: %" PRIu64 "\n",
	      sd, hdr.dst_slot, hdr.src_slot, hdr.seq);
      return OOP_CONTINUE;
    }

    if (nepim_slot_find_addr(&slots, hdr.src_slot, 
			     (const struct sockaddr *) &from,
			     fromlen)) {
      fprintf(stderr, 
	      "%d %d-%d: normal behavior: ignoring existing remote src_slot/addr pair\n",
	      sd, hdr.dst_slot, hdr.src_slot);

      /* 
	 HACK:
	 Send back a packet as an ack,
	 otherwise the client might exit
	 with "server not responding"
	 (due to our pause delay)
      */
      {
	nepim_slot_t *slot;
	slot = nepim_slot_set_search_remote(&slots, 
					    (const struct sockaddr *) &from,
					    fromlen);
	if (slot->session.pause_duration > 0)
	  (void) nepim_slot_buf_sendto(slot, buf, sizeof(buf), UDP_TYPE_DATA);
      }

      return OOP_CONTINUE;
    }

    result = parse_greetings(&opt, sd,
			     hdr.dst_slot, hdr.src_slot, 
			     buf + UDP_HEADER_LEN, 
			     rd - UDP_HEADER_LEN,
			     (const struct sockaddr *) &from,
			     fromlen);
    if (result) {
      fprintf(stderr, 
	      "%d %d-%d: recvfrom: bad greetings: %d\n",
	      sd, hdr.dst_slot, hdr.src_slot, result);
      return OOP_CONTINUE;
    }

    local_slot = nepim_slot_find_free(&slots);

    assert(local_slot < 0xFFFF);

    /*
      multiple UDP clients (slots) on the same socket will
      probably clash distinct requests for socket keepalive
     */
    nepim_socket_keepalive(nepim_global.verbose_stderr,
			   sd, opt.socket_keepalive);

    nepim_slot_set_add(&slots, sd, 
		       local_slot, hdr.src_slot,
		       (const struct sockaddr *) &from, 
		       fromlen,
		       &opt);

    schedule_udp_slot_start(local_slot);

    return OOP_CONTINUE;

  } /* new slot request */

  {
    nepim_slot_t *slot = nepim_slot_set_search(&slots, hdr.dst_slot);

    /*
      multicast client can't know the server slot index,
      since the multicast server never send replies.
      so, the server finds the slot by socket address.
    */
    if (!slot)
      slot = nepim_slot_set_search_remote(&slots, 
					  (const struct sockaddr *) &from,
					  fromlen);

    if (!slot) {
      if (nepim_global.debug_error_verbose)
	fprintf(stderr,
		"%d: recvfrom: unknown local slot: %d\n",
		sd, hdr.dst_slot);
      return OOP_CONTINUE;
    }

    if (slot->index_remote != hdr.src_slot) {
      if (nepim_global.debug_error_verbose)
	fprintf(stderr, 
		"%d %d: recvfrom: remote index mismatch: expected=%d got=%d\n",
		sd, hdr.dst_slot, slot->index_remote, hdr.src_slot);
      return OOP_CONTINUE;
    }

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

    udp_consume(slot, rd, &hdr);

    udp_check_packet_data(sd, &hdr, &(slot->session),
			  (unsigned char *) buf, UDP_HEADER_LEN, rd);
  }

  return OOP_CONTINUE;
}

static int udp_listener(const char *ssm_source,
			const struct sockaddr *ssm_source_addr,
			int ssm_source_addrlen,
			const char *hostname,
			const char *portname, 
			int mcast_join,
			const char *join_iface)
{
  struct addrinfo hints;
  struct addrinfo *ai_res;
  struct addrinfo *ai;
  int result;
  int udp_listeners = 0;

#if 0
  fprintf(stderr,
	  "DEBUG %s %s: mcast_join=%d ssm_source=%s host/group=%s port=%s\n",
	  __FILE__, __PRETTY_FUNCTION__,
	  mcast_join, ssm_source, hostname, portname);
#endif

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_PASSIVE | AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;
  hints.ai_addrlen = 0;
  hints.ai_addr = 0;
  hints.ai_canonname = 0;

  result = getaddrinfo(hostname, portname, &hints, &ai_res);
  if (result) {
    fprintf(stderr, "%s %s: getaddrinfo(%s,%s): %s\n",
	    __FILE__, __PRETTY_FUNCTION__,
            hostname, portname, gai_strerror(result));
    return 0;
  }

  for (ai = ai_res; ai; ai = ai->ai_next) {
    char ssm_source_addrstr[500];
    char addr_str[500];
    int sd;

    if (nepim_global.no_inet6 && (ai->ai_family == PF_INET6))
      continue;

    if (nepim_global.no_inet4 && (ai->ai_family == PF_INET))
      continue;

    if (ssm_source)
      nepim_sock_dump_addr(ssm_source_addrstr, sizeof(ssm_source_addrstr),
			   ssm_source_addr, ssm_source_addrlen);

    nepim_sock_dump_addr(addr_str, sizeof(addr_str),
			 ai->ai_addr, ai->ai_addrlen);

#if 0
  fprintf(stderr,
	  "DEBUG %s %s: ssm_addr=%s host/group_addr=%s\n",
	  __FILE__, __PRETTY_FUNCTION__,
	  ssm_source_addrstr, addr_str);
#endif

    sd = nepim_create_socket(nepim_global.verbose_stderr,
			     ai->ai_addr, ai->ai_addrlen,
			     ai->ai_family, ai->ai_socktype, 
			     ai->ai_protocol,
			     nepim_global.pmtu_mode,
			     nepim_global.ttl,
			     mcast_join,
			     nepim_global.win_recv,
			     nepim_global.win_send,
			     0 /* tcp nodelay */,
			     nepim_global.tos,
			     nepim_global.server_tcp_mss,
			     nepim_global.router_alert,
			     join_iface,
			     ssm_source_addr,
			     ssm_source_addrlen);
    if (sd < 0) {
      if (ssm_source)
	fprintf(stderr, 
		"%s %s: UDP listener socket failed for %s+%s@%s,%d: %d\n",
		__FILE__, __PRETTY_FUNCTION__,
		ssm_source_addrstr,
		addr_str,
		join_iface ? join_iface : "any",
		nepim_sock_get_port(ai->ai_addr), sd);
      else
	fprintf(stderr, 
		"%s %s: UDP listener socket failed for %s@%s,%d: %d\n",
		__FILE__, __PRETTY_FUNCTION__,
		addr_str,
		join_iface ? join_iface : "any",
		nepim_sock_get_port(ai->ai_addr), sd);
      continue;
    }

    nepim_global.oop_src->on_fd(nepim_global.oop_src,
			  	sd, OOP_READ,
				on_udp_segment, 0);

    nepim_usock_set_add(&udp_tab, sd);

    ++udp_listeners;

    if (ssm_source)
	fprintf(stderr, 
		"%d: UDP socket listening on %s+%s@%s,%d\n",
		sd, ssm_source_addrstr,
		addr_str,
		join_iface ? join_iface : "any",
		nepim_sock_get_port(ai->ai_addr));
      else
	fprintf(stderr, 
		"%d: UDP socket listening on %s@%s,%d\n",
		sd, addr_str,
		join_iface ? join_iface : "any",
		nepim_sock_get_port(ai->ai_addr));

    nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, sd);
  }

  freeaddrinfo(ai_res);

  return udp_listeners;
}

int nepim_udp_listener(const char *ssm_source,
		       const char *hostname,
		       const char *portname, 
		       int mcast_join,
		       const char *join_iface)
{
  struct addrinfo hints;
  struct addrinfo *ai_res;
  struct addrinfo *ai;
  int result;
  int udp_listeners = 0;

  if (!ssm_source)
    return udp_listener(0  /* ssm_source */,
			0  /* ssm_source_addr */,
			-1 /* ssm_source_addrlen */,
			hostname,
			portname,
			mcast_join,
			join_iface);

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_PASSIVE | AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;
  hints.ai_addrlen = 0;
  hints.ai_addr = 0;
  hints.ai_canonname = 0;

  result = getaddrinfo(ssm_source, 0, &hints, &ai_res);
  if (result) {
    fprintf(stderr, "%s: getaddrinfo(%s): %s\n",
	    __PRETTY_FUNCTION__,
            ssm_source, gai_strerror(result));
    return 0;
  }

  /* Scan ssm_source addresses */

  for (ai = ai_res; ai; ai = ai->ai_next) {

    if (nepim_global.no_inet6 && (ai->ai_family == PF_INET6))
      continue;

    if (nepim_global.no_inet4 && (ai->ai_family == PF_INET))
      continue;

    udp_listeners += udp_listener(ssm_source,
				  ai->ai_addr,
				  ai->ai_addrlen,
				  hostname,
				  portname,
				  mcast_join,
				  join_iface);
  }

  freeaddrinfo(ai_res);

  return udp_listeners;
}

int nepim_unix_dgram_listener(const char *path)
{
  struct sockaddr_un un_sock_addr;
  int len;
  int sd;

  len = strlen(path);
  if (len >= (int) sizeof(un_sock_addr.sun_path)) {
    fprintf(stderr, "%s %s: unix socket path overly long: len=%d > max=%d\n",
	    __FILE__, __PRETTY_FUNCTION__,
	    len, (int) sizeof(un_sock_addr.sun_path) - 1);
    return 0;
  }
  
  memset(&un_sock_addr, 0, sizeof(un_sock_addr));
  
  un_sock_addr.sun_family = AF_UNIX;
  strcpy(un_sock_addr.sun_path, path);
  
  sd = nepim_create_socket(nepim_global.verbose_stderr,
			   (struct sockaddr *) &un_sock_addr, 
			   sizeof(un_sock_addr),
			   AF_UNIX,
			   SOCK_DGRAM, 
			   0,
			   nepim_global.pmtu_mode,
			   nepim_global.ttl,
			   0 /* mcast_join */,
			   nepim_global.win_recv,
			   nepim_global.win_send,
			   0 /* tcp nodelay */,
			   nepim_global.tos,
			   nepim_global.server_tcp_mss,
			   nepim_global.router_alert,
			   0  /* join iface */,
			   0  /* ssm_source_addr */,
			   -1 /* ssm_source_addrlen */);
  if (sd < 0) {
    fprintf(stderr, 
	    "%s %s: UNIX datagram listener socket failed for path=%s\n",
	    __FILE__, __PRETTY_FUNCTION__, path); 
    return 0;
  }

  nepim_global.oop_src->on_fd(nepim_global.oop_src,
			      sd, OOP_READ,
			      on_udp_segment, 0);

  nepim_usock_set_add(&udp_tab, sd);

  fprintf(stderr, 
	  "%d: UNIX datagram socket listening on path=%s\n",
	  sd, path);

  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, sd);

  return 1;
}
