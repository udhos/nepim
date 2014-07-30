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

/* $Id: server.c,v 1.87 2008/08/22 02:01:19 evertonm Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

#include "conf.h"
#include "sock.h"
#include "pipe.h"
#include "common.h"
#include "slot.h"
#include "usock.h"
#include "str.h"
#include "tcpwrap.h"

nepim_pipe_set_t  pipes;   /* tcp socket table */
nepim_slot_set_t  slots;   /* udp pseudo-sockets */
nepim_usock_set_t udp_tab; /* udp socket table */

static const char * const INET_ANY = "0.0.0.0";
static const char * const INET6_ANY = "::";

void nepim_slot_kill(nepim_slot_t *slot); /* udp_server.c */

static void schedule_stat_interval(int sd);
static void tcp_pipe_cancel_timers(int sd);
static void tcp_pipe_cancel_io(int sd);
static void tcp_pipe_kill(int sd);
static void *on_tcp_rate_delay(oop_source *src, struct timeval tv, void *user);
static void *on_tcp_keepalive_time(oop_source *src, struct timeval tv, void *user);

static void *on_tcp_read(oop_source *src, int sd,
                         oop_event event, void *user)
{
  char buf[nepim_global.tcp_read_size];
  int rd;
  nepim_pipe_t *pipe = user;
  nepim_session_t *session = &pipe->session;

  assert(nepim_global.tcp_read_size = sizeof(buf));

  errno = 0;

  rd = read(sd, buf, nepim_global.tcp_read_size);
  if (rd <= 0) {
    if (rd) {
      switch (errno) {
      case EINTR:
        fprintf(stderr, "read: EINTR on TCP socket %d\n", sd);
        return OOP_CONTINUE;
      case EAGAIN:
        fprintf(stderr, "read: EAGAIN on TCP socket %d\n", sd);
        return OOP_CONTINUE;
      default:
        fprintf(stderr, "read: errno=%d: %s\n",
                errno, strerror(errno));
      }

      fprintf(stderr, "read: connection lost on TCP socket %d\n", sd);
    }
    else {
      fprintf(stderr, "read: connection closed on TCP socket %d\n", sd);
    }

    if (!session->duration_done)
      report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_kill(sd);

    return OOP_CONTINUE;
  }

  assert(rd >= 0);
  assert(rd <= sizeof(buf));

  /* any valid input traffic accounted as keepalive */
  ++session->keepalives_recv;
  
  /* modifies 'session->seed' */
  tcp_check_data(sd, session, (unsigned char *) buf, rd);

  nepim_session_read_add(session, rd + session->overhead);

  return OOP_CONTINUE;
}

static void *on_tcp_write(oop_source *src, int sd,
                          oop_event event, void *user)
{
  char buf[nepim_global.tcp_write_size];
  int wr;
  nepim_pipe_t *pipe = user;
  nepim_session_t *session = &pipe->session;
  unsigned old_seed;
  int to_write;

  assert(event == OOP_WRITE);
  assert(sd == pipe->sd);
  assert(session->max_bit_rate < 1);
  assert(session->max_pkt_rate < 1);

  assert(sizeof(buf) == nepim_global.tcp_write_size);

  to_write = nepim_write_sweep(session);
  assert(to_write >= 0);
  assert(to_write <= nepim_global.tcp_write_size);

  old_seed = session->seed;
  /* modifies 'session->seed' */
  fill_packet_data(session, (unsigned char *) buf, 0, to_write);

  wr = write(sd, buf, to_write);
  if (wr < 0) {
    session->seed = old_seed;   /* rewind seed */
    switch (errno) {
    case EINTR:
      fprintf(stderr, "write: EINTR on TCP socket %d\n", sd);
      return OOP_CONTINUE;
    case EAGAIN:
      fprintf(stderr, "write: EAGAIN on TCP socket %d\n", sd);
      return OOP_CONTINUE;
    case EPIPE:
      fprintf(stderr, "write: EPIPE on TCP socket %d\n", sd);
      break;
    default:
      fprintf(stderr, "write: errno=%d: %s\n",
	      errno, strerror(errno));
    }

    fprintf(stderr, "write: connection lost on TCP socket %d\n", sd);

    if (!session->duration_done)
      report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_kill(sd);

    return OOP_CONTINUE;
  }
  if (wr < to_write) {
      /* rewind seed to use exactly 'wr' bytes */
      session->seed = old_seed;
      /* modifies 'session->seed' */
      fill_packet_data(session, (unsigned char *) buf, 0, wr);
  }

  assert(wr >= 0);
  assert(wr <= to_write);
  assert(to_write <= (sizeof buf));

  nepim_session_write_add(session, wr + session->overhead);

  return OOP_CONTINUE;
}

static void *on_tcp_rate_write(oop_source *src, int sd,
                               oop_event event, void *user)
{
  char buf[nepim_global.tcp_write_size];
  int wr;      /* payload only */
  int full_wr; /* payload plus overhead */
  nepim_pipe_t *pipe = user;
  nepim_session_t *session = &pipe->session;
  int sweep_write;
  int to_write;
  unsigned old_seed;

  assert(event == OOP_WRITE);
  assert(sd == pipe->sd);
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

  assert(sizeof(buf) == nepim_global.tcp_write_size);

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
  assert(sweep_write >= 0);
  assert(sweep_write <= (sizeof buf));

  if (session->rate_remaining > 0)
    to_write = NEPIM_RANGE(session->rate_remaining - session->overhead,
			   0,
			   sweep_write);
  else
    to_write = sweep_write;

  assert(to_write >= 0);
  assert(to_write <= sweep_write);

  old_seed = session->seed;
  /* modifies 'session->seed' */
  fill_packet_data(session, (unsigned char *) buf, 0, to_write);

  wr = write(sd, buf, to_write);
  if (wr < 0) {
    session->seed = old_seed;   /* rewind seed */
    switch (errno) {
    case EINTR:
      fprintf(stderr, "rate_write: EINTR on TCP socket %d\n", sd);
      return OOP_CONTINUE;
    case EAGAIN:
      fprintf(stderr, "rate_write: EAGAIN on TCP socket %d\n", sd);
      return OOP_CONTINUE;
    case EPIPE:
      fprintf(stderr, "rate_write: EPIPE on TCP socket %d\n", sd);
      break;
    default:
      fprintf(stderr, "rate_write: errno=%d: %s\n",
	      errno, strerror(errno));
    }

    fprintf(stderr, "rate_write: connection lost on TCP socket %d\n", sd);

    if (!session->duration_done)
      report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_kill(sd);

    return OOP_CONTINUE;
  }
  if (wr < to_write) {
      /* rewind seed to use exactly 'wr' bytes */
      session->seed = old_seed;
      /* modifies 'session->seed' */
      fill_packet_data(session, (unsigned char *) buf, 0, wr);
  }

  assert(wr >= 0);
  assert(wr <= sizeof(buf));
  assert(wr <= to_write);
  assert(to_write <= sweep_write);

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
    nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                    sd, OOP_WRITE);

    /* schedule for next time saved by on_tcp_rate_delay() */
    nepim_global.oop_src->on_time(nepim_global.oop_src,
                                  session->tv_send_rate,
                                  on_tcp_rate_delay, pipe);
  }

  return OOP_CONTINUE;
}

static void *on_tcp_rate_delay(oop_source *src, struct timeval tv, void *user)
{
  nepim_pipe_t *pipe = user;
  nepim_session_t *session = &pipe->session;

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
  nepim_global.oop_src->on_fd(nepim_global.oop_src,
                              pipe->sd, OOP_WRITE,
                              on_tcp_rate_write, pipe);

  return OOP_CONTINUE;
}

static void *on_tcp_duration(oop_source *src, struct timeval tv, void *user)
{
  nepim_pipe_t *pipe = user;
  nepim_session_t *session = &pipe->session;

  assert(timercmp(&tv, &session->tv_duration, ==));

  nepim_pipe_stat(stdout, tv,
		  NEPIM_LABEL_TOTAL, pipe->sd, 
                  session->byte_total_recv,
                  session->byte_total_sent,
                  session->test_duration,
                  session->tv_start.tv_sec,
                  session->test_duration,
                  session->total_reads,
                  session->total_writes,
		  &session->min,
		  &session->max,
		  1 /* report_min_max = true */);

  session->byte_total_recv = 0;
  session->byte_total_sent = 0;
  session->total_reads     = 0;
  session->total_writes    = 0;
  session->duration_done   = 1;

  tcp_pipe_cancel_timers(pipe->sd);

  return OOP_CONTINUE;
}

static void *on_tcp_interval(oop_source *src, struct timeval tv, void *user)
{
  nepim_pipe_t *pipe = user;
  nepim_session_t *session = &pipe->session;

  assert(timercmp(&tv, &session->tv_interval, ==));

  nepim_pipe_stat(stdout, tv,
		  NEPIM_LABEL_PARTIAL, pipe->sd, 
                  session->byte_interval_recv,
                  session->byte_interval_sent,
                  session->stat_interval,
                  session->tv_start.tv_sec,
                  session->test_duration,
                  session->interval_reads,
                  session->interval_writes,
		  &session->min,
		  &session->max,
		  session->report_partial_min_max);

  session->byte_interval_recv = 0;
  session->byte_interval_sent = 0;
  session->interval_reads     = 0;
  session->interval_writes    = 0;

  schedule_stat_interval(pipe->sd);

  return OOP_CONTINUE;
}

static int parse_greetings(int sd,
			   int sockaddr_family,
                           const struct sockaddr *remote,
                           socklen_t remote_len,
                           const char *buf, const char *past_end)
{
  nepim_greet_t opt;
  int result;
  char password_buf[100];
  int nodelay;

  opt.password_buf = password_buf;
  opt.password_buf_size = sizeof(password_buf);

  result = nepim_parse_greetings(&opt, 1 /* is_tcp=true */, buf, past_end);
  if (result)
    return result;

  fprintf(stderr, 
          "%d: send=%d bit_rate=%lld pkt_rate=%d "
          "interval=%d duration=%d delay=%ld ka_send=%d ka_req=%d ka_tmout=%d ka_delay=%d "
          "seed=0x%08x verify_data=%d random_fill=%d fill_byte=0x%02x pause_duration=%d "
          "sock_ka=%d nagle=%d overhead=%d "
	  "sweep_random=%d sweep_step=%d write_floor=%d write_ceil=%d "
	  "p_minmax=%d mss=%d "
	  "password=%s\n", 
          sd, opt.must_send, opt.bit_rate, opt.pkt_rate,
          opt.stat_interval, opt.test_duration, 
          opt.write_delay, opt.keepalive_must_send,
          opt.keepalive_require, opt.keepalive_timeout, opt.keepalive_send_delay,
          opt.seed,
          opt.verify_data, opt.random_fill, opt.fill_byte, opt.pause_duration,
	  opt.socket_keepalive, opt.nagle, opt.overhead,
	  opt.sweep_random, opt.sweep_step, opt.write_floor, opt.write_ceil,
	  opt.report_partial_min_max, opt.mss,
          password_buf);

  nepim_conf_write_sweep_auto(0 /* udp=false */,
			      &opt.write_floor,
			      &opt.write_ceil);

  nepim_conf_write_sweep_fit(0 /* udp=false */,
			     &opt.write_floor,
			     &opt.write_ceil);

  fprintf(stderr, 
          "%d: sweep write: floor=%d ceil=%d\n",
	  sd,
	  opt.write_floor, opt.write_ceil);

  if (nepim_global.password)
    if (strcmp(nepim_global.password, password_buf)) {
      fprintf(stderr, "%d: bad client password=%s\n",
              sd, password_buf);
      return 1;
    }

  if (nepim_socket_keepalive(nepim_global.verbose_stderr, sd, opt.socket_keepalive))
    return 1;

  nodelay = (opt.nagle == -1) ? -1 : !opt.nagle;

  result = nepim_socket_tcp_opt(nepim_global.verbose_stderr,
				sockaddr_family, sd, nodelay,
				opt.mss);
  if (result) {
    fprintf(stderr, 
            "%d: %s: %s: could not set tcp options: %d\n",
            sd, __FILE__, __PRETTY_FUNCTION__, result);
    return 1;
  }

  nepim_pipe_set_add(&pipes, sd, remote, remote_len, &opt);

  return 0;
}

static int read_greetings(int sd,
			  int sockaddr_family,
                          const struct sockaddr *remote,
                          socklen_t remote_len)
{
  char buf[1024];
  int len = 0;
  char *eos;
  int result;

  for (;;) {
    char *curr = buf + len;
    int rd;

    /* Beware to not eat part of the next packet. */
    rd = read(sd, curr, 1);
    if (!rd) {
      fprintf(stderr, 
              "%s: incoming connection lost\n", 
              __PRETTY_FUNCTION__);
      return -1;
    }
    if (rd < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN)
        continue;
    }

    assert(rd > 0);

    len += rd;

    eos = memchr(curr, '\n', rd);
    if (eos)
      break;
  }

  *eos = '\0';

  result = parse_greetings(sd, sockaddr_family,
			   remote, remote_len, buf, eos);
  if (result) {
    fprintf(stderr, 
            "%d: bad client greetings: %d [%s]\n", 
            sd, result, buf);
    return result;
  }

  return 0;
}

static void schedule_stat_interval(int sd)
{
  nepim_pipe_t *pipe = nepim_pipe_set_get(&pipes, sd);
  nepim_session_t *session;
  assert(pipe);

  session = &pipe->session;

  {
    int result = gettimeofday(&session->tv_interval, 0);
    assert(!result);
  }

  session->tv_interval.tv_sec += session->stat_interval;

  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                session->tv_interval,
                                on_tcp_interval, pipe);
}

static void *on_tcp_keepalive_write(oop_source *src, int sd,
				    oop_event event, void *user)
{
  char buf[1];
  int wr;

  nepim_pipe_t *pipe = user;
  nepim_session_t *session;

  assert(event == OOP_WRITE);
  assert(pipe);
  assert(sd == pipe->sd);

  session = &pipe->session;

  assert(!session->must_send);
  assert(session->keepalive_must_send);

#if 0
  fprintf(stderr, 
	  "DEBUG %s %s: %d: sending keepalive\n",
	  __FILE__, __PRETTY_FUNCTION__,
	  sd);
#endif

  /* stop writing -- re-scheduled below */
  nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                  sd, OOP_WRITE);

  wr = write(sd, buf, sizeof(buf));
  if (wr != sizeof(buf)) {
    switch (errno) {
    case EINTR:
      fprintf(stderr, "keepalive write: EINTR on TCP socket %d\n", sd);
      return OOP_CONTINUE;
    case EAGAIN:
      fprintf(stderr, "keepalive write: EAGAIN on TCP socket %d\n", sd);
      return OOP_CONTINUE;
    case EPIPE:
      fprintf(stderr, "keepalive write: EPIPE on TCP socket %d\n", sd);
      break;
    default:
      fprintf(stderr, "keepalive write: errno=%d: %s\n",
	      errno, strerror(errno));
    }
    
    fprintf(stderr, 
	    "keepalive write: connection lost on TCP socket %d\n", 
	    sd);
    
    if (!session->duration_done)
      report_broken_pipe_stat(stdout, pipe);
    
    tcp_pipe_kill(sd);
    
    return OOP_CONTINUE;
  }

  assert(wr == sizeof(buf));

  nepim_session_write_add(session, wr + session->overhead);

  /* schedule next keepalive time */
  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                session->tv_keepalive_send_next,
                                on_tcp_keepalive_time, pipe);

  return OOP_CONTINUE;
}

static void *on_tcp_keepalive_time(oop_source *src, struct timeval tv, void *user)
{
  nepim_pipe_t *pipe = user;
  nepim_session_t *session;

  assert(pipe);

  session = &pipe->session;

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
  nepim_global.oop_src->on_fd(nepim_global.oop_src, pipe->sd, OOP_WRITE,
			      on_tcp_keepalive_write, pipe);

  return OOP_CONTINUE;
}

static void *on_tcp_keepalive_require(oop_source *src, struct timeval tv, void *user)
{
  nepim_pipe_t *pipe = user;
  nepim_session_t *session = &pipe->session;

  assert(session->keepalive_require);
  assert(session->keepalives_recv >= 0);

#if 0
  fprintf(stderr, 
	  "DEBUG %s %s: %d: keepalives_recv=%d\n",
	  __FILE__, __PRETTY_FUNCTION__,
	  pipe->sd, session->keepalives_recv);
#endif

  if (session->keepalives_recv < 1) {
    int sd = pipe->sd;

    fprintf(stderr, 
            "%d: %s\n",
            sd, NEPIM_MSG_KEEPALIVES_MISS);

    if (!session->duration_done)
      report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_kill(sd);

    return OOP_CONTINUE;
  }

  session->keepalives_recv = 0;

  nepim_pipe_schedule_keepalive_timer(pipe, on_tcp_keepalive_require);

  return OOP_CONTINUE;
}

static void tcp_pipe_start(int sd)
{
  nepim_pipe_t *pipe = nepim_pipe_set_get(&pipes, sd);
  nepim_session_t *session;
  assert(pipe);

  session = &pipe->session;

  nepim_global.oop_src->on_fd(nepim_global.oop_src,
                              sd, OOP_READ,
                              on_tcp_read, pipe);

  if (session->must_send) {
    if ((session->max_bit_rate > 0) || (session->max_pkt_rate > 0)) {
      session->tv_send_rate = OOP_TIME_NOW;
      nepim_global.oop_src->on_time(nepim_global.oop_src,
                                    session->tv_send_rate,
                                    on_tcp_rate_delay, pipe);
    }
    else {
      nepim_global.oop_src->on_fd(nepim_global.oop_src,
                                  sd, OOP_WRITE,
                                  on_tcp_write, pipe);
    }
  }
  else {
    if (session->keepalive_must_send) {

#if 0
      fprintf(stderr, 
              "DEBUG %s %s: %d: %s\n",
              __FILE__, __PRETTY_FUNCTION__,
              sd, NEPIM_MSG_KEEPALIVES_SCHED);
#endif
      
      session->tv_keepalive_send_next = OOP_TIME_NOW;
      nepim_global.oop_src->on_time(nepim_global.oop_src,
                                    session->tv_keepalive_send_next,
                                    on_tcp_keepalive_time, pipe);
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
                                on_tcp_duration, pipe);

  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, sd);

  schedule_stat_interval(sd);

  if (session->keepalive_require)
    nepim_pipe_schedule_keepalive_timer(pipe, on_tcp_keepalive_require);
}

static void *on_tcp_pipe_start(oop_source *src, struct timeval tv, void *user)
{
  nepim_pipe_t *pipe = user;

  tcp_pipe_start(pipe->sd);
  return OOP_CONTINUE;
}

static void schedule_tcp_pipe_start(int sd)
{
    nepim_pipe_t *pipe = nepim_pipe_set_get(&pipes, sd);
    nepim_session_t *session;
    struct timeval pause;

    session = &pipe->session;

    {
        int result = gettimeofday(&pause, 0);
        assert(!result);
    }
    pause.tv_sec += session->pause_duration;
    nepim_global.oop_src->on_time(nepim_global.oop_src,
                                  pause,
                                  on_tcp_pipe_start, pipe);
}

static void tcp_pipe_cancel_timers(int sd)
{
  nepim_pipe_t *pipe = nepim_pipe_set_get(&pipes, sd);
  nepim_session_t *session;
  assert(pipe);

  session = &pipe->session;

  nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                    session->tv_duration,
                                    on_tcp_duration, pipe);

  nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                    session->tv_interval,
                                    on_tcp_interval, pipe);

  /* disable keepalive timer */
  if (pipe->session.keepalive_require)
    nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                      pipe->session.tv_keepalive_recv_timer,
                                      on_tcp_keepalive_require, pipe);
}

static void tcp_pipe_cancel_io(int sd)
{
  nepim_pipe_t *pipe = nepim_pipe_set_get(&pipes, sd);
  nepim_session_t *session;
  assert(pipe);

  session = &pipe->session;

  nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                  sd, OOP_READ);

  if (session->must_send) {
    if ((session->max_bit_rate > 0) || (session->max_pkt_rate > 0)) {
      /* stop current writing, if any */
      nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                      sd, OOP_WRITE);
      
      /* stop periodic write scheduler */
      nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                        session->tv_send_rate,
                                        on_tcp_rate_delay, pipe);
    }
    else {
      nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                      sd, OOP_WRITE);
    }
  }
  else {
    assert(!session->must_send);

    if (session->keepalive_must_send) {
      
      /* stop any will to write keepalives */
      nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
				      sd, OOP_WRITE);

      /* stop periodic keepalive scheduler */
      nepim_global.oop_src->cancel_time(nepim_global.oop_src,
                                        session->tv_keepalive_send_next,
                                        on_tcp_keepalive_time,
                                        pipe);
    }
  }

}

static void tcp_pipe_kill(int sd)
{
  nepim_pipe_t *pipe;

#if 0
  fprintf(stderr, 
	  "DEBUG %s %s: %d: closing sd\n",
	  __FILE__, __PRETTY_FUNCTION__,
	  sd);
#endif

  pipe = nepim_pipe_set_get(&pipes, sd);
  assert(pipe);

  tcp_pipe_cancel_timers(sd);
  tcp_pipe_cancel_io(sd);

  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, sd);

  if (close(sd))
    fprintf(stderr, "%d: close failed\n", sd);

  nepim_pipe_set_del(&pipes, sd);
}

static void *on_tcp_connect(oop_source *src, int sd,
                            oop_event event, void *unnused)
{
  int conn_sd;
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
    struct sockaddr_un un;
  } sa;
  socklen_t len = sizeof(sa);
  int result;
  int family;
  char addr_buf[500];

  conn_sd = accept(sd, (struct sockaddr *) &sa, &len);
  if (conn_sd < 0) {
    fprintf(stderr, 
            "%s: %s: could not accept connection: errno=%d: %s\n", 
            __FILE__, __PRETTY_FUNCTION__, errno, strerror(errno));
    return OOP_CONTINUE;
  }

  nepim_sock_dump_addr(addr_buf, sizeof(addr_buf),
                       (const struct sockaddr *) &sa,
		       len);

  family = nepim_sock_family((const struct sockaddr *) &sa);

  if (family == AF_UNIX)
    fprintf(stderr,
	    "%d: UNIX incoming: path=%s (sockaddr_len=%d path_len=%d)\n",
	    conn_sd, addr_buf, len, (int) strlen(addr_buf));
    else
      fprintf(stderr,
	      "%d: TCP incoming: %s,%d\n",
	      conn_sd, addr_buf, 
	      nepim_sock_get_port((const struct sockaddr *) &sa));

  if (nepim_global.tcpwrap) {
    if (!nepim_hosts_ctl(nepim_global.tcpwrap,
                         nepim_global.prog_name,
                         addr_buf)) {
      fprintf(stderr, 
              "%d: %s: %s: TCP wrapper denied access from client=[%s] to service=[%s]\n",
              conn_sd, __FILE__, __PRETTY_FUNCTION__,
              addr_buf, nepim_global.prog_name);
      close(conn_sd);
      return OOP_CONTINUE;
    }
  }

  result = nepim_socket_opt(nepim_global.verbose_stderr,
			    conn_sd, nepim_global.pmtu_mode, 
                            nepim_global.ttl, nepim_global.tos,
			    nepim_global.router_alert);
  if (result) {
    fprintf(stderr, 
            "%d: %s: %s: could not set socket options: %d\n",
            conn_sd, __FILE__, __PRETTY_FUNCTION__, result);
    close(conn_sd);
    return OOP_CONTINUE;
  }

  if (nepim_socket_block(conn_sd)) {
    fprintf(stderr, 
            "%d: %s: %s: could not set blocking socket mode\n",
            conn_sd, __FILE__, __PRETTY_FUNCTION__);
    close(conn_sd);
    return OOP_CONTINUE;
  }

  if (read_greetings(conn_sd, family,
		     (const struct sockaddr *) &sa, len)) {
    fprintf(stderr, 
            "%d: %s: %s: could not parse client greetings\n",
            conn_sd, __FILE__, __PRETTY_FUNCTION__);
    close(conn_sd);
    return OOP_CONTINUE;
  }

  if (nepim_socket_nonblock(conn_sd)) {
    fprintf(stderr, 
            "%d: %s: %s: could not set non-blocking socket mode\n",
            conn_sd, __FILE__, __PRETTY_FUNCTION__);
    close(conn_sd);
    return OOP_CONTINUE;
  }

  schedule_tcp_pipe_start(conn_sd);

  return OOP_CONTINUE;
}

static int spawn_tcp_listener(const char *hostname, const char *portname)
{
  struct addrinfo hints;
  struct addrinfo *ai_res;
  struct addrinfo *ai;
  int tcp_listeners = 0;
  int result;

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE | AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;
  hints.ai_addrlen = 0;
  hints.ai_addr = 0;
  hints.ai_canonname = 0;
  
  result = getaddrinfo(hostname, portname, &hints, &ai_res);
  if (result) {
    fprintf(stderr, "%s: getaddrinfo(%s,%s): %s\n",
	    __PRETTY_FUNCTION__,
	    hostname, portname, gai_strerror(result));
    return 0;
  }

  for (ai = ai_res; ai; ai = ai->ai_next) {
    char addr_str[500];
    int nodelay;
    int sd;

    if (nepim_global.no_inet6 && (ai->ai_family == PF_INET6))
      continue;

    if (nepim_global.no_inet4 && (ai->ai_family == PF_INET))
      continue;

    nodelay = (nepim_global.nagle == -1) ? -1 : !nepim_global.nagle;

    nepim_sock_dump_addr(addr_str, sizeof addr_str,
			 ai->ai_addr, ai->ai_addrlen);

    sd = nepim_create_listener_socket(nepim_global.verbose_stderr,
				      ai->ai_addr, ai->ai_addrlen,
                                      ai->ai_family, ai->ai_socktype, 
                                      ai->ai_protocol,
                                      nepim_global.listen_backlog,
                                      nepim_global.pmtu_mode,
                                      nepim_global.ttl,
                                      nepim_global.win_recv,
                                      nepim_global.win_send,
				      nodelay,
				      nepim_global.tos,
				      nepim_global.server_tcp_mss,
				      nepim_global.router_alert,
				      0,  /* join_iface */
				      0,  /* ssm_src_addr */
				      -1  /* ssm_src_addrlen */);
    if (sd < 0) {
      fprintf(stderr, 
              "%s %s: TCP listener socket failed for %s,%d: %d\n",
              __FILE__, __PRETTY_FUNCTION__,
	      addr_str, nepim_sock_get_port(ai->ai_addr), sd);
      break;
    }

    nepim_global.oop_src->on_fd(nepim_global.oop_src,
                                sd, OOP_READ,
                                on_tcp_connect, 0);

    ++tcp_listeners;

    fprintf(stderr, 
	    "%d: TCP socket listening on %s,%d\n",
	    sd, addr_str, nepim_sock_get_port(ai->ai_addr));
  }

  freeaddrinfo(ai_res);

  return tcp_listeners;
}

static int spawn_unix_listener(const char *path)
{
  struct sockaddr_un un_sock_addr;
  int nodelay;
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
  
  nodelay = (nepim_global.nagle == -1) ? -1 : !nepim_global.nagle;

  sd = nepim_create_listener_socket(nepim_global.verbose_stderr,
				    (struct sockaddr *) &un_sock_addr, 
				    sizeof(un_sock_addr),
				    AF_UNIX,
				    SOCK_STREAM, 
				    0,
				    nepim_global.listen_backlog,
				    nepim_global.pmtu_mode,
				    nepim_global.ttl,
				    nepim_global.win_recv,
				    nepim_global.win_send,
				    nodelay,
				    nepim_global.tos,
				    nepim_global.server_tcp_mss,
				    nepim_global.router_alert,
				    0, /* iface_index */
				    0,  /* ssm_src_addr */
				    -1  /* ssm_src_addrlen */);
  if (sd < 0) {
    fprintf(stderr, 
	    "%s %s: UNIX stream listener socket failed for path=%s\n",
	    __FILE__, __PRETTY_FUNCTION__, path); 
    return 0;
  }

  nepim_global.oop_src->on_fd(nepim_global.oop_src,
			      sd, OOP_READ,
			      on_tcp_connect, 0);

  fprintf(stderr, 
	  "%d: UNIX stream socket listening on path=%s\n",
	  sd, path);

  return 1;
}


extern int nepim_udp_listener(const char *ssm_source,
			      const char *hostname,
                              const char *portname,
			      int join,
			      const char *join_iface);

static void parse_listeners(const char *list, int *udp, int *tcp, int join)
{
  int i;

  int size = addr_list_size(list);

  for (i = 0; i < size; ++i) {
    char buf[100];
    char *portname;

    if (addr_list_get(list, i, buf, sizeof(buf))) {
      fprintf(stderr, 
              "%s: failure parsing address %d/%d from list: %s\n",
              nepim_global.prog_name, i, size, list);
      continue;
    }

    if (addr_split_port(buf, sizeof(buf), &portname))
      portname = (char *) nepim_global.portname;

    /*
      buf:      host
      portname: port
     */

    if (join) {
      char *group;
      char *ssm_source;
      char *iface;

      if (addr_split_sourcegroup(buf, sizeof(buf), &group)) {
	ssm_source = 0;
	group = buf;
      }
      else {
	ssm_source = buf;
      }

      /* split group into group@iface */
      if (addr_split_iface(group, buf + sizeof(buf) - group, &iface)) {
	iface = 0;
      }

      *tcp += spawn_tcp_listener(group, portname);
      *udp += nepim_udp_listener(ssm_source, group, portname, 1 /* join */, iface);

      continue; /* for */
    }

    *tcp += spawn_tcp_listener(buf, portname);
    *udp += nepim_udp_listener(0, buf, portname, 0 /* join */, 0 /* iface */);

  } /* for */
}
 
static int parse_unix_listeners(const char *list)
{
  int listeners = 0;
  int i;

  int size = addr_list_size(list);

  for (i = 0; i < size; ++i) {
    char buf[500];

    if (addr_list_get(list, i, buf, sizeof(buf))) {
      fprintf(stderr, 
              "%s: failure parsing address %d/%d from list: %s\n",
              nepim_global.prog_name, i, size, list);
      continue;
    }

    listeners += spawn_unix_listener(buf);
  }

  return listeners;
}

extern int nepim_unix_dgram_listener(const char *path);

static int parse_unix_dgram_listeners(const char *list)
{
  int listeners = 0;
  int i;

  int size = addr_list_size(list);

  for (i = 0; i < size; ++i) {
    char buf[500];

    if (addr_list_get(list, i, buf, sizeof(buf))) {
      fprintf(stderr, 
              "%s: failure parsing address %d/%d from list: %s\n",
              nepim_global.prog_name, i, size, list);
      continue;
    }

    listeners += nepim_unix_dgram_listener(buf);
  }

  return listeners;
}

static void break_all()
{
  struct timeval now;
  int result;
  int i;
      
  result = gettimeofday(&now, 0);
  assert(!result);

  for (i = 0; i < pipes.array.capacity; ++i) {
    nepim_pipe_t *pipe = pipes.array.head[i];
    if (pipe) {
      if (!pipe->session.duration_done)
	report_broken_pipe_stat_at(stdout, pipe, now);

      tcp_pipe_kill(pipe->sd);
    }
  }

  for (i = 0; i < slots.array.capacity; ++i) {
    nepim_slot_t *slot = slots.array.head[i];
    if (slot) {
      if (!slot->session.duration_done)
	report_broken_slot_stat_at(stdout, slot, now);

      nepim_slot_kill(slot);
    }
  }
}

static void *on_sigint(oop_source *src, int sig, void *user)
{
  assert(sig == SIGINT);
  assert(!user);

  fprintf(stderr, "%s %s: interrupted by user\n",
	  __FILE__, __PRETTY_FUNCTION__);

  break_all();

  return OOP_HALT;
}

static void *on_sigterm(oop_source *src, int sig, void *user)
{
  assert(sig == SIGTERM);
  assert(!user);

  fprintf(stderr, "%s %s: interrupted by user\n",
	  __FILE__, __PRETTY_FUNCTION__);

  break_all();

  return OOP_HALT;
}

void nepim_server_run()
{
  int tcp_listeners = 0;
  int udp_listeners = 0;
  int unix_listeners = 0;
  int unix_dgram_listeners = 0;

  /* these must be initialized before spawning listeners */
  nepim_pipe_set_init(&pipes);
  nepim_slot_set_init(&slots);
  nepim_usock_set_init(&udp_tab);

  if (nepim_global.bind_list)
    parse_listeners(nepim_global.bind_list, &udp_listeners, &tcp_listeners,
                    0 /* no join */);

  if (nepim_global.join_list)
    parse_listeners(nepim_global.join_list, &udp_listeners, &tcp_listeners,
                    1 /* do join */);

  if (nepim_global.unix_list)
    unix_listeners = parse_unix_listeners(nepim_global.unix_list);

  if (nepim_global.unix_dgram_list)
    unix_dgram_listeners = parse_unix_dgram_listeners(nepim_global.unix_dgram_list);

  /*
    Listen on default wildcard addresses?
  */
  if (!nepim_global.bind_list &&
      !nepim_global.join_list &&
      !nepim_global.unix_list &&
      !nepim_global.unix_dgram_list) {
    if (!nepim_global.no_inet6)
      tcp_listeners += spawn_tcp_listener(INET6_ANY, nepim_global.portname);
    tcp_listeners += spawn_tcp_listener(INET_ANY, nepim_global.portname);
    if (!nepim_global.no_inet6)
      udp_listeners += nepim_udp_listener(0 /* ssm_source */,
					  INET6_ANY, nepim_global.portname,
                                          0 /* no join */,
					  0 /* join_iface */);
    udp_listeners += nepim_udp_listener(0 /* ssm_source */,
					INET_ANY, nepim_global.portname,
                                        0 /* no join */,
					0 /* join_iface */);
  }

#if 0
  fprintf(stderr, "DEBUG ERASEME: %s %s tcp=%d udp=%d stream=%d dgram=%d\n",
	  __FILE__, __PRETTY_FUNCTION__,
	  tcp_listeners, udp_listeners,
	  unix_listeners, unix_dgram_listeners);
#endif
  
  if (tcp_listeners ||
      udp_listeners ||
      unix_listeners ||
      unix_dgram_listeners) {
    nepim_global.oop_src->on_signal(nepim_global.oop_src,
				    SIGINT, on_sigint, 0);
    nepim_global.oop_src->on_signal(nepim_global.oop_src,
				    SIGTERM, on_sigterm, 0);

    fprintf(stderr, "%s: server ready\n", nepim_global.prog_name);
  }

  for (;;) {
    void *result = oop_sys_run(nepim_global.oop_sys);
    if (result == OOP_ERROR) {
      fprintf(stderr, "%s: event system source error\n",
	      nepim_global.prog_name);
      continue;
    }
    if (result == OOP_CONTINUE) {
      fprintf(stderr, "%s: no event sink registered\n",
	      nepim_global.prog_name);
      break;
    }
    if (result == OOP_HALT) {
      fprintf(stderr, "%s: some event sink requested termination\n",
	      nepim_global.prog_name);
      break;
    }
    assert(0);
  }

  nepim_global.oop_src->cancel_signal(nepim_global.oop_src,
				      SIGINT, on_sigint, 0);
  nepim_global.oop_src->cancel_signal(nepim_global.oop_src,
				      SIGTERM, on_sigterm, 0);
}


