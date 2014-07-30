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

/* $Id: client.c,v 1.73 2008/08/22 02:01:19 evertonm Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <signal.h>
#include <assert.h>

#include "conf.h"
#include "sock.h"
#include "pipe.h"
#include "common.h"
#include "usock.h"
#include "str.h"

extern nepim_pipe_set_t pipes;    /* from server.c */
extern nepim_slot_set_t slots;    /* from server.c */
extern nepim_usock_set_t udp_tab; /* from server.c */

static void tcp_pipe_stop(int sd);
static void *on_tcp_interval(oop_source *src, struct timeval tv, void *user);
static void *on_tcp_rate_delay(oop_source *src, struct timeval tv, void *user);
static void *on_tcp_keepalive_time(oop_source *src, struct timeval tv, void *user);

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

static void *on_tcp_read(oop_source *src, int sd,
                         oop_event event, void *user)
{
  char buf[nepim_global.tcp_read_size];
  int rd;
  nepim_pipe_t *pipe = user;
  nepim_session_t *session;

  assert(event == OOP_READ);
  assert(sd == pipe->sd);

  assert(sizeof(buf) == nepim_global.tcp_read_size);

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

    report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_stop(sd);
    close(sd);

    return OOP_CONTINUE;
  }

  assert(rd >= 0);
  assert(rd <= sizeof(buf));

  session = &pipe->session;

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

    report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_stop(sd);
    close(sd);

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

    report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_stop(sd);
    close(sd);

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

  tcp_pipe_stop(pipe->sd);
  close(pipe->sd);

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

static int greet(int sd)
{
  char buf[1024];
  nepim_greet_t opt;
  int pr;
  int wr;
  char *tmp = "";

  opt.must_send               = nepim_global.duplex_mode ||
    !nepim_global.simplex_client_send;
  opt.bit_rate                = nepim_global.bit_rate;
  opt.pkt_rate                = nepim_global.pkt_rate;
  opt.stat_interval           = nepim_global.stat_interval;
  opt.test_duration           = nepim_global.test_duration;
  opt.write_delay             = nepim_global.write_delay;
  opt.keepalive_must_send     = nepim_global.tcp_keepalive_require;
  opt.keepalive_require       = nepim_global.tcp_keepalive_must_send;
  opt.keepalive_timeout       = nepim_global.tcp_keepalive_recv_timer;
  opt.keepalive_send_delay    = nepim_global.tcp_keepalive_send_delay;
  opt.seed                    = nepim_global.seed;
  opt.verify_data             = nepim_global.verify_data;
  opt.random_fill             = nepim_global.random_fill;
  opt.fill_byte               = nepim_global.fill_byte;
  opt.pause_duration          = nepim_global.pause_duration;
  opt.socket_keepalive        = nepim_global.socket_keepalive;
  opt.nagle                   = nepim_global.nagle;
  opt.overhead                = nepim_global.tcp_overhead;
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

  pr = nepim_write_greetings(&opt, buf, sizeof(buf));
  if (pr < 0)
    return -1;
  assert(pr > 0);

  fprintf(stderr, "%d: sending: %s", sd, buf);

  wr = write(sd, buf, pr);
  if (wr != pr)
    return -1;

  return 0;
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
    
    report_broken_pipe_stat(stdout, pipe);
    
    tcp_pipe_stop(sd);
    close(sd);
    
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
            "%d: breaking pipe: %s\n",
            sd, NEPIM_MSG_KEEPALIVES_MISS);

    report_broken_pipe_stat(stdout, pipe);

    tcp_pipe_stop(sd);
    close(sd);

    return OOP_CONTINUE;
  }

  session->keepalives_recv = 0;

  nepim_pipe_schedule_keepalive_timer(pipe, on_tcp_keepalive_require);

  return OOP_CONTINUE;
}

static void *on_sigint(oop_source *src, int sig, void *user)
{
  nepim_pipe_t *pipe = user;

  assert(sig == SIGINT);
  assert(pipe);

  fprintf(stderr, "%d: %s %s: interrupted by user\n",
	  pipe->sd, __FILE__, __PRETTY_FUNCTION__);

  report_broken_pipe_stat(stdout, pipe);

  tcp_pipe_stop(pipe->sd);
  close(pipe->sd);

  return OOP_CONTINUE;
}

static void *on_sigterm(oop_source *src, int sig, void *user)
{
  nepim_pipe_t *pipe = user;

  assert(sig == SIGTERM);
  assert(pipe);

  fprintf(stderr, "%d: %s %s: interrupted by user\n",
	  pipe->sd, __FILE__, __PRETTY_FUNCTION__);

  report_broken_pipe_stat(stdout, pipe);

  tcp_pipe_stop(pipe->sd);
  close(pipe->sd);

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

  nepim_global.oop_src->on_signal(nepim_global.oop_src,
				  SIGINT, on_sigint, pipe);
  nepim_global.oop_src->on_signal(nepim_global.oop_src,
				  SIGTERM, on_sigterm, pipe);
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

static void tcp_pipe_stop(int sd)
{
  nepim_pipe_t *pipe = nepim_pipe_set_get(&pipes, sd);
  nepim_session_t *session;
  assert(pipe);

  nepim_global.oop_src->cancel_signal(nepim_global.oop_src,
				      SIGINT, on_sigint, pipe);
  nepim_global.oop_src->cancel_signal(nepim_global.oop_src,
				      SIGTERM, on_sigterm, pipe);

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

  nepim_pipe_set_del(&pipes, sd);

  nepim_sock_show_opt(nepim_global.verbose_stderr, stderr, sd);
}

static void spawn_one_tcp_client(const char *hostport,
				 const struct sockaddr *bindaddr,
				 int bindaddr_len,
				 const char *hostname,
				 const char *portname)
{
  struct addrinfo hints;
  struct addrinfo *ai_res;
  struct addrinfo *ai;
  struct sockaddr_un un_sock_addr;
  struct stat stat_buf;
  int gai_lookup; /* boolean */
  int result;

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

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = PF_UNSPEC;
    hints.ai_addrlen = 0;
    hints.ai_addr = 0;
    hints.ai_canonname = 0;

    fprintf(stderr, 
	    "TCP socket solving %s,%s\n",
	    hostname, portname);

    result = getaddrinfo(hostname, portname,
			 &hints, &ai_res);
    if (result) {
      fprintf(stderr, "%s: getaddrinfo(%s,%s): %s\n",
	      __PRETTY_FUNCTION__, hostname, portname,
	      gai_strerror(result));
      return;
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
      return;
    }

    memset(&un_sock_addr, 0, sizeof(un_sock_addr));

    un_sock_addr.sun_family = AF_UNIX;
    strcpy(un_sock_addr.sun_path, hostport);

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_family = AF_UNIX;
    hints.ai_addrlen = sizeof(un_sock_addr);
    hints.ai_addr = (struct sockaddr *) &un_sock_addr;
    hints.ai_canonname = 0;

    ai_res = &hints;
  }

  for (ai = ai_res; ai; ai = ai->ai_next) {
    char addr_str[500];
    int nodelay;
    int sd;

    nepim_sock_dump_addr(addr_str, sizeof addr_str,
			 ai->ai_addr, ai->ai_addrlen);

    if (ai->ai_family == PF_UNIX)
      fprintf(stderr, 
	      "UNIX stream socket trying path=%s\n",
	      hostport);
    else
      fprintf(stderr, 
	      "TCP socket trying %s,%d\n",
	      addr_str, nepim_sock_get_port(ai->ai_addr));

    if (nepim_global.no_inet6 && (ai->ai_family == PF_INET6))
      continue;

    if (nepim_global.no_inet4 && (ai->ai_family == PF_INET))
      continue;

    nodelay = (nepim_global.nagle == -1) ? -1 : !nepim_global.nagle;

    sd = nepim_connect_client_socket(nepim_global.verbose_stderr,
				     bindaddr, bindaddr_len,
				     ai->ai_addr, ai->ai_addrlen,
                                     ai->ai_family, ai->ai_socktype, 
                                     ai->ai_protocol,
                                     nepim_global.pmtu_mode,
                                     nepim_global.ttl,
                                     nepim_global.win_recv,
                                     nepim_global.win_send,
				     nodelay,
				     nepim_global.tos,
				     nepim_global.socket_keepalive,
				     nepim_global.client_tcp_mss,
				     nepim_global.router_alert,
				     0 /* join iface */);
    if (sd < 0) {
      if (ai->ai_family == AF_UNIX)
	fprintf(stderr, 
		"could not connect UNIX stream socket to path=%s: %d\n",
		hostport, sd);
      else
	fprintf(stderr, 
		"could not connect TCP socket to %s,%d: %d\n",
		addr_str, nepim_sock_get_port(ai->ai_addr), sd);

      continue;
    }

    if (ai->ai_family == AF_UNIX)
      fprintf(stderr, 
	      "%d: UNIX stream socket connected to path=%s\n",
	      sd, hostport); 
    else
      fprintf(stderr, 
	      "%d: TCP socket connected to %s,%d\n",
	      sd, addr_str, nepim_sock_get_port(ai->ai_addr));
    
    {
      nepim_greet_t opt;

      opt.must_send               = nepim_global.duplex_mode ||
        nepim_global.simplex_client_send;
      opt.bit_rate                = nepim_global.bit_rate;
      opt.pkt_rate                = nepim_global.pkt_rate;
      opt.stat_interval           = nepim_global.stat_interval;
      opt.test_duration           = nepim_global.test_duration;
      opt.write_delay             = nepim_global.write_delay;
      opt.keepalive_must_send     = nepim_global.tcp_keepalive_require;
      opt.keepalive_require       = nepim_global.tcp_keepalive_must_send;
      opt.keepalive_timeout       = nepim_global.tcp_keepalive_recv_timer;
      opt.keepalive_send_delay    = nepim_global.tcp_keepalive_send_delay;
      opt.seed                    = nepim_global.seed;
      opt.verify_data             = nepim_global.verify_data;
      opt.random_fill             = nepim_global.random_fill;
      opt.fill_byte               = nepim_global.fill_byte;
      opt.pause_duration          = nepim_global.pause_duration;
      opt.overhead                = nepim_global.tcp_overhead;
      opt.sweep_random            = nepim_global.sweep_random;
      opt.sweep_step              = nepim_global.sweep_step;
      opt.write_floor             = nepim_global.write_floor;
      opt.write_ceil              = nepim_global.write_ceil;
      opt.report_partial_min_max  = nepim_global.report_partial_min_max;

      nepim_pipe_set_add(&pipes, sd, ai->ai_addr, ai->ai_addrlen, &opt);
    }

    break;
  }

  if (gai_lookup)
    freeaddrinfo(ai_res);
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
    bind_addr = nepim_addrlist_findfirst(SOCK_STREAM, IPPROTO_TCP,
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
    for (i = 0; i < nepim_global.pipes; ++i)
      spawn_one_tcp_client(hostport,
			   bind_addr, bind_addr_len,
			   hostname, portname);

  } /* scan host_list */
}

static void spawn_tcp_clients(const char *host_list)
{
  int i;

  /* spawn sockets */
  parse_hosts(host_list);

  /* activate sockets */
  for (i = 0; i < pipes.array.capacity; ++i) {
    char peer[500];
    nepim_pipe_t *pipe = nepim_pipe_set_get(&pipes, i);
    if (!pipe)
      continue;

    nepim_sock_dump_addr(peer, sizeof(peer),
                         (const struct sockaddr *) &pipe->session.remote,
			 pipe->session.remote_len);

    if (greet(i)) {
      fprintf(stderr,
              "%d: could not greet %s,%d\n",
              i, peer, 
              nepim_sock_get_port((const struct sockaddr *) &pipe->session.remote));
      
      nepim_pipe_set_del(&pipes, i);
      close(i);
      
      continue;
    }

    fprintf(stderr, 
            "%d: greetings sent to %s,%d\n",
            i, peer, 
            nepim_sock_get_port((const struct sockaddr *) &pipe->session.remote));

    schedule_tcp_pipe_start(i);
  }

}

void nepim_udp_clients(const char *host_list);

void nepim_client_run()
{
  nepim_pipe_set_init(&pipes);

  if (nepim_global.udp_mode) {
    nepim_slot_set_init(&slots);
    nepim_usock_set_init(&udp_tab);

    nepim_udp_clients(nepim_global.hostname);
  }
  else
    spawn_tcp_clients(nepim_global.hostname);

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
}
