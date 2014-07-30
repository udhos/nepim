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

/* $Id: slot.c,v 1.52 2008/07/13 02:46:42 evertonm Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "slot.h"
#include "conf.h"
#include "usock.h"
#include "udp_header.h"
#include "common.h"
#include "sock.h"
#include "rand.h"

extern nepim_usock_set_t udp_tab; /* from server.c */

void nepim_slot_set_init(nepim_slot_set_t *set)
{
  nepim_array_init(&set->array);
}

nepim_slot_t *nepim_slot_set_get(const nepim_slot_set_t *set, int index)
{
  return nepim_array_get(&set->array, index);
}

nepim_slot_t *nepim_slot_set_search(const nepim_slot_set_t *set, int index)
{
  return nepim_array_search(&set->array, index);
}

struct ctx_t {
  const struct sockaddr *sa;
  socklen_t len;
};

static int match_remote_addr(const void *context, const void *element)
{
  const struct ctx_t *ctx = context;
  const nepim_slot_t *slot = element;

  assert(ctx);

  if (slot)
    return !memcmp(&slot->session.remote, ctx->sa, ctx->len);

  return 0;
}

nepim_slot_t *nepim_slot_set_search_remote(const nepim_slot_set_t *set,
                                           const struct sockaddr *addr,
                                           socklen_t len)
{
  struct ctx_t ctx = { addr, len };
  return nepim_array_find(&set->array, match_remote_addr, &ctx);
}

int nepim_slot_find_free(nepim_slot_set_t *set)
{
  return nepim_array_find_free(&set->array);
}

void nepim_slot_set_add(nepim_slot_set_t *set, int sd,
                        int index, int index_remote,
                        const struct sockaddr *remote,
                        socklen_t remote_len,
                        const nepim_greet_t *opt)
{
  nepim_slot_t *slot = malloc(sizeof(*slot));
  assert(slot);
  
  slot->index                     = index;
  slot->index_remote              = index_remote;
  slot->udp_sd                    = sd;
  slot->seq                       = 0;
  slot->seq_highest_recv          = 0;
  slot->want_write                = 0; /* boolean */
  slot->greetings_sent            = 0;
  slot->client_writer_status      = NEPIM_SLOT_CLIENT_GREET;

  slot->interval_last_highest_seq = 0;
  slot->interval_pkt_recv         = 0;
  slot->interval_pkt_lost         = 0;
  slot->interval_pkt_ooo          = 0;
  slot->subtotal_pkt_lost         = 0;
  slot->total_pkt_lost            = 0;
  slot->total_pkt_recv            = 0;
  slot->total_pkt_ooo             = 0;
  
  nepim_session_init(&slot->session, opt, 
                     remote, remote_len,
                     SESSION_SLOT, index);

  nepim_array_add(&set->array, index, slot);
}

void nepim_slot_set_del(nepim_slot_set_t *set, int index)
{
  nepim_slot_t *slot = nepim_slot_set_get(set, index);
  assert(slot);
  free(slot);
  nepim_array_del(&set->array, index);
}

/*
  find next round-robin slot wanting
  to write on a shared file descriptor
 */
static int write_cursor = 0;

static int slot_writer(nepim_slot_t *slot, int sd)
{
  if (slot)
    if (slot->udp_sd == sd)
      if (slot->want_write) {
        assert(slot->want_write == 1);
        return -1;
      }
  
  return 0;
}

nepim_slot_t *nepim_slot_find_next_writer(const nepim_slot_set_t *set, int sd)
{
  nepim_slot_t *slot;
  int last = write_cursor; 

  write_cursor = (write_cursor + 1) % set->array.capacity;

  slot = nepim_slot_set_get(set, last);
  if (slot_writer(slot, sd))
    return slot;

  for (; write_cursor != last; write_cursor = (write_cursor + 1) % set->array.capacity) {
    slot = nepim_slot_set_get(set, write_cursor);
    if (slot_writer(slot, sd))
      return slot;
  }

  assert(0);

  return 0;
}

int nepim_slot_find_addr(const nepim_slot_set_t *set,
                         int remote_slot, 
                         const struct sockaddr *remote,
                         socklen_t remote_len)
{
  nepim_slot_t *slot;
  int i;

  for (i = 0; i < set->array.capacity; ++i) {
    slot = nepim_slot_set_get(set, i);
    if (slot)
      if (slot->index_remote == remote_slot)
        if (slot->session.remote_len == remote_len)
          if (!memcmp(&slot->session.remote, remote, remote_len))
            return -1;
  }

  return 0;
}

static void slot_buf_write(nepim_slot_t *slot, char *buf, size_t buf_size, uint8_t type)
{
  nepim_udp_hdr_t hdr;

  assert(buf_size >= UDP_HEADER_LEN);

  hdr.version  = UDP_VERSION;
  hdr.dst_slot = slot->index_remote;
  hdr.src_slot = slot->index;
  hdr.type     = type;
  hdr.seed     = slot->session.seed;

  switch (type) {
  case UDP_TYPE_DATA:

    /* modifies 'session->seed' */
    fill_packet_data(&(slot->session), (unsigned char *) buf,
		     UDP_HEADER_LEN, buf_size);

    hdr.seq = ++slot->seq;

    break;
  case UDP_TYPE_HELLO:
  case UDP_TYPE_KEEPALIVE:
    hdr.seq = 0;
    break;
  default:
    assert(0);
  }

  nepim_udp_hdr_write(&hdr, buf, buf_size);
}

/*
  remove 224.0.0.224 to skip the multicast block,
  because the linux UDP stack doesn't seem to like
  them used in this way (unicast socket mode?)

  we remove 224 from both sides (1st and last byte)
  because we don't want/need to test endianness.

  alternatively, we could work-around this elsewhere.
*/
#define NEPIM_ADDR32_NOMULTICAST(a) ((a) &= ~0xE00000E0)
#define NEPIM_ADDR32_NOZERONET(a) ((a) |= 0x01000001)

int nepim_slot_buf_sendto(nepim_slot_t *slot, char *buf, size_t buf_size, uint8_t type)
{
  ssize_t wr;

  slot_buf_write(slot, buf, buf_size, type);

  /* Randomize destination address? */
  if (nepim_global.udp_dst_random_addr) {
    int family = nepim_sock_family((const struct sockaddr *) &slot->session.remote);
    switch (family) {
    case PF_INET:
      {
	uint32_t random_addr = nepim_urand_next(&slot->session.udp_dst_random_ctx);
	NEPIM_ADDR32_NOMULTICAST(random_addr);
	NEPIM_ADDR32_NOZERONET(random_addr);
	slot->session.remote.inet.sin_addr.s_addr = random_addr;
      }
      break;
    case PF_INET6:
      {
	int i;
	for (i = 0; i < 4; ++i) {
	  uint32_t random_addr = nepim_urand_next(&slot->session.udp_dst_random_ctx);
#ifdef HAVE_INET6_S6_ADDR32 /* Linux */
	  slot->session.remote.inet6.sin6_addr.s6_addr32[i] = random_addr;
#elif HAVE_INET6_IN6_U /* Linux */
	  slot->session.remote.inet6.sin6_addr.in6_u.u6_addr32[i] = random_addr;
#elif HAVE_INET6_S6_UN /* Solaris */
	  slot->session.remote.inet6.sin6_addr._S6_un._S6_u32[i] = random_addr;
#elif HAVE_INET6_U6_ADDR /* FreeBSD */
          slot->session.remote.inet6.sin6_addr.__u6_addr.__u6_addr32[i] = random_addr;
#else
          assert(0);	
#endif
	}
      }
      break;
    default:
      assert(0);
    }
  }

  /* Randomize destination port? */
  if (nepim_global.udp_dst_random_port) {
    int random_port = nepim_rand_next(&slot->session.udp_dst_random_ctx, 0, 65535);
    nepim_sock_set_port((const struct sockaddr *) &slot->session.remote,
			random_port);
  }

  wr = sendto(slot->udp_sd, buf, buf_size, 0,
	      (const struct sockaddr *) &slot->session.remote,
	      slot->session.remote_len);
  if (wr < 1)
    if (nepim_global.verbose_stderr) {
      char addr_buf[500];
      nepim_sock_dump_addr(addr_buf, sizeof addr_buf,
			   (const struct sockaddr *) &slot->session.remote,
			   slot->session.remote_len);
      fprintf(nepim_global.verbose_stderr,
	      "%s %s: sendto(dst=%s,%d len=%d): sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      addr_buf,
	      nepim_sock_get_port((const struct sockaddr *) &slot->session.remote),
	      slot->session.remote_len, slot->udp_sd, errno, strerror(errno));
    }

  return wr;
}

int nepim_slot_buf_write(nepim_slot_t *slot, char *buf, size_t buf_size, uint8_t type)
{
  ssize_t wr;

  /* should not write() to random destinations */
  assert(!nepim_global.udp_dst_random_addr && !nepim_global.udp_dst_random_port);

  slot_buf_write(slot, buf, buf_size, type);

  wr = write(slot->udp_sd, buf, buf_size);

  return wr;
}

void nepim_will_slot_keepalive(nepim_slot_t *slot, oop_call_fd *on_udp_write)
{
  nepim_session_t *session = &slot->session;
  int sd = slot->udp_sd;

  assert(!session->must_send);
  assert(session->keepalive_must_send);

  assert(!slot->want_write);
  ++slot->want_write;

  if (nepim_usock_writer_add(&udp_tab, sd))
    return;

  nepim_global.oop_src->on_fd(nepim_global.oop_src, sd,
                              OOP_WRITE, on_udp_write, 0);
}

void nepim_cancel_slot_keepalive(nepim_slot_t *slot)
{
  nepim_session_t *session = &slot->session;
  int sd = slot->udp_sd;

  assert(!session->must_send);
  assert(session->keepalive_must_send);

  assert(slot->want_write == 1);
  --slot->want_write;

  if (nepim_usock_writer_del(&udp_tab, sd))
    return;

  nepim_global.oop_src->cancel_fd(nepim_global.oop_src,
                                  sd, OOP_WRITE);
}

void nepim_udp_write_keepalive(nepim_slot_t *slot, 
                               int (*nepim_slot_buf_send)(nepim_slot_t*,
                                                          char*,size_t,uint8_t),
                               oop_call_time *on_udp_keepalive_time,
                               void (*udp_slot_kill)(nepim_slot_t *))
{
  char buf[nepim_global.udp_write_size];
  int wr;
  nepim_session_t *session;
  int to_write;
  int sd;

  assert(nepim_global.udp_write_size == sizeof(buf));
  assert(slot);

  /* stop writing */
  nepim_cancel_slot_keepalive(slot);

  sd = slot->udp_sd;
  session = &slot->session;

  assert(!session->must_send);
  assert(session->keepalive_must_send);
  
  to_write = UDP_HEADER_LEN;
  assert(to_write > 0);
  assert(to_write >= UDP_HEADER_LEN);
  assert(to_write <= nepim_global.udp_write_size);

  wr = nepim_slot_buf_send(slot, buf, to_write, UDP_TYPE_KEEPALIVE);
  if (wr < 1) {
    switch (errno) {
    case EINTR:
    case EAGAIN:
      nepim_usock_write_error(&udp_tab, sd, 
                              slot->index, slot->index_remote,
                              errno, nepim_global.soft_error_verbose);

      return;
    case EPIPE:
      fprintf(stderr, "keepalive_write: EPIPE on UDP socket %d\n", sd);
      break;
    }

    fprintf(stderr,
            "%d: keepalive_write: unexpected failure: errno=%d: %s\n",
            sd, errno, strerror(errno));

    if (!session->duration_done)
      report_broken_slot_stat(stdout, slot);

    udp_slot_kill(slot);

    return;
  }

  assert(wr > 0);
  assert(wr <= to_write);

  if (wr == to_write)
    nepim_usock_write_good_full(&udp_tab, sd);
  else
    nepim_usock_write_good_partial(&udp_tab, sd);

  nepim_session_write_add(session, wr);

  /* schedule next keepalive time */
  nepim_global.oop_src->on_time(nepim_global.oop_src,
                                session->tv_keepalive_send_next,
                                on_udp_keepalive_time, slot);
}

void nepim_schedule_keepalive_timer(nepim_slot_t *slot,
                                    oop_call_time *on_udp_keepalive_require)
{
  nepim_session_t *session = &slot->session;

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
                                on_udp_keepalive_require, slot);
}

/*
  per-read
 */
void nepim_slot_seq_recv(nepim_slot_t *slot, uint64_t seq)
{
  uint64_t expected = slot->seq_highest_recv + 1;

#if 0
  fprintf(stderr,
	  "ERASEME DEBUG recv SEQ = %llu\n",
	  seq);
#endif

  ++slot->interval_pkt_recv;
  ++slot->total_pkt_recv;

  if (seq == expected) {
    slot->seq_highest_recv = seq;
    return;
  }

  if (seq > expected)
    slot->seq_highest_recv = seq;

  ++slot->interval_pkt_ooo;
  ++slot->total_pkt_ooo;
}

/*
  per-interval
 */
void nepim_slot_update_pkt_stat(nepim_slot_t *slot)
{
  slot->total_pkt_lost = slot->seq_highest_recv - slot->total_pkt_recv;
  slot->interval_pkt_lost = slot->total_pkt_lost - slot->subtotal_pkt_lost;
  slot->subtotal_pkt_lost = slot->total_pkt_lost;
}
