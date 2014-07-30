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

/* $Id: slot.h,v 1.29 2006/05/11 12:23:35 evertonm Exp $ */

#ifndef NEPIM_SLOT_H
#define NEPIM_SLOT_H

#include <oop.h>

#include "array.h"
#include "session.h"

typedef struct nepim_slot_t nepim_slot_t;
typedef struct nepim_slot_set_t nepim_slot_set_t;

enum {
  NEPIM_SLOT_CLIENT_GREET,
  NEPIM_SLOT_CLIENT_SEND
};

struct nepim_slot_t {
  int             index;                     /* self indexing */
  int             index_remote;              /* remote indexing */
  int             udp_sd;                    /* udp socket */
  uint64_t        seq;                       /* udp sequence number */
  uint64_t        seq_highest_recv;
  nepim_session_t session;
  int             want_write;                /* boolean */
  int             greetings_sent;            /* counter */
  int             client_writer_status;      /* greet/send */
  uint64_t        interval_last_highest_seq;
  int             interval_pkt_recv;
  int             interval_pkt_lost;
  int             interval_pkt_ooo;          /* out-of-order */
  uint64_t        subtotal_pkt_lost;         /* lost until last interval */
  uint64_t        total_pkt_lost;
  uint64_t        total_pkt_recv;
  uint64_t        total_pkt_ooo;             /* out-of-order */
};

struct nepim_slot_set_t {
  nepim_array_t array;
};

void nepim_slot_set_init(nepim_slot_set_t *set);

nepim_slot_t *nepim_slot_set_get(const nepim_slot_set_t *set, int index);
nepim_slot_t *nepim_slot_set_search(const nepim_slot_set_t *set, int index);
nepim_slot_t *nepim_slot_set_search_remote(const nepim_slot_set_t *set,
					   const struct sockaddr *addr,
					   socklen_t len);

int nepim_slot_find_free(nepim_slot_set_t *set);

void nepim_slot_set_add(nepim_slot_set_t *set, int sd,
			int index, int index_remote,
			const struct sockaddr *remote,
			socklen_t remote_len,
			const nepim_greet_t *opt);

void nepim_slot_set_del(nepim_slot_set_t *set, int index);

nepim_slot_t *nepim_slot_find_next_writer(const nepim_slot_set_t *set, int sd);

int nepim_slot_find_addr(const nepim_slot_set_t *set,
			 int remote_slot, 
			 const struct sockaddr *remote,
			 socklen_t remote_len);

int nepim_slot_buf_sendto(nepim_slot_t *slot, char *buf, size_t buf_size, uint8_t type);
int nepim_slot_buf_write(nepim_slot_t *slot, char *buf, size_t buf_size, uint8_t type);

void nepim_slot_seq_recv(nepim_slot_t *slot, uint64_t seq);

void nepim_slot_update_pkt_stat(nepim_slot_t *slot);

/*
 * this is a (exceedingly?) complex way of reusing
 * code between udp_server.c and udp_client.c 
 */
void nepim_will_slot_keepalive(nepim_slot_t *slot, oop_call_fd *on_udp_write);
void nepim_cancel_slot_keepalive(nepim_slot_t *slot);
void nepim_udp_write_keepalive(nepim_slot_t *slot, 
			       int (*nepim_slot_buf_send)(nepim_slot_t*,
							  char*,size_t,uint8_t),
			       oop_call_time *on_udp_keepalive_time,
			       void (*udp_slot_kill)(nepim_slot_t *));
void nepim_schedule_keepalive_timer(nepim_slot_t *slot,
				    oop_call_time *on_udp_keepalive_require);

#endif /* NEPIM_SLOT_H */
