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

/* $Id: common.h,v 1.31 2007/11/28 15:47:19 evertonm Exp $ */

#ifndef NEPIM_COMMON_H
#define NEPIM_COMMON_H

#include <stdio.h>

#include "pipe.h"
#include "slot.h"
#include "usec.h"
#include "udp_header.h"

#define NEPIM_MEGA  (1000000)
#define NEPIM_2MEGA (2000000)
#define NEPIM_8MEGA (8000000)

#define NEPIM_MIN(a, b)      (((a) < (b)) ? (a) : (b))
#define NEPIM_MAX(a, b)      (((a) > (b)) ? (a) : (b))
#define NEPIM_RANGE(v, a, b) NEPIM_MIN(NEPIM_MAX((v), (a)), (b))

extern const char * const NEPIM_LABEL_PARTIAL;
extern const char * const NEPIM_LABEL_TOTAL;

extern const char * const NEPIM_MSG_KEEPALIVES_SCHED;
extern const char * const NEPIM_MSG_KEEPALIVES_MISS;

void nepim_pipe_stat(FILE *out, struct timeval now,
		     const char *label, int sd,
                     long long bytes_recv, long long bytes_sent, 
                     float interval, long sec_start, 
                     long sec_duration, int reads, int writes,
		     nepim_mark_t *min, nepim_mark_t *max,
		     int report_min_max);

void nepim_slot_stat(FILE *out, struct timeval now,
		     const char *label, int sd,
                     int local_slot, int remote_slot,
                     long long bytes_recv, long long bytes_sent, 
                     float interval, long sec_start, 
                     long sec_duration, int reads, int writes,
                     uint64_t pkt_expected, uint64_t pkt_lost,
		     uint64_t pkt_ooo, uint64_t acc_pkt_lost,
		     nepim_mark_t *min, nepim_mark_t *max,
		     int report_min_max);

void report_broken_pipe_stat(FILE *out, nepim_pipe_t *pipe);
void report_broken_slot_stat(FILE *out, nepim_slot_t *slot);

void report_broken_pipe_stat_at(FILE *out, nepim_pipe_t *pipe,
				struct timeval now);
void report_broken_slot_stat_at(FILE *out, nepim_slot_t *slot,
				struct timeval now);

void nepim_timer_usec_add(struct timeval *tv, susec_t usec);

long long nepim_bps2bytes(long long bps_bit_rate, susec_t usec_delay);
long long nepim_min_bps(susec_t usec_delay);
int nepim_pps2packets(int pps_pkt_rate, susec_t usec_delay);
int nepim_min_pps(susec_t usec_delay);
unsigned real_random(void);

void fill_packet_data(nepim_session_t *session, unsigned char *packet_buf,
                      unsigned header_len, unsigned packet_size);
void tcp_check_data(int sd, nepim_session_t *session, unsigned char *buf,
                    unsigned buf_size);
void udp_check_packet_data(int sd, nepim_udp_hdr_t *hdr,
                           nepim_session_t *session,
                           unsigned char *packet_buf, unsigned header_len,
                           unsigned packet_size);

struct sockaddr *nepim_addrlist_findfirst(int socktype, int proto,
					  const char *list,
					  struct sockaddr *addr,
					  int *addr_len);

#endif /* NEPIM_COMMON_H */
