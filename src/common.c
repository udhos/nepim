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

/* $Id: common.c,v 1.96 2014/07/10 06:55:43 evertonm Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <inttypes.h>

#include "common.h"
#include "sock.h"
#include "conf.h"
#include "str.h"
#include "rand.h"


const char * const NEPIM_LABEL_PARTIAL      = "cur";
const char * const NEPIM_LABEL_TOTAL        = "avg";
const char * const NEPIM_LABEL_TOTAL_BROKEN = "avg(broken)";
const char * const NEPIM_LABEL_MIN          = "min";
const char * const NEPIM_LABEL_MAX          = "max";

const char * const NEPIM_MSG_KEEPALIVES_SCHED = "scheduling sending of keepalives";
const char * const NEPIM_MSG_KEEPALIVES_MISS  = "peer not sending keepalives? (see option -K)";

static int line = 0;


static void header(FILE *out, int ident, int udp)
{
  if (!(line++ % 10)) {
    while (--ident >= 0)
      putc(' ', out);
    fprintf(out, " %10s %10s %8s %8s", 
	    "kbps_in", "kbps_out", "rcv/s", "snd/s");
    if (udp) {
      fprintf(out, " %5s %5s", "loss", "ooo");
      if (nepim_global.udp_accumulative_loss)
	fprintf(out, " %s", "LOST");
    }
    fprintf(out, "\n");
  }
}

#define MIN_UPDATE(a, b) { if ((a) < (b)) (b) = (a); }
#define MAX_UPDATE(a, b) { if ((a) > (b)) (b) = (a); }

static void dump_rates_line(FILE *out,
			    float kbps_in, float kbps_out,
			    float read_rate, float write_rate)
{
  fprintf(out,
          " %10.2f %10.2f %8.2f %8.2f", 
          kbps_in,
          kbps_out,
          read_rate,
          write_rate);
}

static void dump_ratio(FILE *out, float ratio)
{
  char buf[100];

  snprintf(buf, sizeof buf, "%6.4f", ratio);
  fprintf(out, " %s", (*buf == '0') ? (buf + 1) : buf);
}

static void show_rates_line(FILE *out,
			    const nepim_mark_t *mark,
			    int udp)
{
  dump_rates_line(out,
		  mark->kbps_in,
		  mark->kbps_out,
		  mark->pps_in,
		  mark->pps_out);

  if (udp) {
    dump_ratio(out, mark->pkt_loss);
    dump_ratio(out, mark->pkt_ooo);
  }

  fprintf(out, "\n");
}

static void nepim_dump_rates(FILE *out,
                            long long bytes_recv, long long bytes_sent, 
                            float interval, int reads, int writes,
			    nepim_mark_t *min, nepim_mark_t *max)
{
  float kbps_recv = bytes_recv / (interval * 125); /* 8/1000 = 1/125 */
  float kbps_sent = bytes_sent / (interval * 125); /* 8/1000 = 1/125 */
  float read_rate = reads / interval;
  float write_rate = writes / interval;

  MIN_UPDATE(kbps_recv, min->kbps_in);
  MIN_UPDATE(kbps_sent, min->kbps_out);
  MIN_UPDATE(read_rate, min->pps_in);
  MIN_UPDATE(write_rate, min->pps_out);

  MAX_UPDATE(kbps_recv, max->kbps_in);
  MAX_UPDATE(kbps_sent, max->kbps_out);
  MAX_UPDATE(read_rate, max->pps_in);
  MAX_UPDATE(write_rate, max->pps_out);

  dump_rates_line(out,
		  kbps_recv,
		  kbps_sent,
		  read_rate,
		  write_rate);
}

void nepim_pipe_stat(FILE *out, struct timeval now,
		     const char *label, int sd,
                     long long bytes_recv, long long bytes_sent, 
                     float interval, long sec_start, 
                     long sec_duration, int reads, int writes,
		     nepim_mark_t *min, nepim_mark_t *max,
		     int report_min_max)
{
  char buf[100];
  int pr;
  long ts = sec_duration - (now.tv_sec - sec_start);

  pr = snprintf(buf, sizeof buf, "%3d %3s %5ld",
		sd, label, ts);

  header(out, pr, 0 /* udp=false */);

  fprintf(out, "%s", buf);

  nepim_dump_rates(out, bytes_recv, bytes_sent, 
		   interval, reads, writes,
		   min, max);

  fprintf(out, "\n");

  if (report_min_max) {
    fprintf(out, "%3d %3s %5ld", sd, NEPIM_LABEL_MIN, ts);
    show_rates_line(out, min, 0 /* udp=false */);
    fprintf(out, "%3d %3s %5ld", sd, NEPIM_LABEL_MAX, ts);
    show_rates_line(out, max, 0 /* udp=false */);
  }

  /* otherwise server won't output stats if out is redirected */
  fflush(out);
}

void nepim_slot_stat(FILE *out, struct timeval now,
		     const char *label, int sd,
                     int local_slot, int remote_slot,
                     long long bytes_recv, long long bytes_sent, 
                     float interval, long sec_start, 
                     long sec_duration, int reads, int writes,
                     uint64_t pkt_expected, uint64_t pkt_lost,
		     uint64_t pkt_ooo, uint64_t acc_pkt_lost,
		     nepim_mark_t *min, nepim_mark_t *max,
		     int report_min_max)
{
  char buf[100];
  int pr;
  long ts = sec_duration - (now.tv_sec - sec_start);

  pr = snprintf(buf, sizeof buf, 
		"%3d %3d %3d %4s %5ld",
		sd, local_slot, remote_slot,
		label, ts);

  header(out, pr, 1 /* udp=true */);

  fprintf(out, "%s", buf);

  nepim_dump_rates(out, bytes_recv, bytes_sent, 
		   interval, reads, writes,
		   min, max);

  {
    float loss_ratio;
    float ooo_ratio;

#if 0
    fprintf(stderr, "DEBUG common.c pkt_expected = %llu\n", pkt_expected);
#endif

    if (pkt_expected) {
      loss_ratio = pkt_lost;
      ooo_ratio  = pkt_ooo;
      loss_ratio /= pkt_expected;
      ooo_ratio  /= pkt_expected;
    }
    else {
      loss_ratio = 0;
      ooo_ratio  = 0;
    }

    MIN_UPDATE(loss_ratio, min->pkt_loss);
    MIN_UPDATE(ooo_ratio, min->pkt_ooo);

    MAX_UPDATE(loss_ratio, max->pkt_loss);
    MAX_UPDATE(ooo_ratio, max->pkt_ooo);

    dump_ratio(out, loss_ratio);
    dump_ratio(out, ooo_ratio);
  }

  if (nepim_global.udp_accumulative_loss)
    fprintf(out, " %" PRIu64, acc_pkt_lost);

  fprintf(out, "\n");

  if (report_min_max) {
    fprintf(out, "%3d %3d %3d %4s %5ld",
	    sd, local_slot, remote_slot,
	    NEPIM_LABEL_MIN, ts);
    show_rates_line(out, min, 1 /* udp=true */);
    fprintf(out, "%3d %3d %3d %4s %5ld",
	    sd, local_slot, remote_slot,
	    NEPIM_LABEL_MAX, ts);
    show_rates_line(out, max, 1 /* udp=true */);
  }

  /* otherwise server won't output stats if out is redirected */
  fflush(out);
}

void report_broken_pipe_stat_at(FILE *out, nepim_pipe_t *pipe,
				struct timeval now)
{
  nepim_session_t *session = &pipe->session;
  float elapsed_sec;
  float elapsed_usec;
  float elapsed;
      
  elapsed_sec = now.tv_sec - session->tv_start.tv_sec;
  elapsed_usec = now.tv_usec - session->tv_start.tv_usec;

  elapsed = elapsed_sec + elapsed_usec / 1000000;

  nepim_pipe_stat(out, 
		  now,
                  NEPIM_LABEL_TOTAL_BROKEN,
                  pipe->sd, 
                  session->byte_total_recv,
                  session->byte_total_sent,
                  elapsed, 
                  session->tv_start.tv_sec,
                  session->test_duration,
                  session->total_reads,
                  session->total_writes,
		  &session->min,
		  &session->max,
		  1 /* report_min_max = true */);
}

void report_broken_pipe_stat(FILE *out, nepim_pipe_t *pipe)
{
  struct timeval now;
  int result;
      
  result = gettimeofday(&now, 0);
  assert(!result);

  report_broken_pipe_stat_at(out, pipe, now);
}

void report_broken_slot_stat_at(FILE *out, nepim_slot_t *slot,
				struct timeval now)
{
  nepim_session_t *session = &slot->session;
  float elapsed_sec;
  float elapsed_usec;
  float elapsed;

  assert(!slot->session.duration_done);

  nepim_slot_update_pkt_stat(slot);
  
  elapsed_sec = now.tv_sec - session->tv_start.tv_sec;
  elapsed_usec = now.tv_usec - session->tv_start.tv_usec;
  elapsed = elapsed_sec + elapsed_usec / 1000000;

  nepim_slot_stat(out,
		  now,
                  NEPIM_LABEL_TOTAL_BROKEN,
                  slot->udp_sd,
                  slot->index, 
                  slot->index_remote,
                  session->byte_total_recv,
                  session->byte_total_sent,
                  elapsed, 
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
}

void report_broken_slot_stat(FILE *out, nepim_slot_t *slot)
{
  struct timeval now;
  int result;
      
  result = gettimeofday(&now, 0);
  assert(!result);

  report_broken_slot_stat_at(out, slot, now);
}

void nepim_timer_usec_add(struct timeval *tv, susec_t usec)
{
  tv->tv_usec += usec;

  /* overflow? */
  if (tv->tv_usec >= NEPIM_MEGA) {
    int sec = tv->tv_usec / NEPIM_MEGA;
    tv->tv_usec %= NEPIM_MEGA;
    tv->tv_sec += sec;
  }

  assert(tv->tv_usec < NEPIM_MEGA);
}

long long nepim_bps2bytes(long long bps_bit_rate, susec_t usec_delay)
{
  long long bytes;

  bytes = bps_bit_rate;
  bytes *= usec_delay;
  bytes /= NEPIM_8MEGA;

  return bytes;
}

long long nepim_min_bps(susec_t usec_delay)
{
  long long rate;

  rate = NEPIM_8MEGA;
  rate /= usec_delay;

  return rate;
}

int nepim_pps2packets(int pps_pkt_rate, susec_t usec_delay)
{
  long long pkts;

  pkts = pps_pkt_rate;
  pkts *= usec_delay;
  pkts /= NEPIM_MEGA;

  assert(pkts > -NEPIM_2MEGA);
  assert(pkts < NEPIM_2MEGA);

#if 0
  fprintf(stderr, "XXX pkt_rate=%d delay=%ld packets=%lld\n", pps_pkt_rate, usec_delay, pkts);
#endif

  return pkts;
}

int nepim_min_pps(susec_t usec_delay)
{
  int pps;

  pps = NEPIM_MEGA;
  pps /= usec_delay;

  return pps;
}

unsigned real_random(void)
{
    FILE        *dev_random;
    unsigned    x;

    if ((dev_random = fopen("/dev/urandom", "r")) == NULL) {
        fprintf(stderr, "ERROR: %s: %s: %s: fopen: %s\n",
                nepim_global.prog_name, __FILE__, __PRETTY_FUNCTION__,
                strerror(errno));
        exit(1);
    }
    if (fread(&x, sizeof(x), 1, dev_random) != 1) {
        fprintf(stderr, "ERROR: %s: %s: %s: fread: failed.\n",
                nepim_global.prog_name, __FILE__, __PRETTY_FUNCTION__);
        exit(1);
    }
    if (fclose(dev_random) == EOF) {
        fprintf(stderr, "ERROR: %s: %s: %s: fclose: %s\n",
                nepim_global.prog_name, __FILE__, __PRETTY_FUNCTION__,
                strerror(errno));
        exit(1);
    }
    return(x);
}

/* Fill the packet with data, excluding the header at the start. */
void fill_packet_data(nepim_session_t *session, unsigned char *packet_buf,
                      unsigned header_len, unsigned packet_size)
{
    unsigned    i;

    if (!session->verify_data) {
        return;
    }
    for (i = header_len; i < packet_size; i++) {
        packet_buf[i] = (session->random_fill ?
                         QRANDOM(session->seed) : session->fill_byte);
    }
}

/* Check the data against the expected random pattern. */
void tcp_check_data(int sd, nepim_session_t *session, unsigned char *buf,
                    unsigned buf_size)
{
    unsigned            i;
    unsigned char       expected_byte;
    static unsigned     errors = 0;
    /* After this number of errors, error messages are not so useful. */
    unsigned            max_errors = 20;

    if (!session->verify_data) {
        return;
    }
    for (i = 0; i < buf_size; i++) {
        /*
         * NOTE that 'check_seed' is used here instead of 'seed'.
         * This is to avoid reusing the same seed for sending and
         * receiving in duplex (-d) mode.
         */
        expected_byte = (session->random_fill ?
                         QRANDOM(session->check_seed) : session->fill_byte);
        if (buf[i] != expected_byte) {
            if (++errors <= max_errors) {
                fprintf(stderr, "%d: ERROR: data mismatch: expected 0x%02x, got 0x%02x.\n",
                        sd, expected_byte, buf[i]);
            }
            if (errors == max_errors) {
                fprintf(stderr, "ERROR: %s: %s: %s: max data mismatches reached.\n",
                        nepim_global.prog_name, __FILE__, __PRETTY_FUNCTION__);
            }
        }
    }
}

/* Check the packet data against the expected pattern,
   excluding the header at the start. */
void udp_check_packet_data(int sd, nepim_udp_hdr_t *hdr,
                           nepim_session_t *session,
                           unsigned char *packet_buf, unsigned header_len,
                           unsigned packet_size)
{
    unsigned            i;
    unsigned char       expected_byte;
    static unsigned     errors = 0;
    /* After this number of errors, error messages are not so useful. */
    unsigned            max_errors = 20;
    unsigned            seed = hdr->seed;

    if (!session->verify_data) {
        return;
    }
    for (i = header_len; i < packet_size; i++) {
        expected_byte = (session->random_fill ?
                         QRANDOM(seed) : session->fill_byte);
        if (packet_buf[i] != expected_byte) {
            if (++errors <= max_errors) {
                fprintf(stderr, "%d %d-%d: ERROR: packet data mismatch at byte %u: expected 0x%02x, got 0x%02x.\n",
                        sd, hdr->dst_slot, hdr->src_slot,
                        i, expected_byte, packet_buf[i]);
            }
            if (errors == max_errors) {
                fprintf(stderr, "ERROR: %s: %s: %s: max data mismatches reached.\n",
                        nepim_global.prog_name, __FILE__, __PRETTY_FUNCTION__);
            }
        }
    }
}

struct sockaddr *nepim_addrlist_findfirst(int socktype, int proto,
					  const char *list,
					  struct sockaddr *addr,
					  int *addr_len)
{
  int size = addr_list_size(list);
  int i;

  for (i = 0; i < size; ++i) {
    char hostname[100];
    char *portname;
    struct addrinfo hints;
    struct addrinfo *ai_res;
    struct addrinfo *ai;
    int result;

    if (addr_list_get(list, i, hostname, sizeof(hostname))) {
      fprintf(stderr, 
              "%s %s: failure parsing address %d/%d from list: %s\n",
              __FILE__, __PRETTY_FUNCTION__,
	      i, size, list);
      continue;
    }

    /* split host/port */
    if (addr_split_port(hostname, sizeof(hostname), &portname))
      portname = 0; /* if port unspecified, ask OS for one */

    memset(&hints, 0, sizeof(hints));

    hints.ai_socktype = socktype;
    hints.ai_protocol = proto;
    hints.ai_flags    = AI_CANONNAME;
    hints.ai_family   = PF_UNSPEC;

    result = getaddrinfo(hostname, portname, &hints, &ai_res);
    if (result) {
      fprintf(stderr, "%s %s: getaddrinfo(%s,%s): %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      hostname, portname ? portname : "0",
	      gai_strerror(result));
      continue;
    }

    for (ai = ai_res; ai; ai = ai->ai_next) {

      if (nepim_global.no_inet6 && (ai->ai_family == PF_INET6))
	continue;

      if (nepim_global.no_inet4 && (ai->ai_family == PF_INET))
	continue;

      memcpy(addr, ai->ai_addr, ai->ai_addrlen);
      *addr_len = ai->ai_addrlen;

      break;
    }

    freeaddrinfo(ai_res);

    return addr;
  }

  return 0;
}
