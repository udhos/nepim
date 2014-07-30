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

/*
  nepim - network pipemeter

  $Id: main.c,v 1.75 2008/08/22 02:01:19 evertonm Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <oop.h>
#include <assert.h>

#ifdef HAVE_SIGHANDLER_T
# define __USE_GNU
# include <signal.h>
#else
# include <signal.h>
typedef void (*sighandler_t)(int);
#endif

#include "conf.h"
#include "common.h"
#include "str.h"
#include "int.h"
#include "udp_header.h"
#include "version.h"

static int UDP_OVERHEAD = 28; /* 20 ip +  8 udp */
static int TCP_OVERHEAD = 44; /* 20 ip + 24 tcp */

extern void nepim_server_run();
extern void nepim_client_run();



static void usage(FILE *out, const char *prog_name)
{
  char buf[100];
  char buf2[100];
  char *bit_rate;
  char *pkt_rate;

  if (nepim_global.bit_rate < 0) {
    bit_rate = "unlimited";
  } else {
    int wr = snprintf(buf, sizeof(buf), "%lld", nepim_global.bit_rate);
    assert(wr > 0);
    assert(wr < sizeof(buf));
    bit_rate = buf;
  }

  if (nepim_global.pkt_rate < 0) {
    pkt_rate = "unlimited";
  } else {
    int wr = snprintf(buf2, sizeof(buf2), "%d", nepim_global.pkt_rate);
    assert(wr > 0);
    assert(wr < sizeof(buf2));
    pkt_rate = buf2;
  }

  fprintf(out, 
          "usage: %s [options]\n"
          "\n"
          "common (client/server) options:\n"
          "  -h             help\n"
          "  -v             show program version\n"
	  "  -V             verbose error messages\n"
          "  -b addr-list   bind to specific addresses (defaults to any)\n"
          "  -p port        server port number (defaults to %s)\n"
          "  -m mode        path MTU discovery mode (defaults to %d)\n"
          "                 modes: -1 = use system-wide settings\n"
          "                         0 = DONT (never do PMTU discovery, DF=0)\n"
          "                         1 = WANT (use per-route hints)\n"
          "                         2 = DO   (always do PMTU discovery, DF=1)\n"
          "  -t ttl         TTL for sending packets (defaults to system)\n"
          "  -smss bytes    set server-side TCP maximum segment size (MSS)\n"
          "  -w size        TCP write size (defaults to %d bytes)\n"
          "  -z size        TCP read size (defaults to %d bytes)\n"
          "  -W size        UDP write size (defaults to %d bytes)\n"
          "  -Z size        UDP read size (defaults to %d bytes)\n"
          "  -O size        maximum socket send buffer in bytes\n"
          "  -I size        maximum socket receive buffer in bytes\n"
          "  -k password    server authentication secret\n"
          "  -6             disable IPv6\n"
          "  -4             disable IPv4\n"
	  "  -q             quietly hide soft read/write errors\n"
	  "  -Q             quietly hide debug errors\n"
	  "  -y tos         ip tos (defaults to %d, tos=-1 means don't change)\n"
	  "  -L             supress output of UDP accumulative loss\n"
	  "  -E             set IP Router Alert option\n"
	  "\n"
          "client-only options:\n"
          "  -c host-list   client mode (defaults to server mode)\n"
          "  -u             UDP mode (defaults to TCP)\n"
          "  -s             client-send simplex mode (defaults to server-send)\n"
          "  -d             duplex traffic (defaults to simplex)\n"
	  "  -F             force sending out UDP regardless of server\n"
	  "  -Fa            same as -F plus randomize destination address\n"
	  "  -Fp            same as -F plus randomize destination port\n"
	  "                 if -c is omitted, either 'a' or 'p' implies -c 1.1.1.1\n"
	  "                 hint: use '-c ::1 -Fa' to randomize IPv6 addresses\n"
          "  -M             enable multicast-compatible options\n"
	  "  -o [overhead]  protocol per-packet overhead in bytes (defaults to none)\n"
	  "                 if the optional 'overhead' argument is omitted:\n"
	  "                 UDP overhead defaults to %d\n"
	  "                 TCP overhead defaults to %d\n"
          "  -n pipes       number of parallel pipes (defaults to %d)\n"
          "  -r bit-rate    upper bit rate limit (defaults to %s bps)\n"
          "  -R pkt-rate    upper packet rate limit (defaults to %s pps)\n"
	  "  -D send-delay  delay between sends (defaults to %ld us)\n"
	  "                 only meaningful if specified before -r or -R\n"
	  "  -e send-rate   even send rate (defaults to off)\n"
	  "                 try to keep uniform delay between sends\n"
	  "                 incompatible with both -R and -D\n"
	  "                 may be disrupted by -r\n"
	  "                 may cause higher processing loads\n"
          "  -i interval    statistics report interval (defaults to %d seconds)\n"
          "  -a age         test duration (defaults to %d seconds)\n"
          "  -S seed        starting seed (in hex) (defaults to random)\n"
          "  -P byte        payload fill byte (in hex) (defaults to do not verify)\n"
          "                 if \"byte\" = \"random\" the payload data is random\n"
          "  -X pause       wait \"pause\" seconds before transmitting data\n"
          "                 (defaults to %d seconds)\n"
          "  -g retries     limit for UDP greeting retries (defaults to %d)\n"
	  "  -A socket-ka   socket keepalive (defaults to %d)\n"
	  "                 socket-ka: -1 = use system's default\n"
	  "                             0 = off\n"
	  "                             1 = on\n"
	  "  -C [interval]  enable app-layer TCP keepalives (defaults to off)\n"
	  "                 if unspecified, 'interval' defaults to %ld us\n"
	  "                 'interval' can't be lower than %ld us\n"
	  "  -K udp-ka-time UDP keepalive timeout (defaults to %ld us)\n"
	  "                 'udp-ka-time' can't be lower than %ld us\n"
	  "  -cmss bytes    set client-side TCP maximum segment size (MSS)\n"
	  "  -mM            report periodic (per-interval) min-MAX rates\n"
	  "  -N nagle       TCP nagle mode (defaults to %d)\n"
	  "                 nagle: -1 = use system's default\n"
	  "                         0 = off (enable TCP_NODELAY)\n"
	  "                         1 = on (disable TCP_NODELAY)\n"
	  "  -sweep lo,hi,s sweep write size from 'lo' to 'hi' at step 's'\n"
	  "                 if lo=\"auto\", lo is minimum size\n"
	  "                 if hi=\"auto\", hi is maximum size\n"
	  "                 'lo' must be lower than 'hi'\n"
	  "                 if s is negative, sweeps from 'hi' to 'lo'\n"
	  "                 if s=\"random\", sweeps randomly\n"
	  "\n"
          "server-only options:\n"
          "  -f [lib-name]  enable TCP wrapper filtering\n"
          "  -j addr-list   join multicast groups (defaults to empty)\n"
          "                 to join an SSM (source,group) pair, use: -j source+group\n"
	  "                 examples: -j fe80::1+ff01::1111\n"
	  "                           -j 10.10.10.10+232.1.1.1,2000\n"
	  "                 append @interface to specify an interface\n"
	  "                 examples: -j 239.1.1.1@eth0             (by name)\n"
	  "                           -j 1.1.1.1+232.1.1.1@10.0.0.1 (by address)\n"
	  "                           -j 239.1.1.1@1                (by index)\n"
	  "  -U path-list   bind UNIX stream sockets to specified addresses\n"
#if 0
	  "  -G path-list   bind UNIX datagram sockets to specified addresses\n"
#endif
          "  -l backlog     TCP listen(2) backlog (defaults to %d)\n"
          "  -T mcast-ttl   TTL for multicast packets (defaults to system)\n"
	  "\n"
          "addr-list syntax: addr_1[,port_1][... addr_n[,port_n]]\n"
          "                  examples: -c localhost\n"
	  "                            -b '10.0.0.1 192.168.0.1,5000 ::1'\n"
	  "                            -j ff01::1111\n"
	  "                            -U '/tmp/sock1 /tmp/sock2'\n"
          ,
          nepim_global.prog_name, 
          nepim_global.portname,
          nepim_global.pmtu_mode,
          nepim_global.tcp_write_size,
          nepim_global.tcp_read_size,
          nepim_global.udp_write_size,
          nepim_global.udp_read_size,
	  nepim_global.tos,
	  UDP_OVERHEAD,
	  TCP_OVERHEAD,
          nepim_global.pipes,
          bit_rate,
          pkt_rate,
          nepim_global.write_delay,
          nepim_global.stat_interval,
          nepim_global.test_duration,
          nepim_global.pause_duration,
          nepim_global.max_greetings,
          nepim_global.socket_keepalive,
	  nepim_global.tcp_keepalive_recv_timer,
	  nepim_global.tcp_keepalive_send_delay,
	  (long) nepim_global.udp_keepalive_recv_timer,
	  (long) nepim_global.udp_keepalive_send_delay,
          nepim_global.nagle,
          nepim_global.listen_backlog
          );
}

static void init_event_loop()
{
  sighandler_t handler;
  handler = signal(SIGPIPE, SIG_IGN);
  assert(handler != SIG_ERR);

  nepim_global.oop_sys = oop_sys_new();
  assert(nepim_global.oop_sys);
  nepim_global.oop_src = oop_sys_source(nepim_global.oop_sys);
  assert(nepim_global.oop_src);
}

static void show_version_brief(FILE *out) 
{
  fprintf(out,
	  "nepim - network pipemeter - version %s\n",
	  nepim_version());
}

static void show_version(FILE *out) 
{
  show_version_brief(out);

  fprintf(out,
         "Copyright (C) 2005 Everton da Silva Marques\n"
"\n"
"This program is free software; you can redistribute it and/or\n"
"modify it under the terms of the GNU General Public License\n"
"as published by the Free Software Foundation; either version 2\n"
"of the License, or (at your option) any later version.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
         );
}


int main(int argc, const char *argv[])
{
  int i;

  nepim_int_sanity();

  nepim_global.seed = real_random();

  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];

    if (!strcmp(arg, "-E")) {
      nepim_global.router_alert = 1; /* boolean */
      continue;
    }

    if (!strcmp(arg, "-sweep")) {
      int j = i + 1;

      nepim_global.write_floor = -2; /* auto: floor=min */
      nepim_global.write_ceil  = -2; /* auto: ceil=max */

      if (j < argc) {
	const char *range = argv[j];
        if (*range != '-') {
	  char lo[100];
	  char *hi;
	  char *step;
	  
          ++i;

	  assert(strlen(range) < (sizeof lo));
	  strncpy(lo, range, sizeof lo);
	  lo[(sizeof lo) - 1] = '\0';

	  /* range == lo,hi ? */
	  if (nepim_str_split_comma(lo, sizeof lo, &hi)) {
	    fprintf(stderr, "%s: malformed sweep range: %s (from '%s')\n",
		    nepim_global.prog_name, lo, range);
	    exit(1);
	  }

	  /* hi == hi,step ? */
	  if (!nepim_str_split_comma(hi, (sizeof lo) - (hi - lo), &step)) {
	    if (strcmp(step, "random"))
	      nepim_global.sweep_step = atoi(step);
	    else
	      nepim_global.sweep_random = 1; /* true */
	  }

	  if (strcmp(lo, "auto"))
	    nepim_global.write_floor = atoi(lo);

	  if (strcmp(hi, "auto"))
	    nepim_global.write_ceil = atoi(hi);
        }
      }

      nepim_global.server_write_floor = nepim_global.write_floor;
      nepim_global.server_write_ceil = nepim_global.write_ceil;

      continue;
    }

    if (!strcmp(arg, "-D")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing send-delay\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.write_delay = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-o")) {
      int j = i + 1;
      
      if (j < argc)
        if (*argv[j] != '-') {
	  int overhead = atoi(argv[j]);
          ++i;
	  nepim_global.udp_overhead = overhead;
          nepim_global.tcp_overhead = overhead;

	  continue;
        }

      nepim_global.udp_overhead = UDP_OVERHEAD;
      nepim_global.tcp_overhead = TCP_OVERHEAD;

      continue;
    }

    if (!strcmp(arg, "-N")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing nagle mode\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.nagle = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-C")) {
      int j = i + 1;
      
      if (j < argc)
        if (*argv[j] != '-') {
	  int interval = atoi(argv[j]);
          ++i;

	  if (interval < nepim_global.tcp_keepalive_send_delay) {
	    fprintf(stderr,
		    "%s: app-layer TCP keepalive timeout (%d us) can't be lower than keepalive interval (%ld us)\n",
		    nepim_global.prog_name,
		    interval,
		    nepim_global.tcp_keepalive_send_delay);
	    exit(1);
	  }

	  nepim_global.tcp_keepalive_recv_timer = interval;
        }

      nepim_global.tcp_keepalive_require   = 1; /* true */
      nepim_global.tcp_keepalive_must_send = 1; /* true */

      continue;
    }

    if (!strcmp(arg, "-A")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing socket keepalive mode\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.socket_keepalive = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-y")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing tos\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.tos = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-K")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing keepalive timeout\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.udp_keepalive_recv_timer = atoi(argv[i]);

      if (nepim_global.udp_keepalive_recv_timer < nepim_global.udp_keepalive_send_delay) {
	fprintf(stderr,
		"%s: UDP keepalive timeout (%ld us) can't be lower than keepalive interval (%ld us)\n",
		nepim_global.prog_name,
		nepim_global.udp_keepalive_recv_timer,
		nepim_global.udp_keepalive_send_delay);
	exit(1);
      }
      continue;
    }

    if (!strcmp(arg, "-L")) {
      nepim_global.udp_accumulative_loss = 0;
      continue;
    }

    if (!strcmp(arg, "-q")) {
      nepim_global.soft_error_verbose = 0;
      continue;
    }

    if (!strcmp(arg, "-Q")) {
      nepim_global.debug_error_verbose = 0;
      continue;
    }

    if (!strcmp(arg, "-f")) {
      int j = i + 1;

      nepim_global.tcpwrap = "libwrap.so";
      
      if (j < argc)
        if (*argv[j] != '-') {
          ++i;
          nepim_global.tcpwrap = argv[i];
        }

      continue;
    }

    if (!strcmp(arg, "-4")) {
      nepim_global.no_inet4 = 1;
      continue;
    }

    if (!strcmp(arg, "-6")) {
      nepim_global.no_inet6 = 1;
      continue;
    }

    if (!strcmp(arg, "-k")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing password\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.password = argv[i];
      continue;
    }

    if (!strcmp(arg, "-a")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing test duration\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.test_duration = nepim_time_unit(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-S")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing seed value\n",
                nepim_global.prog_name);
        exit(1);
      }
      if (sscanf(argv[i], "%x", &(nepim_global.seed)) != 1) {
        fprintf(stderr, "%s: illegal seed value\n",
                nepim_global.prog_name);
        exit(1);
      }
      continue;
    }

    if (!strcmp(arg, "-P")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing fill byte value\n",
                nepim_global.prog_name);
        exit(1);
      }
      if (!strcmp(argv[i], "random")) {
          nepim_global.random_fill = 1;         /* TRUE */
          nepim_global.fill_byte = 0x00;        /* unused */
      } else {
          unsigned      fill_byte;

          nepim_global.random_fill = 0;         /* FALSE */
          if ((sscanf(argv[i], "%x", &(fill_byte)) != 1) ||
              (fill_byte > 0xff)) {
              fprintf(stderr, "%s: illegal fill byte value\n",
                      nepim_global.prog_name);
              exit(1);
          }
          nepim_global.fill_byte = (unsigned char) fill_byte;
      }
      nepim_global.verify_data = 1;
      continue;
    }

    if (!strcmp(arg, "-X")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing pause duration\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.pause_duration = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-b")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing bind address list\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.bind_list = addr_list_append(nepim_global.bind_list, argv[i]);
      continue;
    }

    if (!strcmp(arg, "-U")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing path list\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.unix_list = addr_list_append(nepim_global.unix_list, argv[i]);
      continue;
    }

    if (!strcmp(arg, "-G")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing path list\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.unix_dgram_list = addr_list_append(nepim_global.unix_dgram_list, argv[i]);
      continue;
    }

    if (!strcmp(arg, "-c")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing hostname list\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.client_mode = 1;
      nepim_global.hostname = addr_list_append(nepim_global.hostname, argv[i]);
      continue;
    }

    if (!strcmp(arg, "-d")) {
      nepim_global.duplex_mode = 1;
      continue;
    }

    if (!strcmp(arg, "-h")) {
      usage(stdout, nepim_global.prog_name);
      exit(0);
    }

    if (!strcmp(arg, "-g")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing maximum of UDP greeting requests\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.max_greetings = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-i")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing report interval\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.stat_interval = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-j")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing multicast join list\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.join_list = addr_list_append(nepim_global.join_list, argv[i]);
      continue;
    }

    if (!strcmp(arg, "-n")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing number of pipes\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.pipes = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-p")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing port number\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.portname = argv[i];
      continue;
    }

    if (!strcmp(arg, "-m")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing PMTU discovery mode\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.pmtu_mode = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-M")) {
      nepim_global.udp_mode                = 1; /* boolean */
      nepim_global.simplex_client_send     = 1; /* boolean */
      nepim_global.udp_keepalive_require   = 0; /* boolean */
      nepim_global.udp_require_greet_reply = 0; /* boolean */
      nepim_global.max_greetings           = 1; /* counter */
      continue;
    }

    if (!strcmp(arg, "-mM")) {
      nepim_global.report_partial_min_max = 1; /* boolean = true */
      continue;
    }

    if (!strcmp(arg, "-cmss")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing client TCP MSS\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.client_tcp_mss = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-smss")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing server TCP MSS\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.server_tcp_mss = atoi(argv[i]);
      continue;
    }

    if (!strncmp(arg, "-F", 2)) {
      nepim_global.udp_mode                = 1; /* -u (UDP) */
      nepim_global.simplex_client_send     = 1; /* -s (client-send) */
      nepim_global.udp_keepalive_require   = 0; /* boolean */
      nepim_global.udp_require_greet_reply = 0; /* boolean */
      nepim_global.max_greetings           = 0; /* counter */

      /* -Fa ? */
      if (strchr(arg + 1, 'a')) {
	nepim_global.udp_dst_random_addr = 1; /* 0=fixed,1=random */

	/* force -c */
	nepim_global.client_mode = 1;
	if (!nepim_global.hostname)
	  nepim_global.hostname = addr_list_append(nepim_global.hostname, "1.1.1.1");
      }

      /* -Fp ? */
      if (strchr(arg + 1, 'p')) {
	nepim_global.udp_dst_random_port = 1; /* 0=fixed,1=random */

	/* force -c */
	nepim_global.client_mode = 1;
	if (!nepim_global.hostname)
	  nepim_global.hostname = addr_list_append(nepim_global.hostname, "1.1.1.1");
      }

      continue;
    }

    if (!strcmp(arg, "-r")) {
      int bytes;
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing bit-rate\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.bit_rate = nepim_unit_ll(argv[i]);
      bytes = nepim_bps2bytes(nepim_global.bit_rate,
                              nepim_global.write_delay);
      if (bytes < 1) {
        long long min_bps = nepim_min_bps(nepim_global.write_delay);
        fprintf(stderr,
                "%s: bit-rate=%lld bps (bytes=%d) lower than minimum=%lld bps (for send-delay=%ld ms)\n",
                nepim_global.prog_name,
                nepim_global.bit_rate, bytes, min_bps, nepim_global.write_delay);
        exit(1);
      }
      assert(nepim_global.bit_rate >= nepim_min_bps(nepim_global.write_delay));
      continue;
    }

    if (!strcmp(arg, "-R")) {
      int pkts;
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing pkt-rate\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.pkt_rate = nepim_unit_int(argv[i]);
      pkts = nepim_pps2packets(nepim_global.pkt_rate,
                               nepim_global.write_delay);
      if (pkts < 1) {
        int min_pps = nepim_min_pps(nepim_global.write_delay);
        fprintf(stderr,
                "%s: pkt-rate=%d pps (pkts=%d) lower than min=%d pps (for send-delay=%ld ms)\n",
                nepim_global.prog_name, 
                nepim_global.pkt_rate, pkts, min_pps, nepim_global.write_delay);
        exit(1);
      }
      assert(nepim_global.pkt_rate >= nepim_min_pps(nepim_global.write_delay));
      continue;
    }

    if (!strcmp(arg, "-e")) {
      int pkts;
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing send-rate\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.pkt_rate = nepim_unit_int(argv[i]);

      if (nepim_global.pkt_rate < 1) {
        fprintf(stderr, "%s: excessively low send-rate: %d pps (min: 1 pps)\n",
                nepim_global.prog_name, nepim_global.pkt_rate);
	exit(1);
      }

      if (nepim_global.pkt_rate > NEPIM_MEGA) {
        fprintf(stderr, "%s: excessively high send-rate: %d pps (max: %d pps)\n",
                nepim_global.prog_name, nepim_global.pkt_rate, NEPIM_MEGA);
	exit(1);
      }

      nepim_global.write_delay = NEPIM_MEGA / nepim_global.pkt_rate;

      pkts = nepim_pps2packets(nepim_global.pkt_rate,
                               nepim_global.write_delay);
      if (pkts < 1) {
	++nepim_global.write_delay; /* fix rounding error */
#if 0
        fprintf(stderr,
                "ugh: pkt-rate=%d delay=%ld pkts=%d\n",
                nepim_global.pkt_rate, nepim_global.write_delay, pkts);
	assert(0);
        exit(1);
#endif
      }

      pkts = nepim_pps2packets(nepim_global.pkt_rate,
                               nepim_global.write_delay);
      assert(pkts >= 1);

      assert(nepim_global.pkt_rate >= nepim_min_pps(nepim_global.write_delay));

      continue;
    }

    if (!strcmp(arg, "-s")) {
      nepim_global.simplex_client_send = 1;
      continue;
    }

    if (!strcmp(arg, "-t")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing ttl\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.ttl = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-T")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing multicast-ttl\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.mcast_ttl = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-u")) {
      nepim_global.udp_mode = 1;
      continue;
    }

    if (!strcmp(arg, "-v")) {
      show_version(stdout);
      exit(0);
    }

    if (!strcmp(arg, "-V")) {
      nepim_global.verbose_stderr = stderr;
      continue;
    }

    if (!strcmp(arg, "-w")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing TCP write size\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.tcp_write_size = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-z")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing TCP read size\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.tcp_read_size = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-W")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing UDP write size\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.udp_write_size = atoi(argv[i]);
      if (nepim_global.udp_write_size < UDP_HEADER_LEN) {
        fprintf(stderr,
                "%s: %d is less than minimum UDP write size (%d)\n",
                nepim_global.prog_name, nepim_global.udp_write_size,
                UDP_HEADER_LEN);
        exit(1);
      }
      continue;
    }

    if (!strcmp(arg, "-Z")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing UDP read size\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.udp_read_size = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-l")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing listen backlog\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.listen_backlog = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-O")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing maximum socket send buffer size\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.win_send = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-I")) {
      ++i;
      if (i >= argc) {
        fprintf(stderr, "%s: missing maximum socket read buffer size\n",
                nepim_global.prog_name);
        exit(1);
      }
      nepim_global.win_recv = atoi(argv[i]);
      continue;
    }

    fprintf(stderr, "%s: unknown option: %s\n",
            nepim_global.prog_name, arg);
    usage(stderr, nepim_global.prog_name);
    exit(1);
  }

  show_version_brief(stderr);

  init_event_loop();

  if (nepim_global.client_mode) {

    if (nepim_global.udp_mode) {

      nepim_conf_write_sweep_auto(1 /* udp=true */,
				  &nepim_global.write_floor,
				  &nepim_global.write_ceil);

      if (nepim_global.write_floor < UDP_HEADER_LEN) {
        fprintf(stderr, "%s: excessively low UDP write sweep floor=%d (min=%d)\n",
                nepim_global.prog_name, nepim_global.write_floor, UDP_HEADER_LEN);
	exit(1);
      }

      if (nepim_global.write_ceil > nepim_global.udp_write_size) {
        fprintf(stderr, "%s: excessively high UDP write sweep ceil=%d (max=%d)\n",
                nepim_global.prog_name, nepim_global.write_ceil,
		nepim_global.udp_write_size);
	exit(1);
      }

      if (nepim_global.write_floor > nepim_global.write_ceil) {
        fprintf(stderr, "%s: UDP write sweep floor=%d higher than ceil=%d\n",
                nepim_global.prog_name,
		nepim_global.write_floor,
		nepim_global.write_ceil);
	exit(1);
      }

      assert(nepim_global.write_floor >= UDP_HEADER_LEN);
      assert(nepim_global.write_ceil <= nepim_global.udp_write_size);
      assert(nepim_global.write_floor <= nepim_global.write_ceil);

      fprintf(stderr, 
              "client: udp_read=%d udp_write=%d write_floor=%d write_ceil=%d\n",
              nepim_global.udp_read_size, nepim_global.udp_write_size,
	      nepim_global.write_floor, nepim_global.write_ceil);
    }
    else {

      nepim_conf_write_sweep_auto(0 /* udp=false */,
				  &nepim_global.write_floor,
				  &nepim_global.write_ceil);

      if (nepim_global.write_ceil > nepim_global.tcp_write_size) {
        fprintf(stderr, "%s: excessively high TCP write sweep ceil=%d (max=%d)\n",
                nepim_global.prog_name, nepim_global.write_ceil,
		nepim_global.tcp_write_size);
	exit(1);
      }

      if (nepim_global.write_floor > nepim_global.write_ceil) {
        fprintf(stderr, "%s: TCP write sweep floor=%d higher than ceil=%d\n",
                nepim_global.prog_name,
		nepim_global.write_floor,
		nepim_global.write_ceil);
	exit(1);
      }

      assert(nepim_global.write_floor >= 0);
      assert(nepim_global.write_ceil <= nepim_global.tcp_write_size);
      assert(nepim_global.write_floor <= nepim_global.write_ceil);

      fprintf(stderr, 
              "client: tcp_read=%d tcp_write=%d write_floor=%d write_ceil=%d step=%d\n",
              nepim_global.tcp_read_size, nepim_global.tcp_write_size,
	      nepim_global.write_floor, nepim_global.write_ceil,
	      nepim_global.sweep_step);
    }

    nepim_client_run();

    fprintf(stderr, "%s: done\n", nepim_global.prog_name);
    exit(0);
  }

  fprintf(stderr, 
          "server: tcp_read=%d tcp_write=%d udp_read=%d udp_write=%d\n",
          nepim_global.tcp_read_size,
          nepim_global.tcp_write_size,
          nepim_global.udp_read_size,
          nepim_global.udp_write_size);

  nepim_server_run();

#if 0
  /* requires previous fd de-registration */
  oop_sys_delete(nepim_global.oop_sys);
#endif

  fprintf(stderr, "%s: done\n", nepim_global.prog_name);
  exit(0);
}
