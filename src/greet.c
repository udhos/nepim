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

/* $Id: greet.c,v 1.23 2008/03/27 20:57:19 evertonm Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "conf.h"
#include "greet.h"
#include "common.h"

const char *GREET_SERVER_SEND       = "server_send=";
const char *GREET_BIT_RATE          = "bit_rate=";
const char *GREET_PKT_RATE          = "pkt_rate=";
const char *GREET_STAT_INTERVAL     = "stat_interval=";
const char *GREET_TEST_DURATION     = "test_duration=";
const char *GREET_WRITE_DELAY       = "write_delay=";
const char *GREET_SERVER_KA_SEND    = "server_ka_send=";
const char *GREET_SERVER_KA_REQUIRE = "server_ka_req=";
const char *GREET_SERVER_KA_TIMEOUT = "server_ka_tmout=";
const char *GREET_SERVER_KA_DELAY   = "server_ka_delay=";
const char *GREET_SEED              = "seed=";
const char *GREET_VERIFY_DATA       = "verify_data=";
const char *GREET_RANDOM_FILL       = "random_fill=";
const char *GREET_FILL_BYTE         = "fill_byte=";
const char *GREET_PAUSE_DURATION    = "pause_duration=";
const char *GREET_SOCKET_KEEPALIVE  = "sock_ka=";
const char *GREET_NAGLE             = "nagle=";
const char *GREET_OVERHEAD          = "overhead=";
const char *GREET_SWEEP_RANDOM      = "sweep_random=";
const char *GREET_SWEEP_STEP        = "sweep_step=";
const char *GREET_WRITE_FLOOR       = "write_floor=";
const char *GREET_WRITE_CEIL        = "write_ceil=";
const char *GREET_PARTIAL_MINMAX    = "partial_minmax=";
const char *GREET_MSS               = "mss=";
const char *GREET_PASSWORD          = "password=";

#define NEPIM_GREET_PARSE_OK     (0)
#define NEPIM_GREET_PARSE_FTOKEN (-1)
#define NEPIM_GREET_PARSE_HELLO  (-2)

#define NEPIM_GREET_WRITE_OK       (0)
#define NEPIM_GREET_WRITE_IO       (-1)
#define NEPIM_GREET_WRITE_OVERFLOW (-2)

int nepim_write_greetings(const nepim_greet_t *opt, char *buf, int buf_size)
{
  int pr;

  assert(opt->password_buf);
  assert(opt->password_buf_size > 0);
  assert(memchr(opt->password_buf, '\0', opt->password_buf_size));
  assert(strlen(opt->password_buf) >= 0);
  assert(strlen(opt->password_buf) < opt->password_buf_size);

  pr = snprintf(buf, buf_size,
                "hello"
		" %s%d %s%lld"
                " %s%d %s%d %s%d"
                " %s%ld %s%d %s%d %s%d %s%d"
		" %s0x%08x %s%d %s%d %s0x%02x %s%d"
		" %s%d %s%d %s%d"
		" %s%d %s%d %s%d %s%d"
		" %s%d"
		" %s%d"
		" %s%s\n", 
                GREET_SERVER_SEND,       opt->must_send,
                GREET_BIT_RATE,          opt->bit_rate,
                GREET_PKT_RATE,          opt->pkt_rate,
                GREET_STAT_INTERVAL,     opt->stat_interval,
                GREET_TEST_DURATION,     opt->test_duration,
                GREET_WRITE_DELAY,       opt->write_delay,
                GREET_SERVER_KA_SEND,    opt->keepalive_must_send,
                GREET_SERVER_KA_REQUIRE, opt->keepalive_require,
                GREET_SERVER_KA_TIMEOUT, opt->keepalive_timeout,
                GREET_SERVER_KA_DELAY,   opt->keepalive_send_delay,
                GREET_SEED,              opt->seed,
                GREET_VERIFY_DATA,       opt->verify_data,
                GREET_RANDOM_FILL,       opt->random_fill,
                GREET_FILL_BYTE,         opt->fill_byte,
                GREET_PAUSE_DURATION,    opt->pause_duration,
                GREET_SOCKET_KEEPALIVE,  opt->socket_keepalive,
                GREET_NAGLE,             opt->nagle,
		GREET_OVERHEAD,          opt->overhead,
		GREET_SWEEP_RANDOM,      opt->sweep_random,
		GREET_SWEEP_STEP,        opt->sweep_step,
		GREET_WRITE_FLOOR,       opt->write_floor,
		GREET_WRITE_CEIL,        opt->write_ceil,
		GREET_PARTIAL_MINMAX,    opt->report_partial_min_max,
		GREET_MSS,               opt->mss,
                GREET_PASSWORD,          opt->password_buf);

  if (pr < 1)
    return NEPIM_GREET_WRITE_IO;
  if (pr >= buf_size)
    return NEPIM_GREET_WRITE_OVERFLOW;

  assert(pr > 0);
  assert(pr < buf_size);

  return pr;
}

int nepim_parse_greetings(nepim_greet_t *opt, int is_tcp,
                          const char *buf, const char *past_end)
{
  char tmp[past_end - buf + 1];
  const char *SEP = " ";
  const char *tok;
  char *ptr;

  const int GREET_SERVER_SEND_LEN       = strlen(GREET_SERVER_SEND);
  const int GREET_BIT_RATE_LEN          = strlen(GREET_BIT_RATE);
  const int GREET_PKT_RATE_LEN          = strlen(GREET_PKT_RATE);
  const int GREET_STAT_INTERVAL_LEN     = strlen(GREET_STAT_INTERVAL);
  const int GREET_TEST_DURATION_LEN     = strlen(GREET_TEST_DURATION);
  const int GREET_WRITE_DELAY_LEN       = strlen(GREET_WRITE_DELAY);
  const int GREET_SERVER_KA_SEND_LEN    = strlen(GREET_SERVER_KA_SEND);
  const int GREET_SERVER_KA_REQUIRE_LEN = strlen(GREET_SERVER_KA_REQUIRE);
  const int GREET_SERVER_KA_TIMEOUT_LEN = strlen(GREET_SERVER_KA_TIMEOUT);
  const int GREET_SERVER_KA_DELAY_LEN   = strlen(GREET_SERVER_KA_DELAY);
  const int GREET_SEED_LEN              = strlen(GREET_SEED);
  const int GREET_VERIFY_DATA_LEN       = strlen(GREET_VERIFY_DATA);
  const int GREET_RANDOM_FILL_LEN       = strlen(GREET_RANDOM_FILL);
  const int GREET_FILL_BYTE_LEN         = strlen(GREET_FILL_BYTE);
  const int GREET_PAUSE_DURATION_LEN    = strlen(GREET_PAUSE_DURATION);
  const int GREET_SOCKET_KEEPALIVE_LEN  = strlen(GREET_SOCKET_KEEPALIVE);
  const int GREET_NAGLE_LEN             = strlen(GREET_NAGLE);
  const int GREET_OVERHEAD_LEN          = strlen(GREET_OVERHEAD);
  const int GREET_SWEEP_RANDOM_LEN      = strlen(GREET_SWEEP_RANDOM);
  const int GREET_SWEEP_STEP_LEN        = strlen(GREET_SWEEP_STEP);
  const int GREET_WRITE_FLOOR_LEN       = strlen(GREET_WRITE_FLOOR);
  const int GREET_WRITE_CEIL_LEN        = strlen(GREET_WRITE_CEIL);
  const int GREET_PARTIAL_MINMAX_LEN    = strlen(GREET_PARTIAL_MINMAX);
  const int GREET_MSS_LEN               = strlen(GREET_MSS);
  const int GREET_PASSWORD_LEN          = strlen(GREET_PASSWORD);

  int       server_send       = -2;
  long long bit_rate          = -2;
  int       pkt_rate          = -2;
  int       stat_interval     = -2;
  int       test_duration     = -2;
  long      write_delay       = -2;
  int       server_ka_send    = -2;
  int       server_ka_require = -2;
  int       server_ka_timeout = -2;
  int       server_ka_delay   = -2;
  unsigned  seed              = -2;
  int       verify_data       = -2;
  int       random_fill       = -2;
  unsigned  fill_byte         = -2;
  int       pause_duration    = -2;
  int       socket_keepalive  = -2;
  int       nagle             = -2;
  int       overhead          = -2;
  int       sweep_random      = -2;
  int       sweep_step        = -55555; /* something obviously wrong (-2 is too sane) */
  int       write_floor       = -2;
  int       write_ceil        = -2;
  int       partial_minmax    = -2;
  int       mss               = -2;

  assert(opt->password_buf);
  assert(opt->password_buf_size > 0);
  *opt->password_buf = '\0';

  memcpy(tmp, buf, past_end - buf + 1);

  tok = strtok_r(tmp, SEP, &ptr);

  if (!tok)
    return NEPIM_GREET_PARSE_FTOKEN;

  if (strncmp(tok, "hello", 5))
    return NEPIM_GREET_PARSE_HELLO;

  for (;;) {
    tok = strtok_r(0, SEP, &ptr);
    if (!tok)
      break;

    if (!strncmp(tok, GREET_SERVER_SEND, GREET_SERVER_SEND_LEN)) {
      server_send = atoi(tok + GREET_SERVER_SEND_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_BIT_RATE, GREET_BIT_RATE_LEN)) {
      bit_rate = strtoll(tok + GREET_BIT_RATE_LEN, 0, 10);
      continue;
    }

    if (!strncmp(tok, GREET_PKT_RATE, GREET_PKT_RATE_LEN)) {
      pkt_rate = strtoll(tok + GREET_PKT_RATE_LEN, 0, 10);
      continue;
    }

    if (!strncmp(tok, GREET_STAT_INTERVAL, GREET_STAT_INTERVAL_LEN)) {
      stat_interval = atoi(tok + GREET_STAT_INTERVAL_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_TEST_DURATION, GREET_TEST_DURATION_LEN)) {
      test_duration = atoi(tok + GREET_TEST_DURATION_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_WRITE_DELAY, GREET_WRITE_DELAY_LEN)) {
      write_delay = atoi(tok + GREET_WRITE_DELAY_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SERVER_KA_SEND, GREET_SERVER_KA_SEND_LEN)) {
      server_ka_send = atoi(tok + GREET_SERVER_KA_SEND_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SERVER_KA_REQUIRE, GREET_SERVER_KA_REQUIRE_LEN)) {
      server_ka_require = atoi(tok + GREET_SERVER_KA_REQUIRE_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SERVER_KA_TIMEOUT, GREET_SERVER_KA_TIMEOUT_LEN)) {
      server_ka_timeout = atoi(tok + GREET_SERVER_KA_TIMEOUT_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SERVER_KA_DELAY, GREET_SERVER_KA_DELAY_LEN)) {
      server_ka_delay = atoi(tok + GREET_SERVER_KA_DELAY_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SEED, GREET_SEED_LEN)) {
      if (sscanf(tok + GREET_SEED_LEN, "%x", &seed) != 1) {
        fprintf(stderr, "%s: illegal seed value\n",
                nepim_global.prog_name);
        exit(1);
      }
      continue;
    }

    if (!strncmp(tok, GREET_VERIFY_DATA, GREET_VERIFY_DATA_LEN)) {
      verify_data = atoi(tok + GREET_VERIFY_DATA_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_RANDOM_FILL, GREET_RANDOM_FILL_LEN)) {
      random_fill = atoi(tok + GREET_RANDOM_FILL_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_FILL_BYTE, GREET_FILL_BYTE_LEN)) {
      if ((sscanf(tok + GREET_FILL_BYTE_LEN, "%x", &fill_byte) != 1) ||
          (fill_byte > 0xff)) {
        fprintf(stderr, "%s: illegal fill byte value\n",
                nepim_global.prog_name);
        exit(1);
      }
      continue;
    }

    if (!strncmp(tok, GREET_PAUSE_DURATION, GREET_PAUSE_DURATION_LEN)) {
      pause_duration = atoi(tok + GREET_PAUSE_DURATION_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SOCKET_KEEPALIVE, GREET_SOCKET_KEEPALIVE_LEN)) {
      socket_keepalive = atoi(tok + GREET_SOCKET_KEEPALIVE_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_NAGLE, GREET_NAGLE_LEN)) {
      nagle = atoi(tok + GREET_NAGLE_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_OVERHEAD, GREET_OVERHEAD_LEN)) {
      overhead = atoi(tok + GREET_OVERHEAD_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SWEEP_RANDOM, GREET_SWEEP_RANDOM_LEN)) {
      sweep_random = atoi(tok + GREET_SWEEP_RANDOM_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_SWEEP_STEP, GREET_SWEEP_STEP_LEN)) {
      sweep_step = atoi(tok + GREET_SWEEP_STEP_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_WRITE_FLOOR, GREET_WRITE_FLOOR_LEN)) {
      write_floor = atoi(tok + GREET_WRITE_FLOOR_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_WRITE_CEIL, GREET_WRITE_CEIL_LEN)) {
      write_ceil = atoi(tok + GREET_WRITE_CEIL_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_PARTIAL_MINMAX, GREET_PARTIAL_MINMAX_LEN)) {
      partial_minmax = atoi(tok + GREET_PARTIAL_MINMAX_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_MSS, GREET_MSS_LEN)) {
      mss = atoi(tok + GREET_MSS_LEN);
      continue;
    }

    if (!strncmp(tok, GREET_PASSWORD, GREET_PASSWORD_LEN)) {
      const char *tmp_past_end = tmp + sizeof(tmp);
      const char *pass;
      const char *end;
      int pass_len;
      int rem;

      pass = tok + GREET_PASSWORD_LEN;
      rem = tmp_past_end - pass;
      end = memchr(pass, ' ', rem);
      if (!end)
        end = memchr(pass, '\0', rem);
      if (!end)
        end = tmp_past_end;
      
      pass_len = NEPIM_MIN(opt->password_buf_size - 1, end - pass);

      assert(pass_len >= 0);
      assert(pass_len < opt->password_buf_size);

      memcpy(opt->password_buf, pass, pass_len);
      opt->password_buf[pass_len] = '\0';

      assert(memchr(opt->password_buf, '\0', opt->password_buf_size));
      assert(strlen(opt->password_buf) >= 0);
      assert(strlen(opt->password_buf) < opt->password_buf_size);
      assert(strlen(opt->password_buf) == pass_len);

      continue;
    }

    fprintf(stderr, "%s %s: unknown greeting parameter: '%s'\n",
            __FILE__, __PRETTY_FUNCTION__, tok);
  }

  assert(memchr(opt->password_buf, '\0', opt->password_buf_size));
  assert(strlen(opt->password_buf) >= 0);
  assert(strlen(opt->password_buf) < opt->password_buf_size);

  if (write_delay < 0)
    write_delay = nepim_global.write_delay;

  if (is_tcp) {
    if (server_ka_timeout == -2) {
      server_ka_timeout = nepim_global.tcp_keepalive_recv_timer;
    }
    if (server_ka_delay == -2) {
      server_ka_delay = nepim_global.tcp_keepalive_send_delay;
    }
  }
  else {
    if (server_ka_timeout == -2) {
      server_ka_timeout = nepim_global.udp_keepalive_recv_timer;
    }
    if (server_ka_delay == -2) {
      server_ka_delay = nepim_global.udp_keepalive_send_delay;
    }
  }

  opt->must_send              = server_send;
  opt->bit_rate               = bit_rate;
  opt->pkt_rate               = pkt_rate;
  opt->stat_interval          = stat_interval;
  opt->test_duration          = test_duration;
  opt->write_delay            = write_delay;
  opt->keepalive_must_send    = server_ka_send;
  opt->keepalive_require      = server_ka_require;
  opt->keepalive_timeout      = server_ka_timeout;
  opt->keepalive_send_delay   = server_ka_delay;
  opt->seed                   = seed;
  opt->verify_data            = verify_data;
  opt->random_fill            = random_fill;
  opt->fill_byte              = (unsigned char) fill_byte;
  opt->pause_duration         = pause_duration;
  opt->socket_keepalive       = socket_keepalive;
  opt->nagle                  = nagle;
  opt->overhead               = overhead;
  opt->sweep_random           = sweep_random;
  opt->sweep_step             = sweep_step;
  opt->write_floor            = write_floor;
  opt->write_ceil             = write_ceil;
  opt->report_partial_min_max = (partial_minmax == -2) ? 0 : partial_minmax;
  opt->mss                    = mss;

  return NEPIM_GREET_PARSE_OK;
}
