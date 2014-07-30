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

/* $Id: sock.c,v 1.57 2008/11/26 15:46:14 evertonm Exp $ */

#include <assert.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <stdlib.h>
#include <ctype.h>
#include <net/if.h>

#include "sock.h"
#include "conf.h"

#ifndef SOL_IP
#define SOL_IP 0
#endif
#ifndef SOL_IPV6
#define SOL_IPV6 41
#endif
#ifndef SOL_TCP
#define SOL_TCP 6
#endif
#ifndef IP_MTU
#define IP_MTU 14
#endif
#ifndef IP_ADD_MEMBERSHIP
#define IP_ADD_MEMBERSHIP 35
#endif
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP 20
#endif
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif

#ifndef HAVE_IP_MREQN
struct ip_mreqn {
  struct in_addr imr_multiaddr;
  struct in_addr imr_address;
  int            imr_ifindex;
};
#endif

#ifndef HAVE_IP_MREQ
struct ip_mreq {
  struct in_addr imr_multiaddr; /* group to join */
  struct in_addr imr_interface; /* interface to join on */
}  
#endif

#ifndef HAVE_IPV6_MREQ
struct ipv6_mreq {
  struct in6_addr ipv6mr_multiaddr;
  int             ipv6mr_ifindex;
};
#endif

#ifndef HAVE_GROUP_SOURCE_REQ
struct group_source_req {
  uint32_t                gsr_interface; 
  struct sockaddr_storage gsr_group;
  struct sockaddr_storage gsr_source;
};
#endif /* HAVE_GROUP_SOURCE_REQ */

#define NEPIM_SOCK_ERR_NONE           (0)
#define NEPIM_SOCK_ERR_UNSPEC         (-1)
#define NEPIM_SOCK_ERR_SOCKET         (-2)
#define NEPIM_SOCK_ERR_BIND           (-3)
#define NEPIM_SOCK_ERR_LISTEN         (-4)
#define NEPIM_SOCK_ERR_CONNECT        (-5)
#define NEPIM_SOCK_ERR_BLOCK          (-6)
#define NEPIM_SOCK_ERR_UNBLOCK        (-7)
#define NEPIM_SOCK_ERR_UNLINGER       (-8)
#define NEPIM_SOCK_ERR_REUSE          (-9)
#define NEPIM_SOCK_ERR_NODELAY        (-10)
#define NEPIM_SOCK_ERR_PMTU           (-11)
#define NEPIM_SOCK_ERR_TTL            (-12)
#define NEPIM_SOCK_ERR_MCAST_TTL      (-13)
#define NEPIM_SOCK_ERR_MCAST_JOIN     (-14)
#define NEPIM_SOCK_ERR_MCAST_JOIN_SOURCEGROUP (-15)
#define NEPIM_SOCK_ERR_WIN_RECV               (-16)
#define NEPIM_SOCK_ERR_WIN_SEND               (-17)
#define NEPIM_SOCK_ERR_TOS                    (-18)
#define NEPIM_SOCK_ERR_SOCK_KA                (-19)
#define NEPIM_SOCK_ERR_MSS                    (-20)
#define NEPIM_SOCK_ERR_MCAST_JOIN_IFACE       (-21)
#define NEPIM_SOCK_ERR_RA                     (-22)

int nepim_sock_get_port(const struct sockaddr *addr)
{
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
  } *sa = (void *) addr;

  if (nepim_sock_family(addr) == AF_UNIX)
    return -1; /* something obviously invalid */

  assert(&(sa->inet.sin_port) == &(sa->inet6.sin6_port));
  assert(sa->inet.sin_port == sa->inet6.sin6_port);

  return ntohs(sa->inet.sin_port);
}

void nepim_sock_set_port(const struct sockaddr *addr, int port)
{
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
  } *sa = (void *) addr;

  assert(nepim_sock_family(addr) != AF_UNIX);

  assert(&(sa->inet.sin_port) == &(sa->inet6.sin6_port));
  assert(sa->inet.sin_port == sa->inet6.sin6_port);

  sa->inet.sin_port = htons(port);
}

int nepim_sock_family(const struct sockaddr *addr)
{
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
    struct sockaddr_un un;
  } *sa = (void *) addr;

  assert(&(sa->inet.sin_family) == &(sa->inet6.sin6_family));
  assert(sa->inet.sin_family == sa->inet6.sin6_family);

  assert(&(sa->inet.sin_family) == &(sa->un.sun_family));
  assert(sa->inet.sin_family == sa->un.sun_family);

  return sa->inet.sin_family;
}

int nepim_sock_addrlen(const struct sockaddr *addr)
{
  switch (nepim_sock_family(addr)) {
  case PF_INET:  return sizeof(struct sockaddr_in);
  case PF_INET6: return sizeof(struct sockaddr_in6);
  default:
    assert(0);
  }
  assert(0);
  return -1;
}

void nepim_sock_dump_addr(char *buf, int buf_size,
			  const struct sockaddr *addr,
			  int addr_len)
{
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
    struct sockaddr_un un;
  } *sa;
  const char *dst;
  int family;

  if (addr_len < 3) {
    assert(buf_size >= 2);
    snprintf(buf, buf_size, "?");
    return;
  }

  family = nepim_sock_family(addr);

  assert(PF_INET == AF_INET);
  assert(PF_INET6 == AF_INET6);

  sa = (void *) addr;

  switch (family) {
  case PF_INET:
    assert(buf_size >= INET_ADDRSTRLEN);
    dst = inet_ntop(family, &sa->inet.sin_addr, buf, buf_size);
    break;
  case PF_INET6:
    assert(buf_size >= INET6_ADDRSTRLEN);
    dst = inet_ntop(family, &sa->inet6.sin6_addr, buf, buf_size);
    break;
  case PF_UNIX:
    assert(buf_size > strlen(sa->un.sun_path));
    strcpy(buf, sa->un.sun_path);
    return; /* skip code below */
  default:
    assert(0);
  }

#ifndef NDEBUG
  {
    if (!dst) {
      fprintf(stderr,
	      "%s %s: inet_ntop() failure: errno=%d %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      errno, strerror(errno));
    }
  }
#endif /* NDEBUG */

  assert(dst);
  assert(dst == buf);
}

int nepim_socket_block(int sd)
{
  long flags;

  flags = fcntl(sd, F_GETFL, 0);
  if (flags == -1)
    return NEPIM_SOCK_ERR_BLOCK;
  assert(flags >= 0);
  if (fcntl(sd, F_SETFL, flags & ~O_NONBLOCK))
    return NEPIM_SOCK_ERR_BLOCK;

  return NEPIM_SOCK_ERR_NONE;
}

int nepim_socket_nonblock(int sd)
{
  long flags;

  flags = fcntl(sd, F_GETFL, 0);
  if (flags == -1)
    return NEPIM_SOCK_ERR_UNBLOCK;
  assert(flags >= 0);
  if (fcntl(sd, F_SETFL, flags | O_NONBLOCK))
    return NEPIM_SOCK_ERR_UNBLOCK;

  return NEPIM_SOCK_ERR_NONE;
}

int nepim_socket_pmtu(int sd, int pmtu_mode)
{
  if (pmtu_mode < 0)
    return NEPIM_SOCK_ERR_NONE;

#ifdef IP_MTU_DISCOVER
  return setsockopt(sd, SOL_IP, IP_MTU_DISCOVER, &pmtu_mode, sizeof(pmtu_mode));
#else
  return NEPIM_SOCK_ERR_NONE;
#endif
}

int nepim_socket_ttl(int sd, int ttl)
{
  if (ttl < 0)
    return NEPIM_SOCK_ERR_NONE;

  return setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
}

int nepim_socket_mcast_ttl(int sd, int mc_ttl)
{
#ifdef HAVE_UCHAR_MCAST_TTL
  unsigned char mcast_ttl;
#else
  int mcast_ttl;
#endif

  if (mc_ttl < 0)
    return NEPIM_SOCK_ERR_NONE;

  assert(mc_ttl >= 0);
  assert(mc_ttl < 256);

  mcast_ttl = mc_ttl;

  return setsockopt(sd, SOL_IP, IP_MULTICAST_TTL, &mcast_ttl, sizeof(mcast_ttl));
}

static int socket_set_win_recv(int sd, int win_recv)
{
  if (win_recv < 0)
    return NEPIM_SOCK_ERR_NONE;

  if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &win_recv, sizeof(win_recv)))
    return NEPIM_SOCK_ERR_WIN_RECV;

  return NEPIM_SOCK_ERR_NONE;
}

static int socket_set_win_send(int sd, int win_send)
{
  if (win_send < 0)
    return NEPIM_SOCK_ERR_NONE;

  if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &win_send, sizeof(win_send)))
    return NEPIM_SOCK_ERR_WIN_SEND;
  
  return NEPIM_SOCK_ERR_NONE;
}

int nepim_socket_tos(FILE *err, int sd, int tos)
{
  if (tos < 0)
    return NEPIM_SOCK_ERR_NONE;

  if (setsockopt(sd, SOL_IP, IP_TOS, &tos, sizeof(tos))) {

    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: setsockopt: tos=%d (0x%02x): sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      tos, tos, sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_TOS;
  }

  return NEPIM_SOCK_ERR_NONE;
}

/* Set IP router alert option (RFC 2113) */
static int socket_set_ra(FILE *err, int sd)
{
  char ra[4];

  ra[0] = 148;
  ra[1] = 4;
  ra[2] = 0;
  ra[3] = 0;

  if (setsockopt(sd, IPPROTO_IP, IP_OPTIONS, ra, 4)) {

    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: setsockopt(RA): sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_RA;
  }

  return NEPIM_SOCK_ERR_NONE;
}

static const char *family_name(int family)
{
  switch (family) {
  case AF_INET:
    return "inet";
  case AF_INET6:
    return "inet6";
  }

  return "unknown_family";
}

static const char *socket_type_name(int type)
{
  switch (type) {
  case SOCK_STREAM:
    return "stream";
  case SOCK_DGRAM:
    return "datagram";
  }

  return "unknown_socket_type";
}

static const char *proto_name(int proto)
{
  struct protoent *pe;

  pe = getprotobynumber(proto);
  if (pe)
    return pe->p_name;

  return "unknown_protocol";
}

static int create_socket(FILE *err, int domain, int type, int protocol,
			 int pmtu_mode, int ttl, int win_recv,
			 int win_send, int nodelay, int tos, int mss,
			 int ra)
{
  int sd;
  int result;

  sd = socket(domain, type, protocol);
  if (sd < 0) {
    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: socket(%s,%s,%s): errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      family_name(domain), socket_type_name(type),
	      proto_name(protocol),
	      e, strerror(e));
    }

    return NEPIM_SOCK_ERR_SOCKET;
  }

  if (type == SOCK_STREAM) {
    result = nepim_socket_tcp_opt(err, domain, sd, nodelay, mss);
    if (result) {
      close(sd);
      return result;
    }
  }

  result = nepim_socket_opt(err, sd, pmtu_mode, ttl, tos, ra);
  if (result) {
    close(sd);
    return result;
  }

  result = socket_set_win_recv(sd, win_recv);
  if (result) {
    close(sd);
    return result;
  }

  result = socket_set_win_send(sd, win_send);
  if (result) {
    close(sd);
    return result;
  }

  return sd;
}

static int iface_solve_index(const char *ifname)
{
  struct if_nameindex *ini;
  int ifindex = -1;
  int i;

  assert(ifname);

  ini = if_nameindex();
  if (!ini) {
    if (nepim_global.verbose_stderr) {
      int err = errno;
      fprintf(nepim_global.verbose_stderr,
	      "%s: %s: interface=%s: failure solving index: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      ifname, err, strerror(err));
      errno = err;
    }
    return -1;
  }

  for (i = 0; ini[i].if_index; ++i) {
    if (nepim_global.verbose_stderr) {
      fprintf(nepim_global.verbose_stderr,
	      "%s: %s: interface=%s matching against local ifname=%s ifindex=%d\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      ifname, ini[i].if_name, ini[i].if_index);
    }
    if (!strcmp(ini[i].if_name, ifname)) {
      ifindex = ini[i].if_index;
      break;
    }
  }

  if_freenameindex(ini);

  return ifindex;
}

static int iface_solve_addr4(struct in_addr *ifaddr,
			     const char *ifhost)
{
  struct addrinfo hints;
  struct addrinfo *ai_res;
  struct addrinfo *ai;
  int result;

  assert(ifaddr);

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_INET;
  hints.ai_addrlen = 0;
  hints.ai_addr = 0;
  hints.ai_canonname = 0;

  result = getaddrinfo(ifhost, 0, &hints, &ai_res);
  if (result)
    return -1;

  for (ai = ai_res; ai; ai = ai->ai_next) {
    if (ai->ai_family != PF_INET)
      continue;

    memcpy(ifaddr, &((struct sockaddr_in *) ai->ai_addr)->sin_addr, sizeof(*ifaddr));
    break;
  }

  freeaddrinfo(ai_res);
  return !ai;
}

static int iface_solve(int *ifindex,
		       struct in_addr *ifaddr,
		       const char *iface)
{
  int result;
  long value;
  const char *i;

  assert(ifindex);
  assert(ifaddr);
  assert(iface);

  /* option 1: interface literal index */
  for (i = iface;;++i) {
    int c = *i;
    /* eos? */
    if (!c) {
      errno = 0;
      value = strtol(iface, 0, 10);
      if (!errno) {
	*ifindex = value;
	ifaddr->s_addr = htons(INADDR_ANY);
	return 0;
      }
      break;
    }
    /* bad number? */
    if (!isdigit(c)) {
      errno = EINVAL;
      if (nepim_global.verbose_stderr)
	fprintf(nepim_global.verbose_stderr,
		"%s: %s: interface=%s: not a literal interface index: errno=%d: %s\n",
		__FILE__, __PRETTY_FUNCTION__, iface, errno, strerror(errno));
      break;
    }
  }
  
  /* option 2: interface name to index */
  result = iface_solve_index(iface);
  if (result >= 0) {
    *ifindex = result;
    ifaddr->s_addr = htons(INADDR_ANY);
    return 0;
  }
  if (nepim_global.verbose_stderr)
    fprintf(nepim_global.verbose_stderr,
	    "%s: %s: interface=%s: not an interface name\n",
	    __FILE__, __PRETTY_FUNCTION__, iface);

  /* option 3: interface address */
  /*
    only for PF_INET, since PF_INET6 relies on ifindex
  */
  result = iface_solve_addr4(ifaddr, iface);
  if (!result) {
    *ifindex = 0;
    return 0;
  }

  if (nepim_global.verbose_stderr)
    fprintf(nepim_global.verbose_stderr,
	    "%s: %s: interface=%s: not an interface address\n",
	    __FILE__, __PRETTY_FUNCTION__,
	    iface);

  *ifindex = -1;
  ifaddr->s_addr = htons(INADDR_ANY);
  
  return -1;
}

static int socket_mcast_join(int sd, int family,
			     const struct sockaddr *addr,
			     const char *iface)
{
  union {
    struct sockaddr_in inet;
    struct sockaddr_in6 inet6;
  } *sa = (void *) addr;
  struct in_addr ifaddr;
  int ifindex;
  int result;

  if (iface) { 
    ifindex = -1;
    if (iface_solve(&ifindex, &ifaddr, iface)) {

      if (nepim_global.verbose_stderr)
	fprintf(nepim_global.verbose_stderr,
		"%s %s: failure solving interface=%s: ifaddr=%s ifindex=%d\n",
		__FILE__, __PRETTY_FUNCTION__,
		iface ? iface : "any",
		inet_ntoa(ifaddr), ifindex);

      errno = ENODEV;
      return NEPIM_SOCK_ERR_MCAST_JOIN_IFACE;
    }
  }
  else {
    ifindex = 0;
    ifaddr.s_addr = htons(INADDR_ANY);
  }

  switch (family) {
  case PF_INET:
    {
#ifdef HAVE_IP_MREQN
      struct ip_mreqn opt;
      opt.imr_multiaddr = sa->inet.sin_addr;
      opt.imr_ifindex = ifindex;
      opt.imr_address = ifaddr;
      result = setsockopt(sd, SOL_IP, IP_ADD_MEMBERSHIP, &opt, sizeof(opt));
#else
      struct ip_mreq opt;
      opt.imr_multiaddr = sa->inet.sin_addr;
      opt.imr_interface = ifaddr;
      result = setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &opt, sizeof(opt));
#endif
    }
    break;
  case PF_INET6:
    {
      struct ipv6_mreq opt;

      opt.ipv6mr_interface = ifindex;
      assert(sizeof(opt.ipv6mr_multiaddr.s6_addr) == 
	     sizeof(sa->inet6.sin6_addr.s6_addr));
      memcpy(&opt.ipv6mr_multiaddr.s6_addr, 
	     &sa->inet6.sin6_addr.s6_addr, 
	     sizeof(opt.ipv6mr_multiaddr.s6_addr));

      result = setsockopt(sd, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &opt, sizeof(opt));
    }
    break;
  default:
    assert(0);
  }

  if (result) {
    int err = errno;

    if (nepim_global.verbose_stderr) {
      char buf_grp[300];

      nepim_sock_dump_addr(buf_grp, sizeof(buf_grp), addr, nepim_sock_addrlen(addr));

      fprintf(nepim_global.verbose_stderr,
	      "%s %s: failure joining %s@%s ifaddr=%s ifindex=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      buf_grp, iface ? iface : "any",
	      inet_ntoa(ifaddr), ifindex,
	      err, strerror(err));
    }
  
    errno = err;
  }

  return result;
}

static int socket_mcast_join_sourcegroup(int sd, int family,
					 const struct sockaddr *src,
					 const struct sockaddr *grp,
					 const char *iface)
{
  struct group_source_req group_source_req;
  struct in_addr ifaddr;
  int result;
  int ifindex;

  if (iface) { 
    ifindex = -1;
    if (iface_solve(&ifindex, &ifaddr, iface)) {

      if (nepim_global.verbose_stderr)
	fprintf(nepim_global.verbose_stderr,
		"%s %s: failure solving interface=%s: ifaddr=%s ifindex=%d\n",
		__FILE__, __PRETTY_FUNCTION__,
		iface ? iface : "any",
		inet_ntoa(ifaddr), ifindex);
      
      errno = ENODEV;
      return NEPIM_SOCK_ERR_MCAST_JOIN_IFACE;
    }

    /* got null ifindex while user didn't request it explicitely? */
    if (!ifindex && strcmp(iface, "0")) {

      if (nepim_global.verbose_stderr)
	fprintf(nepim_global.verbose_stderr,
		"%s %s: could not find non-null ifindex for interface=%s: ifaddr=%s ifindex=%d\n",
		__FILE__, __PRETTY_FUNCTION__,
		iface ? iface : "any",
		inet_ntoa(ifaddr), ifindex);
	
      errno = ENOTSUP;
      return NEPIM_SOCK_ERR_MCAST_JOIN_IFACE;
    }
  }
  else {
    ifindex = 0;
  }

  if (ifindex < 0) {
    fprintf(stderr,
	    "%s: %s: interface=%s ifaddr=%s index=%d: could not find interface index (FIXME: ifaddr => index)\n",
	    __FILE__, __PRETTY_FUNCTION__, iface, inet_ntoa(ifaddr), ifindex);
    errno = ENODEV;
    return NEPIM_SOCK_ERR_MCAST_JOIN_IFACE;
  }

  group_source_req.gsr_interface = ifindex;

  switch (family) {
  case PF_INET:
    {

      assert(sizeof(group_source_req.gsr_source) >= sizeof(struct sockaddr_in));
      assert(sizeof(group_source_req.gsr_group) >= sizeof(struct sockaddr_in));

      memcpy(&group_source_req.gsr_source, src, sizeof(struct sockaddr_in));
      memcpy(&group_source_req.gsr_group, grp, sizeof(struct sockaddr_in));

      result = setsockopt(sd, SOL_IP, MCAST_JOIN_SOURCE_GROUP,
			  &group_source_req, sizeof(group_source_req));
      break;
    }
  case PF_INET6:
    {
      assert(sizeof(group_source_req.gsr_source) >= sizeof(struct sockaddr_in6));
      assert(sizeof(group_source_req.gsr_group) >= sizeof(struct sockaddr_in6));

      memcpy(&group_source_req.gsr_source, src, sizeof(struct sockaddr_in6));
      memcpy(&group_source_req.gsr_group, grp, sizeof(struct sockaddr_in6));

      result = setsockopt(sd, SOL_IPV6, MCAST_JOIN_SOURCE_GROUP,
			  &group_source_req, sizeof(group_source_req));
      break;
    }
  default:
    assert(0);
  }

  if (result) {
    int err = errno;

    if (nepim_global.verbose_stderr) {
      char buf_src[300];
      char buf_grp[300];

      nepim_sock_dump_addr(buf_src, sizeof(buf_src), src, nepim_sock_addrlen(src));
      nepim_sock_dump_addr(buf_grp, sizeof(buf_grp), grp, nepim_sock_addrlen(grp));

      fprintf(nepim_global.verbose_stderr,
	      "%s %s: failure joining %s+%s@%s ifaddr=%s ifindex=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      buf_src, buf_grp, iface ? iface : "any",
	      inet_ntoa(ifaddr),
	      group_source_req.gsr_interface,
	      err,
	      strerror(err));
    }
  
    errno = err;
  }

  return result;
}

int nepim_create_socket(FILE *err,
			const struct sockaddr *addr, int addr_len,
			int family,
			int type,
			int protocol,
			int pmtu_mode,
			int ttl,
			int mcast_join,
			int win_recv,
			int win_send,
			int nodelay,
			int tos,
			int mss,
			int ra,
			const char *iface,
			const struct sockaddr *ssm_src_addr,
			int ssm_src_addrlen)
{
  int sd;
  int result;

  sd = create_socket(err, family, type, protocol, pmtu_mode, ttl,
		     win_recv, win_send, nodelay, tos, mss, ra);
  if (sd < 0)
    return sd;

#if 0
  {
    char buf1[500];
    char buf2[500];
    nepim_sock_dump_addr(buf1, sizeof(buf1), ssm_src_addr, ssm_src_addrlen);
    nepim_sock_dump_addr(buf2, sizeof(buf2), addr, addr_len);
    fprintf(stderr, "DEBUG %s %s: mcast_join=%d mcast_join_sourcegroup(%d,%s,%s,%d,%s)\n",
	    __FILE__, __PRETTY_FUNCTION__,
	    mcast_join, sd, buf1, buf2, nepim_sock_get_port(addr),
	    iface ? iface : "any");
  }
#endif

  if (mcast_join) {
    assert(type == SOCK_DGRAM);

    /* Linux 2.4 getaddrinfo yields IPPROTO_UDP */
    /* Solaris 10 getaddrinfo yields IPPROTO_IP */
    assert(protocol == IPPROTO_IP || protocol == IPPROTO_UDP);

    /* SSM join (S,G) ? */
    if (ssm_src_addr) {

      if (socket_mcast_join_sourcegroup(sd, family, ssm_src_addr, addr, iface)) {
	
	if (err) {
	  char buf1[500];
	  char buf2[500];
	  int e = errno;
	  
	  nepim_sock_dump_addr(buf1, sizeof(buf1), ssm_src_addr, ssm_src_addrlen);
	  nepim_sock_dump_addr(buf2, sizeof(buf2), addr, addr_len);
	  
	  fprintf(err, "%s: %s: mcast_join_sourcegroup(%d,%s,%s,%d,%s): errno=%d: %s\n",
		  __FILE__, __PRETTY_FUNCTION__,
		  sd, buf1, buf2, nepim_sock_get_port(addr),
		  iface ? iface : "any",
		  e, strerror(e));
	}
	
	close(sd);
	return NEPIM_SOCK_ERR_MCAST_JOIN_SOURCEGROUP;
      }
    } /* ssm_src_addr */
    
      /* Regular mcast join (*,G) */
    else if (socket_mcast_join(sd, family, addr, iface)) {

      if (err) {
	char buf[500];
	int e = errno;

	nepim_sock_dump_addr(buf, sizeof(buf), addr, addr_len);

	fprintf(err, "%s: %s: mcast_join(%d,%s,%d,%s): errno=%d: %s\n",
		__FILE__, __PRETTY_FUNCTION__,
		sd, buf, nepim_sock_get_port(addr),
		iface ? iface : "any",
		e, strerror(e));
      }

      close(sd);
      return NEPIM_SOCK_ERR_MCAST_JOIN;
    }
  }

  result = nepim_socket_nonblock(sd);
  if (result) {
    close(sd);
    return result;
  }

  if (!addr)
    return sd;

  if (bind(sd, addr, addr_len)) {

    if (err) {
      char buf[500];
      int e = errno;
      
      nepim_sock_dump_addr(buf, sizeof(buf), addr, addr_len);
      
      if (family == AF_UNIX)
	fprintf(err, "%s: %s: UNIX-socket bind(%d,%s): errno=%d: %s\n",
		__FILE__, __PRETTY_FUNCTION__,
		sd, buf,
		e, strerror(e));
      else
	fprintf(err, "%s: %s: bind(%d,%s,%d): errno=%d: %s\n",
		__FILE__, __PRETTY_FUNCTION__,
		sd, buf, nepim_sock_get_port(addr),
		e, strerror(e));
    }
    
    close(sd);
    return NEPIM_SOCK_ERR_BIND;
  }

  return sd;
}

int nepim_create_listener_socket(FILE *err,
				 struct sockaddr *addr,
				 int addr_len,
				 int family,
				 int type,
				 int protocol,
				 int backlog,
				 int pmtu_mode,
				 int ttl,
				 int win_recv,
				 int win_send,
				 int nodelay,
				 int tos,
				 int mss,
				 int ra,
				 const char *iface,
				 const struct sockaddr *ssm_src_addr, int ssm_src_addrlen)
{
  int sd;

  sd = nepim_create_socket(err, addr, addr_len, family,
			   type, protocol, pmtu_mode, 
			   ttl, 0, win_recv, win_send,
			   nodelay, tos, mss, ra,
			   iface, ssm_src_addr, ssm_src_addrlen);
  if (sd < 0)
    return sd;

  if (listen(sd, backlog)) {

    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: listen: sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      sd, e, strerror(e));
    }

    close(sd);

    return NEPIM_SOCK_ERR_LISTEN;
  }

  return sd;
}

static int unlinger(int sd)
{
  struct linger opt;

  opt.l_onoff = 0;  /* active? */
  opt.l_linger = 0; /* seconds */

  return setsockopt(sd, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
}

static int reuse(int sd)
{
  int opt = 1;

  return setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static int set_tcp_nodelay(FILE *err, int sd, int nodelay)
{
  if (nodelay == -1)
    return NEPIM_SOCK_ERR_NONE;

  if (setsockopt(sd, SOL_TCP, TCP_NODELAY,
		 &nodelay, sizeof(nodelay))) {
    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: setsockopt: TCP_NODELAY: sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_NODELAY;
  }

  return NEPIM_SOCK_ERR_NONE;
}

static int nepim_socket_get_nodelay(FILE *err, int sd)
{
  int nodelay;
  socklen_t optlen = sizeof(nodelay);

  if (getsockopt(sd, SOL_TCP, TCP_NODELAY,
		 &nodelay, &optlen)) {
    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: getsockopt: TCP_NODELAY: sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_NODELAY;
  }
  
  assert(optlen == sizeof(nodelay));
  
  return nodelay;
}

int nepim_socket_opt(FILE *err, int sd, int pmtu_mode, int ttl, int tos, int ra)
{
  if (unlinger(sd))
    return NEPIM_SOCK_ERR_UNLINGER;

  if (reuse(sd))
    return NEPIM_SOCK_ERR_REUSE;

  if (nepim_socket_pmtu(sd, pmtu_mode))
    return NEPIM_SOCK_ERR_PMTU;

  if (nepim_socket_ttl(sd, ttl))
    return NEPIM_SOCK_ERR_TTL;

  if (nepim_socket_tos(err, sd, tos))
    return NEPIM_SOCK_ERR_TOS;

  if (ra)
    if (socket_set_ra(err, sd))
      return NEPIM_SOCK_ERR_RA;

  return NEPIM_SOCK_ERR_NONE;
}

static int nepim_socket_mss(FILE *err, int sd, int mss)
{
  if (mss < 0)
    return NEPIM_SOCK_ERR_NONE;

  if (err)
    fprintf(err, "%s: %s: setsockopt(%d, SOL_TCP, TCP_MAXSEG, %d)\n",
	    __FILE__, __PRETTY_FUNCTION__, sd, mss);

  if (setsockopt(sd, SOL_TCP, TCP_MAXSEG, &mss, sizeof(mss))) {

    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: setsockopt: TCP_MAXSEG: mss=%d: sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      mss, sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_MSS;
  }

  return NEPIM_SOCK_ERR_NONE;
}

int nepim_socket_tcp_opt(FILE *err, int family, int sd, int nodelay, int mss)
{
  if (set_tcp_nodelay(err, sd, nodelay)) {
    /*
      Tolerate failure in setting NODELAY for PF_UNIX sockets
    */
    if (family != PF_UNIX)
      return NEPIM_SOCK_ERR_NODELAY;
  }

  if (nepim_socket_mss(err, sd, mss)) {
    /*
      Tolerate failure in setting TCP_MAXSEG for PF_UNIX sockets
    */
    if (family != PF_UNIX)
      return NEPIM_SOCK_ERR_MSS;
  }

  return NEPIM_SOCK_ERR_NONE;
}

int nepim_socket_keepalive(FILE *err, int sd, int keepalive)
{
  if (keepalive == -1)
    return NEPIM_SOCK_ERR_NONE;

  if (setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE,
		 &keepalive, sizeof(keepalive))) {

    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: setsockopt: SO_KEEPALIVE: sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_SOCK_KA;
  }

  return NEPIM_SOCK_ERR_NONE;
}

static int nepim_socket_get_keepalive(FILE *err, int sd)
{
  int keepalive;
  socklen_t optlen = sizeof(keepalive);

  if (getsockopt(sd, SOL_SOCKET, SO_KEEPALIVE,
		 &keepalive, &optlen)) {

    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: getsockopt: SO_KEEPALIVE: sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_SOCK_KA;
  }
  
  assert(optlen == sizeof(keepalive));
  
  return keepalive;
}

int nepim_connect_client_socket(FILE *err,
				const struct sockaddr *bind, int bind_len,
				struct sockaddr *addr, int addr_len,
				int family,
				int type,
				int protocol,
				int pmtu_mode,
				int ttl,
				int win_recv,
				int win_send,
				int nodelay,
				int tos,
				int socket_keepalive,
				int mss,
				int ra,
				const char *iface)
{
  int sd;
  int result;

  sd = nepim_create_socket(err, bind, bind_len,
			   family, type, protocol, pmtu_mode, ttl,
			   0 /* mcast_join: false */,
			   win_recv, win_send, nodelay, tos, mss, ra,
			   iface,
			   0,  /* ssm_src_addr */
			   -1  /* ssm_src_addrlen */);
  if (sd < 0)
    return sd;

#ifdef SO_BSDCOMPAT
  /*
   * We don't want Linux ECONNREFUSED on UDP sockets
   */
  if (protocol == IPPROTO_UDP) {
    int one = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_BSDCOMPAT, &one, sizeof(one)))
      return -1;
  }
#endif /* Linux SO_BSDCOMPAT */

  result = nepim_socket_keepalive(err, sd, socket_keepalive);
  if (result) {
    close(sd);
    return result;
  }

  result = nepim_socket_block(sd);
  if (result) {
    close(sd);
    return result;
  }

#ifdef NEPIM_DEBUG_FIXME
  fprintf(stderr, 
	  "DEBUG FIXME %s %s slow synchronous connect\n",
	  __FILE__, __PRETTY_FUNCTION__);
#endif

  if (connect(sd, addr, addr_len)) {

    if (err) {
      char buf[500];
      int e = errno;

      nepim_sock_dump_addr(buf, sizeof(buf), addr, addr_len);

      if (family == PF_UNIX)
	fprintf(err, "%s: %s: UNIX-socket connect(%d,%s): errno=%d: %s\n",
		__FILE__, __PRETTY_FUNCTION__,
		sd, buf, e, strerror(e));
      else
	fprintf(err, "%s: %s: connect(%d,%s,%d): errno=%d: %s\n",
		__FILE__, __PRETTY_FUNCTION__,
		sd, buf, nepim_sock_get_port(addr),
		e, strerror(e));
    }
    
    close(sd);
    return NEPIM_SOCK_ERR_CONNECT;
  }

  result = nepim_socket_nonblock(sd);
  if (result) {
    close(sd);
    return result;
  }

  return sd;
}

int nepim_socket_pmtu_get_mode(int sd)
{
#ifdef IP_MTU_DISCOVER
  int mode;
  socklen_t optlen = sizeof(mode);

  if (getsockopt(sd, SOL_IP, IP_MTU_DISCOVER, &mode, &optlen))
    return NEPIM_SOCK_ERR_PMTU;
  
  assert(optlen == sizeof(mode));

  return mode;
#else
  return NEPIM_SOCK_ERR_PMTU;
#endif
}

int nepim_socket_pmtu_get_mtu(int sd)
{
  int mtu;
  socklen_t optlen = sizeof(mtu);

  if (getsockopt(sd, SOL_IP, IP_MTU, &mtu, &optlen))
    return NEPIM_SOCK_ERR_PMTU;

  assert(optlen == sizeof(mtu));

  return mtu;
}

int nepim_socket_get_ttl(int sd)
{
  int ttl;
  socklen_t optlen = sizeof(ttl);

  if (getsockopt(sd, SOL_IP, IP_TTL, &ttl, &optlen))
    return NEPIM_SOCK_ERR_TTL;

  assert(optlen == sizeof(ttl));

  return ttl;
}

static int socket_mcast_get_ttl(int sd)
{
#ifdef HAVE_UCHAR_MCAST_TTL
  unsigned char mcast_ttl;
#else
  int mcast_ttl;
#endif
  socklen_t optlen = sizeof(mcast_ttl);

  if (getsockopt(sd, SOL_IP, IP_MULTICAST_TTL, &mcast_ttl, &optlen))
    return NEPIM_SOCK_ERR_MCAST_TTL;

  assert(optlen == sizeof(mcast_ttl));

  return mcast_ttl;
}

static int socket_get_win_recv(int sd)
{
  int win_recv;
  socklen_t optlen = sizeof(win_recv);

  if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &win_recv, &optlen))
    return NEPIM_SOCK_ERR_WIN_RECV;
  
  assert(optlen == sizeof(win_recv));

  return win_recv;
}

static int socket_get_win_send(int sd)
{
  int win_send;
  socklen_t optlen = sizeof(win_send);

  if (getsockopt(sd, SOL_SOCKET, SO_SNDBUF, &win_send, &optlen))
    return NEPIM_SOCK_ERR_WIN_SEND;
  
  assert(optlen == sizeof(win_send));

  return win_send;
}

int nepim_socket_get_tos(int sd)
{
  unsigned char tos;
  socklen_t optlen = sizeof(tos);

  if (getsockopt(sd, SOL_IP, IP_TOS, &tos, &optlen))
    return NEPIM_SOCK_ERR_TOS;

  assert(optlen == sizeof(tos));

  return tos;
}

static int socket_get_mss(FILE *err, int sd)
{
  int mss;
  socklen_t optlen = sizeof(mss);

  if (getsockopt(sd, SOL_TCP, TCP_MAXSEG, &mss, &optlen)) {

    if (err) {
      int e = errno;
      fprintf(err, "%s: %s: getsockopt: TCP_MAXSEG: sd=%d: errno=%d: %s\n",
	      __FILE__, __PRETTY_FUNCTION__,
	      sd, e, strerror(e));
    }

    return NEPIM_SOCK_ERR_MSS;
  }
  
  assert(optlen == sizeof(mss));
  
  return mss;
}

void nepim_sock_show_opt(FILE *err, FILE *out, int sd)
{
  int pmtud_mode;
  int mtu;
  int ttl;
  int mcast_ttl;
  int win_recv;
  int win_send;
  int tos;
  int keepalive;
  int nodelay;
  int mss;

  pmtud_mode = nepim_socket_pmtu_get_mode(sd);
  mtu = nepim_socket_pmtu_get_mtu(sd);
  ttl = nepim_socket_get_ttl(sd);
  mcast_ttl = socket_mcast_get_ttl(sd);
  win_recv = socket_get_win_recv(sd);
  win_send = socket_get_win_send(sd);
  tos = nepim_socket_get_tos(sd);
  keepalive = nepim_socket_get_keepalive(err, sd);
  nodelay = nepim_socket_get_nodelay(err, sd);
  mss = socket_get_mss(err, sd);

  fprintf(out, 
	  "%d:"
	  " pmtud_mode=%d path_mtu=%d mss=%d tos=%d ttl=%d"
	  " mcast_ttl=%d win_recv=%d win_send=%d sock_ka=%d"
	  " nodelay=%d\n"
	  ,
	  sd,
	  pmtud_mode, mtu, mss, tos, ttl,
	  mcast_ttl, win_recv, win_send, keepalive,
	  nodelay);
}
