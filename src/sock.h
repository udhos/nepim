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

#ifndef NEPIM_SOCK_H
#define NEPIM_SOCK_H

#include <sys/types.h>
#include <sys/socket.h>

int nepim_socket_nonblock(int sd);
int nepim_socket_block(int sd);
int nepim_socket_ttl(int sd, int ttl);
int nepim_socket_mcast_ttl(int sd, int mcast_ttl);
int nepim_socket_pmtu(int sd, int pmtu_mode);
int nepim_socket_opt(FILE *err, int sd, int pmtu_mode, int ttl, int tos, int ra);
int nepim_socket_tcp_opt(FILE *err, int family, int sd, int nodelay, int mss);
int nepim_socket_keepalive(FILE *err, int sd, int keepalive);

int nepim_socket_pmtu_get_mode(int sd);
int nepim_socket_pmtu_get_mtu(int sd);
int nepim_socket_get_ttl(int sd);
int nepim_socket_get_tos(int sd);

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
			const struct sockaddr *ssm_src_addr, int ssm_src_addrlen);
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
				 const struct sockaddr *ssm_src_addr, int ssm_src_addrlen);
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
				const char *iface);
int nepim_sock_get_port(const struct sockaddr *addr);
void nepim_sock_set_port(const struct sockaddr *addr, int port);
void nepim_sock_dump_addr(char *buf, int buf_size,
			  const struct sockaddr *addr,
			  int addr_len);
int nepim_sock_family(const struct sockaddr *addr);
int nepim_sock_addrlen(const struct sockaddr *addr);
void nepim_sock_show_opt(FILE *err, FILE *out, int sd);

#endif /* NEPIM_SOCK_H */

