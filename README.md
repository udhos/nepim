INTRODUCTION
============

        nepim stands for network pipemeter, a tool for measuring
        available bandwidth between hosts. nepim is also useful to
        generate network traffic for testing purposes.

        nepim operates in client/server mode, is able to handle
        multiple parallel traffic streams, reports periodic partial
        statistics along the testing, accepts rich tuning from
	command-line, supports multicast and IPv6.

LICENSE
=======

        nepim - network pipemeter
        Copyright (C) 2005 Everton da Silva Marques

        nepim is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as
        published by the Free Software Foundation; either version 2,
        or (at your option) any later version.

        nepim is distributed in the hope that it will be useful, but
        WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public
        License along with nepim; see the file COPYING.  If not, write
        to the Free Software Foundation, Inc., 59 Temple Place - Suite
        330, Boston, MA 02111-1307, USA.

HOME
====
        nepim lives at https://github.com/udhos/nepim

REQUIREMENTS
============

        nepim depends on Liboop (1.0 or higher), available at:

        http://download.ofb.net/liboop/

        http://directory.fsf.org/libs/c/liboop.html

        http://ftp.debian.org/debian/pool/main/libo/liboop/liboop_1.0.orig.tar.gz

        http://liboop.org/

BUILDING
========

        nepim has been tested under Linux, Solaris and FreeBSD, though
        it should work under other platforms as well. If you manage to
        build nepim for different systems, please send the patch.

        Before compiling nepim, install Liboop on your system.

        Then type:

        $ cd src
        $ make

        If you have Liboop installed on a special location, pass it to
        the make, as in the following example:

        $ cd src
        $ make OOP_BASE=/usr/local/oop

        Afterwards copy the 'nepim' binary to your system's proper
        filesystem location. For instance:

        $ cp nepim /usr/local/bin

        If you face trouble compiling, try tweaking the
        Makefile. Otherwise, post your problem at nepim support site.

	--

	* Tip for building with 64-bit Solaris:

	# 1. Use Solaris' 64-bit libraries
	lib64=/usr/local/lib/sparcv9

	# 2. Decide where 64-bit Liboop will lie
	liboop=$lib64/oop

	# 3. When building Liboop:
	#    Configure Liboop to link against 64-bit libraries
	CFLAGS="-m64 -mcpu=v9" LDFLAGS=-R$lib64 ./configure --prefix=$liboop

	# 4. When building nepim:
	#    Simply pass the Liboop base location to make
	make build OOP_BASE=$liboop

BASIC USAGE
===========

        Starting the server:

        $ nepim

        Starting the client against one server located at 10.10.10.10:

        $ nepim -c 10.10.10.10 -d

        Display brief help about command line options:

        $ nepim -h

EXAMPLE
=======

        Running nepim in server mode at the server host:

	server$ nepim
	nepim - network pipemeter - version 0.27
	server: tcp_read=32768 tcp_write=32768 udp_read=4096 udp_write=4096
	3: TCP socket listening on ::,1234
	sock.c: nepim_create_socket: bind(4,0.0.0.0,1234): errno=98: Address already in use
	server.c spawn_tcp_listener: TCP listener socket failed for 0.0.0.0,1234: -3
	4: UDP socket listening on ::,1234
	4: pmtud_mode=1 path_mtu=-11 mss=-19 tos=0 ttl=64 mcast_ttl=1 win_recv=109568 win_send=109568 sock_ka=0 nodelay=-10
	5: UDP socket listening on 0.0.0.0,1234
	5: pmtud_mode=1 path_mtu=-11 mss=-19 tos=0 ttl=64 mcast_ttl=1 win_recv=109568 win_send=109568 sock_ka=0 nodelay=-10
	nepim: server ready

        Running nepim in client mode at the client host:

	client$ nepim -c localhost -d -r 100000
	nepim - network pipemeter - version 0.27
	client: tcp_read=32768 tcp_write=32768
	not a UNIX domain path: localhost: errno=2: No such file or directory
	TCP socket solving localhost,1234
	TCP socket trying 127.0.0.1,1234
	DEBUG FIXME sock.c nepim_connect_client_socket slow synchronous connect
	3: TCP socket connected to 127.0.0.1,1234
	3: sending: hello server_send=1 bit_rate=100000 pkt_rate=-1 stat_interval=2 test_duration=10 write_delay=250000 server_ka_send=0 server_ka_req=0 seed=0xd4d2e835 verify_data=0 random_fill=1 fill_byte=0x00 pause_duration=0 sock_ka=1 nagle=-1 overhead=0 password=
	3: greetings sent to 127.0.0.1,1234
	3: pmtud_mode=1 path_mtu=16436 mss=16383 tos=0 ttl=64 mcast_ttl=1 win_recv=87856 win_send=50568 sock_ka=1 nodelay=0
	                  kbps_in   kbps_out    rcv/s    snd/s
	  3  prt     8     100.00     100.00     4.00     4.00
	  3  prt     6     100.00     100.00     4.00     4.00
	  3  prt     4     100.00     100.00     4.00     4.00
	  3  prt     2     100.00     100.00     4.00     4.00
	  3  avg     0     100.00     100.00     4.00     4.00
	3: pmtud_mode=1 path_mtu=16436 mss=16384 tos=0 ttl=64 mcast_ttl=1 win_recv=87856 win_send=50568 sock_ka=1 nodelay=0
	nepim: no event sink registered
	nepim: done

USAGE HINTS
===========

        * nepim is useful to assess the throughput at the transport
        layer (TCP or UDP) as seen by applications.

        * nepim runs single-threaded and should impose very light
        burden on your CPU. Unless, of course, your testing hosts have
        relatively high network bandwidth compared to low CPU power.

	* The client/server interaction is friendly to clients hosted
	behind Dynamic NAT or stateful firewalls: to build a
	connection, the client needs to reach only one transport-layer
	port on the server; test options are negotiated in the
	beginning of that single data connection; there is not any
	control connection.

	* Test duration defaults to 10 seconds. The "-a" client option
	can supply a distinct duration. Releases higher than 0.31
	recognize some time suffixes: m=minute, h=hour, d=day. For
	instance:

	Up to 0.31			Higher than 0.31
	--------------------------	------------------------
	nepim -c 10.0.0.1 -a 120	nepim -c 10.0.0.1 -a 2m
	nepim -c 10.0.0.1 -a 3600	nepim -c 10.0.0.1 -a 1h
	nepim -c 10.0.0.1 -a 43200	nepim -c 10.0.0.1 -a .5d

        * One single server can service multiple clients
	simultaneously.

        * As of nepim 0.11, one single client can interact
        simultaneously with multiple servers. For instance, suppose
        you want to test, from a single client, two remote servers,
        one located at 10.0.0.1,2000 and another at 192.168.0.1,3000:

                nepim -c 10.0.0.1,2000 -c 192.168.0.1,3000

        * The server listens to both TCP and UDP sockets. The client
        by default uses TCP sockets. Use the "-u" client option to
        switch the client operation to UDP.

        * By default, only the server sends traffic towards the
        client. Use the "-s" client option to reverse the behavior,
        then only the client will send traffic. Use the "-d" client
        option to make both client and server to send traffic.

	* Starting from nepim 0.32, options -r,-R,-e accept
	multiplicative suffixes and floating point rates. Examples:

	-r .25g   = 250,000,000 bps
	-r .1m    =     100,000 bps
	-R .02k   =          20 pps

        * Use the "-r" client option to establish an upper bit rate
        limit. Without a rate limiting option, nepim sends as fast as
        possible. See also "-R" below. Please notice the rate is
        specified in bps (bits per second); for instance, the
        following example states a rate limit of 100,000 bps (100
        Kbps):

                nepim -c 10.0.0.1 -r 100000

        * Use the "-R" client option to establish an upper "packet"
        rate limit (outbound rate limit for transport layer
        segments). Without a rate limiting option, nepim sends as fast
        as possible. If both "-r" and "-R" are given, nepim limits the
        sending rate at the lower of those bounds.

	* The options "-r" and "-R" try to send some packets whenever
	a constant period is reached. The default period can be
	changed with the "-D" client option, in microseconds. "-D" is
	meaningful only when specified before "-r" or "-R". Example:

		nepim -c 10.0.0.1 -D 100000 -R 20

	* The "-e send-rate" client option tries to generate a
	constant data rate with segments sent at regular intervals. It
	should not be combined with "-D", "-r" or "-R", and might be
	processor-intensive. Example for 10 segments per second:

		nepim -c 10.0.0.1 -e 10

        * Use the "-n" client option to run multiple parallel traffic
        streams.

        * Use the "-b" server option to make the server to listen on
        specific local addresses.

        * Use the "-6" option to disable IPv6 support.

        * Use the "-4" option to disable IPv4 support.

        * Multicast support is special. Use the "-j" server switch to
        join a multicast group, then specify the "-M" client switch to
        enable multicast-compatible options. Example:

                server$ nepim -j ff01::1111

                client$ nepim -M -c ff01::1111 -r 100000

	* Use the "-j source+group" syntax to join an Source-Specific
	Multicast (source,group) pair. Examples:

		server$ nepim -j fe80::1+ff01::1111

		server$ nepim -j 10.10.10.10+232.1.1.1,2000

	* In the "-j" option, append "@interface" to group in order to
	specify an interface. Examples:

                server$ nepim -j 239.1.1.1@eth0             ;# by name

                server$ nepim -j 1.1.1.1+232.1.1.1@10.0.0.1 ;# by address

                server$ nepim -j 239.1.1.1@1                ;# by index

        	server$ nepim -j ::1+ff01::1111@eth1        ;# by name

		server$ nepim -j ::1+ff01::1111@2           ;# by index

        * The "-k" switch provides a simple password mechanism for
        client authentication. Just use the same password at both
        sides:

                server$ nepim -k 321

                client$ nepim -k 321 -c server-hostname

	* One can specify the "-F" switch to force sending out UDP
	packets regardless of a remote server.

		client$ nepim -F -c 1.1.1.1 -r 100000

	* The "-F" switch accepts suboption 'a' for randomizing
	destination address, or 'p' for randomizing destination port.

		Example for randomizing both address and port:

		client$ nepim -Fap -R 10

		Example for randomizing IPv6 address and port:

		client$ nepim -c ::1 -Fap -R 10

	* The "-U" option makes the server to listen on UNIX-domain
	stream sockets. See the example below.

		server$ nepim -U /tmp/sock1

		client$ nepim -c /tmp/sock1

	* By default, nepim uses only transport payload data to
	compute incoming/outgoing rates. Such behavior is reasonable
	for large packets (as in the standard 1500 bytes MTU for
	Ethernet interfaces) since the encapsulation headers remain
	comparatively small. However, as packets become smaller, the
	effect of encapsulation on transfer rates grows. The "-o"
	client option can be used to circumvent gross rate computation
	errors caused by excessive per-packet encapsulation
	overhead. The example below shows how the "-o" client option
	should be used to specify a per-packet overhead of 28 bytes,
	for UDP payloads of 100 bytes.

		server$ nepim -W 100

		client$ nepim -u -W 100 -d -r 100000 -c 10.10.10.10 -o 28

	Notes:

	1. The "-o" switch remains untested for TCP segments.

	2. It is probably incorrect to specify "-o" with the default
           large UDP write size, which typically causes local
           fragmentation. Thus, in order to use the "-o" option, it
           is advisable to choose a payload size which would surely
           fit the UDP segment entirely into a single MTU. For
           instance, with a 1500-byte MTU, 1400 would likely suffice:

		server$ nepim -W 1400

		client$ nepim -u -W 1400 -d -r 100000 -c 10.10.10.10 -o

	* The "-sweep low,high,step" client option cycles the write
	size (segment payload) from "low" to "high" with a increment
	of "step". "Low" must be lower than "high". If low=auto, "low"
	receives the minimum possible value. If high=auto, "high"
	receives the maximum possible value. If "step" is negative,
	the scan moves from "high" to "low". If step=random, the write
	size is random. Examples:

		client$ nepim -d -c 10.0.0.2 -R 5 -sweep 20,1400,10

		client$ nepim -d -c 10.0.0.2 -e 1 -sweep auto,auto,random

END
===
