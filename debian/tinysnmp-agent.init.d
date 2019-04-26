#!/bin/bash

#  Copyright (c) Abraham vd Merwe <abz@blio.com>
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the author nor the names of other contributors
#     may be used to endorse or promote products derived from this software
#     without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

PATH="/sbin:/bin:/usr/sbin"

user=tinysnmp
pidfile=/var/run/tinysnmpd.pid
facility=daemon
loglevel=verbose
config=/etc/tinysnmp.conf
daemon=/usr/sbin/tinysnmpd
modpath=/usr/lib/tinysnmp

test -x $daemon || exit 0

case "$1" in
	start)
		echo -n "Starting router-monitoring daemon: tinysnmpd"
		rm -f $pidfile
		start-stop-daemon --start --quiet --pidfile $pidfile --user root --exec $daemon -- -d -s $facility -l $loglevel $config $modpath
		echo "."
		;;
	stop)
		echo -n "Stopping router-monitoring daemon: tinysnmpd"
		start-stop-daemon --stop --quiet --pidfile $pidfile --user $user --exec $daemon && rm -f $pidfile
		echo "."
		;;
	restart|reload|force-reload)
		$0 stop
		sleep 1
		$0 start
		;;
	*)
		echo 'usage: /etc/init.d/tinysnmpd {start|stop|restart}'
		exit 1
esac

exit 0

