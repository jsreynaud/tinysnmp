
# -*- sh -*-

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

LDFLAGS = -rdynamic -Wl,-export-dynamic
LDLIBS = -ldebug -labz -lber -levent

ifeq ($(shell uname -s),Linux)
LDLIBS += -ldl
endif	# ifeq ($(shell uname -s),Linux)

# path to toplevel directory from here
TOPDIR = ..

# subdirectories (leave as is if there is no subdirectories)
DIR =

# names of object files
OBJ = cmdline.o config.o agent.o module.o	\
	snmp.o network.o odb.o module-snmp.o	\
	module-system.o main.o

# program name (leave as is if there is no program)
PRG = tinysnmpd

# library name (leave as is if there is no library)
LIB =

include $(TOPDIR)/paths.mk
include $(TOPDIR)/defs.mk
include $(TOPDIR)/vars.mk
include $(TOPDIR)/rules.mk

install::
	$(INSTALL) -d $(sbindir)
	$(INSTALL) -c -m 0755 $(PRG) $(sbindir)
	$(INSTALL) -d $(sysconfdir)
	$(INSTALL) -c -m 0644 tinysnmp.conf $(sysconfdir)/tinysnmp.conf
	$(INSTALL) -d $(mandir)/man8
	$(INSTALL) -c -m 0644 $(PRG).8 $(mandir)/man8
	gzip -9 $(mandir)/man8/$(PRG).8
	$(INSTALL) -d $(mandir)/man5
	$(INSTALL) -c -m 0644 tinysnmp.conf.5 $(mandir)/man5
	gzip -9 $(mandir)/man5/tinysnmp.conf.5
	$(INSTALL) -d $(mandir)/man3
	$(INSTALL) -c -m 0644 tinysnmp-modules.3 $(mandir)/man3
	gzip -9 $(mandir)/man3/tinysnmp-modules.3
	$(INSTALL) -d $(datadir)/tinysnmp/mibs
	$(INSTALL) -c -m 0644 $(TOPDIR)/mibs/SNMPv2-SMI.txt $(datadir)/tinysnmp/mibs
	$(INSTALL) -c -m 0644 $(TOPDIR)/mibs/SNMPv2-TC.txt $(datadir)/tinysnmp/mibs
	$(INSTALL) -c -m 0644 $(TOPDIR)/mibs/SNMPv2-CONF.txt $(datadir)/tinysnmp/mibs
	$(INSTALL) -c -m 0644 $(TOPDIR)/mibs/SNMPv2-MIB.txt $(datadir)/tinysnmp/mibs

uninstall::
	$(RM) $(sbindir)/$(PRG)
	$(RM) $(sysconfdir)/tinysnmp.conf
	$(RM) $(mandir)/man8/$(PRG).8.gz
	$(RM) $(mandir)/man5/tinysnmp.conf.5.gz
	$(RM) $(mandir)/man3/tinysnmp-modules.3.gz
	$(RM) $(datadir)/tinysnmp/SNMPv2-SMI.txt
	$(RM) $(datadir)/tinysnmp/SNMPv2-TC.txt
	$(RM) $(datadir)/tinysnmp/SNMPv2-CONF.txt
	$(RM) $(datadir)/tinysnmp/SNMPv2-MIB.txt

