#ifndef PROC_H
#define PROC_H

/*
 * Copyright (c) Abraham vd Merwe <abz@blio.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <net/if.h>
#include <abz/typedefs.h>

/* from linux/net/core/dev.c */
struct devstats
{
   /* name of device */
   char dev[IFNAMSIZ];

   /* receive */
   uint64_t rx_bytes;
   uint64_t rx_packets;
   uint64_t rx_errors;
   uint64_t rx_dropped;
   uint64_t rx_fifo_errors;
   uint64_t rx_frame_errors;
   uint64_t rx_compressed;
   uint64_t multicast;

   /* transmit */
   uint64_t tx_bytes;
   uint64_t tx_packets;
   uint64_t tx_errors;
   uint64_t tx_dropped;
   uint64_t tx_fifo_errors;
   uint64_t collisions;
   uint64_t tx_carrier_errors;
   uint64_t tx_compressed;
};

#define getdevstats(n) getdevstats_stub(__FILE__,__LINE__,__FUNCTION__,n)
extern struct devstats *getdevstats_stub (const char *filename,int line,const char *function,size_t *n);

extern int getprocuptime (uint32_t *uptime);

#endif	/* #ifndef PROC_H */
