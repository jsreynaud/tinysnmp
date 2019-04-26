#ifndef DVB_H
#define DVB_H

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

#include <stdint.h>
#include <net/if.h>

#define DVB_DESCR			0x0001
#define DVB_VERSION			0x0002
#define DVB_HWADDR			0x0004
#define DVB_STATUS			0x0008
#define DVB_RXPACKETS		0x0010
#define DVB_RXRATE			0x0020
#define DVB_LOCK			0x0040
#define DVB_BER				0x0080
#define DVB_CORRECTED		0x0100
#define DVB_UNCORRECTED		0x0200
#define DVB_SIGNAL			0x0400

struct dvb
{
   char dvbDescr[IFNAMSIZ];
   char dvbVersion[32];
   uint8_t dvbHWAddr[6];
   int32_t dvbStatus;
   uint32_t dvbRxPackets;
   uint32_t dvbRxRate;
   int32_t dvbLNBLock;
   uint32_t dvbBitErrorRate;
   uint32_t dvbErrorsCorrected;
   uint32_t dvbErrorsUncorrected;
   uint32_t dvbSNRatio;
};

extern uint32_t dvb_query (struct dvb *dvb,const char *dev);

#endif	/* #ifndef DVB_H */
