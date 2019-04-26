
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
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>

#include <pentanet/xptype.h>
#include <pentanet/ifdef.h>
#include <pentanet/pentapi.h>

#include "dvb.h"

uint32_t dvb_query (struct dvb *dvb,const char *dev)
{
   int result;
   uint32_t mask = DVB_DESCR | DVB_STATUS;
   double quality;

   memset (dvb,0L,sizeof (struct dvb));

   strncpy (dvb->dvbDescr,dev,IFNAMSIZ);
   dvb->dvbDescr[IFNAMSIZ - 1] = '\0';

   switch (result = sm_get_device_status (dvb->dvbDescr))
	 {
	  case ERR_NOT_DEVICE_OPEN:
		dvb->dvbStatus = 2;
		return (mask);
	  default:
		if (result > 0)
		  {
			 dvb->dvbStatus = 1;
			 break;
		  }
	  case ERR_OPEN_SOCKET:
		dvb->dvbStatus = 3;
		return (mask);
	 }

   mask |= DVB_LOCK | DVB_SIGNAL;
   quality = sm_get_signal_quality (dvb->dvbDescr);
   dvb->dvbSNRatio = quality * 1000000.0;
   dvb->dvbLNBLock = sm_tuner_get_status (dvb->dvbDescr) ? 1 : 2;

   if ((result = sm_get_device_version (dvb->dvbDescr)) > 0)
	 {
		mask |= DVB_VERSION;
		sprintf (dvb->dvbVersion,
				 "%x.%x.%x",
				 (result>>16) & 0xff,
				 (result>>8) & 0xff,
				 result & 0xff);
	 }

   if (!sm_get_mac_address (dvb->dvbDescr,(char *) dvb->dvbHWAddr))
	 mask |= DVB_HWADDR;

   if ((result = sm_get_received_packets (dvb->dvbDescr)) >= 0)
	 {
		mask |= DVB_RXPACKETS;
		dvb->dvbRxPackets = result;
	 }

   if ((result = sm_get_down_speed (dvb->dvbDescr)) >= 0)
	 {
		mask |= DVB_RXRATE;
		dvb->dvbRxRate = result * 8U;
	 }

   if ((result = sm_get_bit_error_rate (dvb->dvbDescr)) >= 0)
	 {
		mask |= DVB_BER;
		dvb->dvbBitErrorRate = 0;
		if (result)
		  dvb->dvbBitErrorRate = ((float) result / 1048576) * 1000000000000.0;
	 }

   if ((result = sm_get_corrected_rs_error (dvb->dvbDescr)) >= 0)
	 {
		mask |= DVB_CORRECTED;
		dvb->dvbErrorsCorrected = result;
	 }

   if ((result = sm_get_uncorrected_rs_error (dvb->dvbDescr)) >= 0)
	 {
		mask |= DVB_UNCORRECTED;
		dvb->dvbErrorsUncorrected = result;
	 }

   return (mask);
}

#if 0
int main (int argc,char *argv[])
{
   struct dvb dvb;
   uint32_t mask = dvb_query (&dvb,"pentanet0");

   if (mask & DVB_DESCR)
	 printf ("descr    : %s\n",dvb.dvbDescr);

   if (mask & DVB_VERSION)
	 printf ("version  : %s\n",dvb.dvbVersion);

   if (mask & DVB_HWADDR)
	 printf ("hwaddr   : %02x:%02x:%02x:%02x:%02x:%02x\n",
			 dvb.dvbHWAddr[0],
			 dvb.dvbHWAddr[1],
			 dvb.dvbHWAddr[2],
			 dvb.dvbHWAddr[3],
			 dvb.dvbHWAddr[4],
			 dvb.dvbHWAddr[5]);

   if (mask & DVB_STATUS)
	 printf ("status   : %s\n",
			 dvb.dvbStatus == 1 ? "open(1)" :
			 dvb.dvbStatus == 2 ? "close(2)" :
			 dvb.dvbStatus == 3 ? "error(3)" :
			 "*** BUG ***");

   if (mask & DVB_RXPACKETS)
	 printf ("rxpkts   : %u\n",dvb.dvbRxPackets);

   if (mask & DVB_RXRATE)
	 printf ("rxrate   : %.3f [Mbps]\n",(float) dvb.dvbRxRate / 1048576.0);

   if (mask & DVB_LOCK)
	 printf ("lock     : %s\n",
			 dvb.dvbLNBLock == 1 ? "true(1)" :
			 dvb.dvbLNBLock == 2 ? "false(2)" :
			 "*** BUG ***");

   if (mask & DVB_BER)
	 printf ("ber      : %e\n",dvb.dvbBitErrorRate / 1000000000000.0);

   if (mask & DVB_CORRECTED)
	 printf ("rscorr   : %u\n",dvb.dvbErrorsCorrected);

   if (mask & DVB_UNCORRECTED)
	 printf ("rsuncorr : %u\n",dvb.dvbErrorsUncorrected);

   if (mask & DVB_SIGNAL)
	 printf ("signal   : %f [dB]\n",(float) dvb.dvbSNRatio / 1000000.0);

   return (0);
}
#endif

