
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

#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <debug/memory.h>

#include <abz/typedefs.h>
#include <abz/error.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/odb.h>
#include <tinysnmp/agent/module.h>

#include "proc.h"

enum
{
   IFINDEX				= 1,
   IFDESCR				= 2,
   IFTYPE				= 3,
   IFMTU				= 4,
   IFSPEED				= 5,
   IFPHYSADDRESS		= 6,
   IFADMINSTATUS		= 7,
   IFOPERSTATUS			= 8,
   IFLASTCHANGE			= 9,
   IFINOCTETS			= 10,
   IFINUCASTPKTS		= 11,
   IFINNUCASTPKTS		= 12,
   IFINDISCARDS			= 13,
   IFINERRORS			= 14,
   IFINUNKNOWNPROTOS	= 15,
   IFOUTOCTETS			= 16,
   IFOUTUCASTPKTS		= 17,
   IFOUTNUCASTPKTS		= 18,
   IFOUTDISCARDS		= 19,
   IFOUTERRORS			= 20,
   IFOUTQLEN			= 21,
   IFSPECIFIC			= 22
};

static void socket_failed (void)
{
   abz_set_error ("failed to create socket: %m");
}

static int update (struct odb **odb,const uint32_t *oid,uint8_t type,void *data)
{
   snmp_value_t value;

   value.type = type;

   switch (type)
	 {
	  case BER_INTEGER:
		value.data.INTEGER = *(int32_t *) data;
		break;
	  case BER_Counter32:
		value.data.Counter32 = *(uint32_t *) data;
		break;
	  case BER_Gauge32:
		value.data.Gauge32 = *(uint32_t *) data;
		break;
	  case BER_TimeTicks:
		value.data.TimeTicks = *(uint32_t *) data;
		break;
	  case BER_Counter64:
		value.data.Counter64 = *(uint64_t *) data;
		break;
	  case BER_OID:
		value.data.OID = (uint32_t *) data;
		break;
	  case BER_OCTET_STRING:
		value.data.OCTET_STRING = *(octet_string_t *) data;
		break;
	  default:
		abz_set_error ("invalid type (0x%02x) specified",type);
		return (-1);
	 }

   return (odb_add (odb,oid,&value));
}

static int update_iftable (struct odb **odb,uint32_t entry,uint32_t index,uint8_t type,void *data)
{
   const uint32_t ifTable[11] = { 10, 43, 6, 1, 2, 1, 2, 2, 1, entry, index };
   return (update (odb,ifTable,type,data));
}

static int update_ifnumber (struct odb **odb,int32_t n)
{
   const uint32_t ifNumber[9] = { 8, 43, 6, 1, 2, 1, 2, 1, 0 };
   return (update (odb,ifNumber,BER_INTEGER,&n));
}

static int update_ifdescr (struct odb **odb,char *dev,int32_t index)
{
   octet_string_t str;

   str.len = strlen (dev);
   str.buf = (uint8_t *) dev;

   return (update_iftable (odb,IFDESCR,index,BER_OCTET_STRING,&str));
}

static int update_ifphysaddress (struct odb **odb,char *dev,int32_t index)
{
   uint8_t ifPhysAddress[IFHWADDRLEN * 3];
   octet_string_t str;
   struct ifreq ifr;
   int fd;

   if ((fd = socket (PF_INET,SOCK_DGRAM,0)) < 0)
	 {
		socket_failed ();
		return (-1);
	 }

   strcpy (ifr.ifr_name,dev);

   if (ioctl (fd,SIOCGIFHWADDR,&ifr))
	 {
		abz_set_error ("failed to get hardware address for interface %s",dev);
		close (fd);
		return (-1);
	 }

   close (fd);

   str.len = 0;
   str.buf = ifPhysAddress;

   if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER && IFHWADDRLEN)
	 {
		str.len = IFHWADDRLEN;
		memcpy (str.buf,ifr.ifr_hwaddr.sa_data,str.len);
	 }

   return (update_iftable (odb,IFPHYSADDRESS,index,BER_OCTET_STRING,&str));
}

static int update_ifmtu (struct odb **odb,const char *dev,int32_t index)
{
   struct ifreq ifr;
   int fd;
   int32_t ifMtu;

   if ((fd = socket (PF_INET,SOCK_DGRAM,0)) < 0)
	 {
		socket_failed ();
		return (-1);
	 }

   strcpy (ifr.ifr_name,dev);

   if (ioctl (fd,SIOCGIFMTU,&ifr))
	 {
		abz_set_error ("failed to get mtu for interface %s",dev);
		close (fd);
		return (-1);
	 }

   close (fd);

   ifMtu = ifr.ifr_mtu;

   return (update_iftable (odb,IFMTU,index,BER_INTEGER,&ifMtu));
}

static int update_ifstatus (struct odb **odb,const char *dev,int32_t index)
{
   struct ifreq ifr;
   int fd;
   int32_t ifAdminStatus;
   int32_t ifOperStatus;

   if ((fd = socket (PF_INET,SOCK_DGRAM,0)) < 0)
	 {
		socket_failed ();
		return (-1);
	 }

   strcpy (ifr.ifr_name,dev);

   if (ioctl (fd,SIOCGIFFLAGS,&ifr))
	 {
		abz_set_error ("failed to get status flags for %s",dev);
		close (fd);
		return (-1);
	 }

   close (fd);

   ifAdminStatus = ifr.ifr_flags & IFF_UP ? 1 : 2;
   ifOperStatus = ifr.ifr_flags & IFF_RUNNING ? 1 : 2;

   return (update_iftable (odb,IFADMINSTATUS,index,BER_INTEGER,&ifAdminStatus) ||
		   update_iftable (odb,IFOPERSTATUS,index,BER_INTEGER,&ifOperStatus) ?
		   -1 : 0);
}

static int update_iftype (struct odb **odb,const char *dev,int32_t index)
{
   int fd;
   struct ifreq ifr;
   int32_t ifType;

   if ((fd = socket (PF_INET,SOCK_DGRAM,0)) < 0)
	 {
		socket_failed ();
		return (-1);
	 }

   strcpy (ifr.ifr_name,dev);

   if (ioctl (fd,SIOCGIFHWADDR,&ifr))
	 {
		abz_set_error ("failed to get hardware address for interface %s",dev);
		close (fd);
		return (-1);
	 }

   switch (ifr.ifr_hwaddr.sa_family)
	 {
	  case ARPHRD_ETHER:
		ifType = 6;
		break;
	  case ARPHRD_PPP:
		ifType = 23;
		break;
	  case ARPHRD_HDLC:
		ifType = 118;
		break;
	  case ARPHRD_LOOPBACK:
		ifType = 24;
		break;
	  default:
		ifType = 1;
	 }

   strcpy (ifr.ifr_name,dev);

   if (ioctl (fd,SIOCGIFFLAGS,&ifr))
	 {
		abz_set_error ("failed to get status flags for interface %s",dev);
		close (fd);
		return (-1);
	 }

   if (ifr.ifr_flags & IFF_PORTSEL)
	 {
		strcpy (ifr.ifr_name,dev);

		if (ioctl (fd,SIOCGIFMAP,&ifr))
		  {
			 abz_set_error ("failed to get interface mapping for %s",dev);
			 close (fd);
			 return (-1);
		  }

		if (ifr.ifr_map.port == 4 || ifr.ifr_map.port == 5)
		  ifType = 62;
		else if (ifr.ifr_map.port == 6)
		  ifType = 69;
	 }

   close (fd);

   return (update_iftable (odb,IFTYPE,index,BER_INTEGER,&ifType));
}

static int update_ifspeed (struct odb **odb,int32_t index)
{
   /* Linux doesn't report the speed of the interface :P */
   uint32_t ifSpeed = 0xffffffff;

   return (update_iftable (odb,IFSPEED,index,BER_Gauge32,&ifSpeed));
}

static int update_iflastchange (struct odb **odb,int32_t index)
{
   /* ...neither does is support interface change timestamps */
   uint32_t ifLastChange = 0;

   return (update_iftable (odb,IFLASTCHANGE,index,BER_TimeTicks,&ifLastChange));
}

static int update_ifstats (struct odb **odb,const struct devstats *stats,int32_t index)
{
   /* Linux have no way to retrieve the unknown protocol packets received */
   uint32_t ifInUnknownProtos = 0;
   /* Linux is too brain damaged to let us know about transmitted multicast packets :P */
   uint32_t ifOutNUcastPkts = 0;
   uint32_t ifInOctets = stats->rx_bytes;
   uint32_t ifInUcastPkts = stats->rx_packets - stats->multicast;
   uint32_t ifInNUcastPkts = stats->multicast;
   uint32_t ifInDiscards = stats->rx_dropped;
   uint32_t ifInErrors = stats->rx_errors;
   uint32_t ifOutOctets = stats->tx_bytes;
   uint32_t ifOutUcastPkts = stats->tx_packets;
   uint32_t ifOutDiscards = stats->tx_dropped;
   uint32_t ifOutErrors = stats->tx_errors;

   return (update_iftable (odb,IFINOCTETS,index,BER_Counter32,&ifInOctets) ||
		   update_iftable (odb,IFINUCASTPKTS,index,BER_Counter32,&ifInUcastPkts) ||
		   update_iftable (odb,IFINNUCASTPKTS,index,BER_Counter32,&ifInNUcastPkts) ||
		   update_iftable (odb,IFINDISCARDS,index,BER_Counter32,&ifInDiscards) ||
		   update_iftable (odb,IFINERRORS,index,BER_Counter32,&ifInErrors) ||
		   update_iftable (odb,IFINUNKNOWNPROTOS,index,BER_Counter32,&ifInUnknownProtos) ||
		   update_iftable (odb,IFOUTOCTETS,index,BER_Counter32,&ifOutOctets) ||
		   update_iftable (odb,IFOUTUCASTPKTS,index,BER_Counter32,&ifOutUcastPkts) ||
		   update_iftable (odb,IFOUTNUCASTPKTS,index,BER_Counter32,&ifOutNUcastPkts) ||
		   update_iftable (odb,IFOUTDISCARDS,index,BER_Counter32,&ifOutDiscards) ||
		   update_iftable (odb,IFOUTERRORS,index,BER_Counter32,&ifOutErrors) ?
		   -1 : 0);
}

static int update_ifoutqlen (struct odb **odb,const char *dev,int32_t index)
{
   int fd;
   struct ifreq ifr;
   uint32_t ifOutQLen;

   if ((fd = socket (PF_INET,SOCK_DGRAM,0)) < 0)
	 {
		socket_failed ();
		return (-1);
	 }

   strcpy (ifr.ifr_name,dev);

   if (ioctl (fd,SIOCGIFTXQLEN,&ifr))
	 {
		abz_set_error ("failed to get tx queue length for interface %s",dev);
		close (fd);
		return (-1);
	 }

   close (fd);

   ifOutQLen = ifr.ifr_qlen;

   return (update_iftable (odb,IFOUTQLEN,index,BER_Gauge32,&ifOutQLen));
}

static int update_ifspecific (struct odb **odb,int32_t index)
{
   /* ccitt.zeroDotZero */
   uint32_t ifSpecific[2] = { 1, 0 };

   return (update_iftable (odb,IFSPECIFIC,index,BER_OID,ifSpecific));
}

static int iface_update (struct odb **odb)
{
   size_t i,n;
   int32_t ifIndex;
   struct devstats *stats;

   abz_clear_error ();

   if ((stats = getdevstats (&n)) == NULL)
	 return (-1);

   if (update_ifnumber (odb,n))
	 {
		mem_free (stats);
		return (-1);
	 }

   for (i = 0; i < n; i++)
	 {
		if (!(ifIndex = if_nametoindex (stats[i].dev)))
		  {
			 abz_set_error ("failed to map %s to an interface index",stats[i].dev);
			 mem_free (stats);
			 return (-1);
		  }

		if (update_iftable (odb,IFINDEX,ifIndex,BER_INTEGER,&ifIndex) ||
			update_ifdescr (odb,stats[i].dev,ifIndex) ||
			update_ifphysaddress (odb,stats[i].dev,ifIndex) ||
			update_ifmtu (odb,stats[i].dev,ifIndex) ||
			update_ifstatus (odb,stats[i].dev,ifIndex) ||
			update_iftype (odb,stats[i].dev,ifIndex) ||
			update_ifspeed (odb,ifIndex) ||
			update_iflastchange (odb,ifIndex) ||
			update_ifstats (odb,stats + i,ifIndex) ||
			update_ifoutqlen (odb,stats[i].dev,ifIndex) ||
			update_ifspecific (odb,ifIndex))
		  {
			 mem_free (stats);
			 return (-1);
		  }
	 }

   mem_free (stats);

   return (0);
}

/* iso.org.dod.internet.mgmt.mib-2.interfaces */
static const uint32_t interfaces[7] = { 6, 43, 6, 1, 2, 1, 2 };

/* iso.org.dod.internet.mgmt.mib-2.ifMIB */
static const uint32_t ifMIB[7] = { 6, 43, 6, 1, 2, 1, 31 };

struct module module =
{
   .name	= "interfaces",
   .descr	= "The MIB module to describe generic objects for network interface sub-layers",
   .mod_oid	= interfaces,
   .con_oid = ifMIB,
   .parse	= NULL,
   .open	= NULL,
   .update	= iface_update,
   .close	= NULL
};

