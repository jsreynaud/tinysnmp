
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <debug/memory.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/odb.h>
#include <tinysnmp/agent/module.h>

#include <abz/typedefs.h>
#include <abz/error.h>
#include <abz/atoa.h>
#include <abz/atop.h>
#include <abz/trim.h>
#include <abz/tokens.h>

#define DEFAULT_PORT 6543
#define BUFFER_SIZE 4096

#define UPS_CALIBRATION		0x00000001
#define UPS_SMARTTRIM		0x00000002
#define UPS_SMARTBOOST		0x00000004
#define UPS_ONLINE			0x00000008
#define UPS_ONBATT			0x00000010
#define UPS_OVERLOAD		0x00000020
#define UPS_BATTLOW			0x00000040
#define UPS_REPLACEBATT		0x00000080
#define UPS_COMMLOST		0x00000100	/* Communications with UPS lost			*/
#define UPS_SHUTDOWN		0x00000200	/* Shutdown in progress					*/
#define UPS_SLAVE			0x00000400	/* Set if this is a slave				*/
#define UPS_SLAVEDOWN		0x00000800	/* Slave not responding					*/
#define UPS_SHUTDOWNIMM		0x00001000	/* Shutdown imminent					*/
#define UPS_BELOWCAPLIMIT	0x00002000	/* Below battery capacity limit			*/
#define UPS_REMTIMELIMIT	0x00004000	/* Remaining run time limit exceeded	*/
#define UPS_PREV_ONBATT		0x00008000	/* Previous value for UPS_ONBATT		*/
#define UPS_PREV_BATTLOW	0x00010000	/* Previous value for UPS_BATTLOW		*/
#define UPS_ONBATT_MSG		0x00020000	/* Set when UPS_ONBATT message is sent	*/
#define UPS_FASTPOLL		0x00040000	/* Set on power failure to poll faster	*/
#define UPS_SHUT_LOAD		0x00080000	/* Set when BatLoad <= percent			*/
#define UPS_SHUT_BTIME		0x00100000	/* Set when time on batts > maxtime		*/
#define UPS_SHUT_LTIME		0x00200000	/* Set when TimeLeft <= runtime			*/
#define UPS_SHUT_EMERG		0x00400000	/* Set when battery power has failed	*/
#define UPS_SHUT_REMOTE		0x00800000	/* Set when remote shutdown				*/
#define UPS_PLUGGED			0x01000000	/* Set if computer is plugged into UPS	*/
#define UPS_DEV_SETUP		0x02000000	/* Set if UPS's driver did the setup()	*/
#define UPS_SELFTEST		0x80000000

struct scalar
{
   const char *name;
   int (*update) (snmp_value_t *,char *);
   const uint32_t *oid;
   int once;
};

struct alarm
{
   uint32_t *oid;
   unsigned int mask;
};

/* configuration variables */
static struct sockaddr_in apcupsd;
static char *identifier = NULL;
static char *attached = NULL;

/* scalar object identifiers */
static const uint32_t upsIdentManufacturer[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 1, 1, 0 };
static const uint32_t upsIdentModel[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 1, 2, 0 };
static const uint32_t upsIdentUPSSoftwareVersion[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 1, 3, 0 };
static const uint32_t upsIdentAgentSoftwareVersion[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 1, 4, 0 };
static const uint32_t upsIdentName[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 1, 5, 0 };
static const uint32_t upsIdentAttachedDevices[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 1, 6, 0 };
static const uint32_t upsBatteryStatus[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 2, 1, 0 };
static const uint32_t upsSecondsOnBattery[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 2, 2, 0 };
static const uint32_t upsEstimatedMinutesRemaining[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 2, 3, 0 };
static const uint32_t upsEstimatedChargeRemaining[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 2, 4, 0 };
static const uint32_t upsBatteryVoltage[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 2, 5, 0 };
static const uint32_t upsBatteryTemperature[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 2, 7, 0 };
static const uint32_t upsInputLineBads[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 3, 1, 0 };
static const uint32_t upsInputNumLines[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 3, 2, 0 };
static const uint32_t upsInputLineIndex[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 3, 3, 1, 1, 1 };
static const uint32_t upsInputFrequency[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 3, 3, 1, 2, 1 };
static const uint32_t upsInputVoltage[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 3, 3, 1, 3, 1 };
static const uint32_t upsOutputSource[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 4, 1, 0 };
static const uint32_t upsOutputNumLines[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 4, 3, 0 };
static const uint32_t upsOutputLineIndex[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 4, 4, 1, 1, 1 };
static const uint32_t upsOutputVoltage[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 4, 4, 1, 2, 1 };
static const uint32_t upsOutputPercentLoad[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 4, 4, 1, 5, 1 };
static const uint32_t upsConfigOutputVoltage[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 9, 3, 0 };
static const uint32_t upsConfigLowBattTime[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 9, 7, 0 };
static const uint32_t upsConfigAudibleStatus[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 9, 8, 0 };
static const uint32_t upsConfigLowVoltageTransferPoint[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 9, 9, 0 };
static const uint32_t upsConfigHighVoltageTransferPoint[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 9, 10, 0 };

/* scalar function prototypes */
static int ident_manufacturer (snmp_value_t *,char *);
static int ident_model (snmp_value_t *,char *);
static int ident_firmware (snmp_value_t *,char *);
static int ident_software (snmp_value_t *,char *);
static int ident_identifier (snmp_value_t *,char *);
static int ident_attached (snmp_value_t *,char *);
static int battery_status (snmp_value_t *,char *);
static int battery_avail (snmp_value_t *,char *);
static int battery_remaining (snmp_value_t *,char *);
static int battery_charge (snmp_value_t *,char *);
static int battery_voltage (snmp_value_t *,char *);
static int battery_temperature (snmp_value_t *,char *);
static int input_transfers (snmp_value_t *,char *);
static int input_frequency (snmp_value_t *,char *);
static int input_voltage (snmp_value_t *,char *);
static int output_status (snmp_value_t *,char *);
static int output_voltage (snmp_value_t *,char *);
static int output_load (snmp_value_t *,char *);
static int config_outvoltage (snmp_value_t *,char *);
static int config_lowtime (snmp_value_t *,char *);
static int config_audio (snmp_value_t *,char *);
static int config_lowvoltage (snmp_value_t *,char *);
static int config_highvoltage (snmp_value_t *,char *);
static int dummy_index (snmp_value_t *,char *);

static struct scalar scalars[] =
{
   /* upsIdent */
   { NULL, ident_manufacturer, upsIdentManufacturer, 1 },
   { "MODEL", ident_model, upsIdentModel, 1 },
   { "FIRMWARE", ident_firmware, upsIdentUPSSoftwareVersion, 1 },
   { NULL, ident_software, upsIdentAgentSoftwareVersion, 1 },
   { NULL, ident_identifier, upsIdentName, 1 },
   { NULL, ident_attached, upsIdentAttachedDevices, 1 },

   /* upsBattery */
   { "STATFLAG", battery_status, upsBatteryStatus, 0 },
   { "TONBATT", battery_avail, upsSecondsOnBattery, 0 },
   { "TIMELEFT", battery_remaining, upsEstimatedMinutesRemaining, 0 },
   { "BCHARGE", battery_charge, upsEstimatedChargeRemaining, 0 },
   { "BATTV", battery_voltage, upsBatteryVoltage, 0 },
   { "ITEMP", battery_temperature, upsBatteryTemperature, 0 },

   /* upsInput */
   { "NUMXFERS", input_transfers, upsInputLineBads, 0 },
   { NULL, dummy_index, upsInputNumLines, 1 },
   { NULL, dummy_index, upsInputLineIndex, 1 },
   { "LINEFREQ", input_frequency, upsInputFrequency, 0 },
   { "LINEV", input_voltage, upsInputVoltage, 0 },

   /* upsOutput */
   { "STATFLAG", output_status, upsOutputSource, 0 },
   { NULL, dummy_index, upsOutputNumLines, 1 },
   { NULL, dummy_index, upsOutputLineIndex, 1 },
   { "OUTPUTV", output_voltage, upsOutputVoltage, 0 },
   { "LOADPCT", output_load, upsOutputPercentLoad, 0 },

   /* upsConfig */
   { "NOMOUTV", config_outvoltage, upsConfigOutputVoltage, 0 },
   { "DLOWBATT", config_lowtime, upsConfigLowBattTime, 0 },
   { NULL, config_audio, upsConfigAudibleStatus, 1 },
   { "LOTRANS", config_lowvoltage, upsConfigLowVoltageTransferPoint, 0 },
   { "HITRANS", config_highvoltage, upsConfigHighVoltageTransferPoint, 0 }
};

/* alarm object identifiers */
static const uint32_t upsAlarmsPresent[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 1, 0 };
static uint32_t upsAlarmId[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 6, 2, 1, 1, 0 };
static uint32_t upsAlarmDescr[13] = { 12, 43, 6, 1, 2, 1, 33, 1, 6, 2, 1, 2, 0 };
static uint32_t upsAlarmBatteryBad[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 1 };
static uint32_t upsAlarmOnBattery[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 2 };
static uint32_t upsAlarmLowBattery[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 3 };
static uint32_t upsAlarmInputBad[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 6 };
static uint32_t upsAlarmOutputOverload[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 8 };
static uint32_t upsAlarmDiagnosticTestFailed[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 19 };
static uint32_t upsAlarmCommunicationsLost[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 20 };
static uint32_t upsAlarmShutdownImminent[11] = { 10, 43, 6, 1, 2, 1, 33, 1, 6, 3, 23 };

static const struct alarm alarms[] =
{
   { upsAlarmBatteryBad, UPS_REPLACEBATT },
   { upsAlarmOnBattery, UPS_ONBATT },
   { upsAlarmLowBattery, UPS_BATTLOW },
   { upsAlarmInputBad, UPS_SMARTTRIM | UPS_SMARTBOOST | UPS_ONBATT },
   { upsAlarmOutputOverload, UPS_OVERLOAD },
   { upsAlarmDiagnosticTestFailed, UPS_SELFTEST },
   { upsAlarmCommunicationsLost, UPS_COMMLOST },
   { upsAlarmShutdownImminent, UPS_SHUTDOWNIMM }
};

static void out_of_memory (void)
{
   abz_set_error ("failed to allocate memory: %m");
}

static void parse_error (const struct tokens *tokens,const char *suffix)
{
   abz_set_error ("usage: %s %s",tokens->argv[0],suffix);
}

static void already_defined (const struct tokens *tokens)
{
   abz_set_error ("`%s' already defined",tokens->argv[0]);
}

static int ups_open (void)
{
   memset (&apcupsd,0L,sizeof (struct sockaddr_in));
   apcupsd.sin_family = AF_INET;
   apcupsd.sin_port = htons (DEFAULT_PORT);
   apcupsd.sin_addr.s_addr = INADDR_NONE;
   identifier = NULL;
   attached = NULL;

   return (0);
}

static void ups_close (void)
{
   if (identifier != NULL)
	 mem_free (identifier);

   if (attached != NULL)
	 mem_free (attached);

   ups_open ();
}

static int parse_apcupsd (struct tokens *tokens)
{
   char *host,*port;

   if (apcupsd.sin_addr.s_addr != INADDR_NONE)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"{ <host> | <addr> } [ : { <service> | <port> } ]");
		return (-1);
	 }

   host = tokens->argv[1];

   if ((port = strchr (host,':')) != NULL)
	 *port++ = '\0';

   if (atoa (&apcupsd.sin_addr.s_addr,host))
	 {
		abz_set_error ("invalid hostname: %s",host);
		return (-1);
	 }

   if (port != NULL && atop (&apcupsd.sin_port,port))
	 {
		abz_set_error ("invalid service/port: %s",port);
		return (-1);
	 }

   return (1);
}

static int parse_identifier (struct tokens *tokens)
{
   if (identifier != NULL)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<description>");
		return (-1);
	 }

   if ((identifier = mem_alloc (strlen (tokens->argv[1]) + 1)) == NULL)
	 {
		out_of_memory ();
		return (-1);
	 }

   strcpy (identifier,tokens->argv[1]);

   return (1);
}

static int parse_attached (struct tokens *tokens)
{
   if (attached != NULL)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<description>");
		return (-1);
	 }

   if ((attached = mem_alloc (strlen (tokens->argv[1]) + 1)) == NULL)
	 {
		out_of_memory ();
		return (-1);
	 }

   strcpy (attached,tokens->argv[1]);

   return (1);
}

static int ups_parse (struct tokens *tokens)
{
   static const struct
	 {
		const char *name;
		int (*parse) (struct tokens *);
	 } command[] =
	 {
		{ "apcupsd", parse_apcupsd },
		{ "identifier", parse_identifier },
		{ "attached", parse_attached }
	 };
   size_t i;

   abz_clear_error ();

   if (tokens == NULL)
	 {
		const char *missing =
		  apcupsd.sin_addr.s_addr == INADDR_NONE ? "apcupsd" :
		  identifier == NULL ? "identifier" :
		  attached == NULL ? "attached" :
		  NULL;

		if (missing != NULL)
		  {
			 abz_set_error ("unexpected end of file. `%s' statement missing",missing);
			 return (-1);
		  }

		return (0);
	 }

   for (i = 0; i < ARRAYSIZE (command); i++)
	 if (!strcmp (tokens->argv[0],command[i].name))
	   return (command[i].parse (tokens));

   return (0);
}

static int apc_open (struct sockaddr_in *addr)
{
   int fd;

   abz_clear_error ();

   if ((fd = socket (AF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
	 {
		abz_set_error ("socket: %m");
		return (-1);
	 }

   if (connect (fd,(struct sockaddr *) addr,sizeof (struct sockaddr_in)))
	 {
		abz_set_error ("connect %u.%u.%u.%u:%u: %m",
					   NIPQUAD (addr->sin_addr.s_addr),
					   addr->sin_port);
		close (fd);
		return (-1);
	 }

   return (fd);
}

static int apc_send (int fd,const void *buf,size_t count)
{
   ssize_t result;

   abz_clear_error ();

   do
	 {
		switch (result = write (fd,buf,count))
		  {
		   case -1:
			 if (errno != EINTR && errno != EAGAIN)
			   {
				  abz_set_error ("write: %m");
				  return (-1);
			   }
			 break;
		   case 0:
			 abz_set_error ("remote side closed connection");
			 return (-1);
		   default:
			 assert (result <= count);
			 count -= result;
			 buf += result;
		  }
	 }
   while (count);

   return (0);
}

static int apc_recv (int fd,void *buf,size_t count)
{
   ssize_t result;

   abz_clear_error ();

   do
	 {
		switch (result = read (fd,buf,count))
		  {
		   case -1:
			 if (errno != EINTR && errno != EAGAIN)
			   {
				  abz_set_error ("read: %m");
				  return (-1);
			   }
			 break;
		   case 0:
			 abz_set_error ("remote side closed connection");
			 return (-1);
		   default:
			 assert (result <= count);
			 count -= result;
			 buf += result;
		  }
	 }
   while (count);

   return (0);
}

static void apc_close (int fd)
{
   uint16_t len = 0;

   apc_send (fd,&len,sizeof (uint16_t));
   shutdown (fd,SHUT_RDWR);
   close (fd);
}

static int apc_query (int fd,const char *cmd)
{
   uint16_t len = htons (strlen (cmd));

   abz_clear_error ();

   if (apc_send (fd,&len,sizeof (uint16_t)) || apc_send (fd,cmd,ntohs (len)))
	 return (-1);

   return (0);
}

static int apc_poll (int fd,char *buf,size_t count)
{
   uint16_t len;

   abz_clear_error ();

   if (apc_recv (fd,&len,sizeof (uint16_t)))
	 return (-1);

   if (!(len = ntohs (len)))
	 return (0);

   if (len >= count)
	 {
		abz_set_error ("receive buffer too small (<%u bytes)",len);
		return (-1);
	 }

   if (apc_recv (fd,buf,len))
	 return (-1);

   buf[len] = '\0';

   return (len);
}

static int ident_manufacturer (snmp_value_t *value,char *null)
{
   static char manufacturer[] = "American Power Conversion Corporation";

   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (manufacturer);
   value->data.OCTET_STRING.buf = (uint8_t *) manufacturer;

   return (0);
}

static int ident_model (snmp_value_t *value,char *str)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (str);
   value->data.OCTET_STRING.buf = (uint8_t *) str;

   return (0);
}

static int ident_firmware (snmp_value_t *value,char *str)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (str);
   value->data.OCTET_STRING.buf = (uint8_t *) str;

   return (0);
}

static int ident_software (snmp_value_t *value,char *null)
{
   static char version[] = VERSION;

   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (version);
   value->data.OCTET_STRING.buf = (uint8_t *) version;

   return (0);
}

static int ident_identifier (snmp_value_t *value,char *null)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (identifier);
   value->data.OCTET_STRING.buf = (uint8_t *) identifier;

   return (0);
}

static int ident_attached (snmp_value_t *value,char *null)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (attached);
   value->data.OCTET_STRING.buf = (uint8_t *) attached;

   return (0);
}

static int getstats (unsigned int *status,const char *str)
{
   if (sscanf (str,"0x%X Status Flag",status) != 1)
	 {
		abz_set_error ("invalid status flags: %s",str);
		return (-1);
	 }

   if (*status & UPS_COMMLOST)
	 *status = UPS_COMMLOST;

   return (0);
}

static int battery_status (snmp_value_t *value,char *str)
{
   unsigned int status;

   if (getstats (&status,str))
	 return (-1);

   /*
	* Possible Values:
	*
	* unknown(1)
	* batteryNormal(2)
	* batteryLow(3)
	* batteryDepleted(4)
	*/

   value->type = BER_INTEGER;
   value->data.INTEGER = 1;

   if (status & (UPS_ONLINE | UPS_ONBATT | UPS_BATTLOW))
	 {
		value->data.INTEGER = 2;

		if (status & UPS_BATTLOW)
		  value->data.INTEGER = 3;
	 }

   return (0);
}

static int battery_avail (snmp_value_t *value,char *str)
{
   int seconds;

   if (sscanf (str,"%d seconds",&seconds) != 1 || seconds < 0)
	 {
		abz_set_error ("invalid time-on-batt: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = seconds;

   return (0);
}

static int battery_remaining (snmp_value_t *value,char *str)
{
   float minutes;

   if (sscanf (str,"%f Minutes",&minutes) != 1 || minutes < 0)
	 {
		abz_set_error ("invalid time-left: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (minutes + 0.5);

   if (!value->data.INTEGER)
	 value->data.INTEGER = 1;

   return (0);
}

static int battery_charge (snmp_value_t *value,char *str)
{
   float percent;

   if (sscanf (str,"%f Percent",&percent) != 1 || percent < 0 || percent > 100)
	 {
		abz_set_error ("invalid batt-charge: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (percent + 0.5);

   return (0);
}

static int battery_voltage (snmp_value_t *value,char *str)
{
   float volts;

   if (sscanf (str,"%f Volts",&volts) != 1 || volts < 0)
	 {
		abz_set_error ("invalid battery voltage: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (volts * 10.0 + 0.5);

   return (0);
}

static int battery_temperature (snmp_value_t *value,char *str)
{
   float temp;

   if (sscanf (str,"%f C Internal",&temp) != 1)
	 {
		abz_set_error ("invalid battery temperature: %s",str);
		return (-1);
	 }

   /*
	* This is wrong. It is supposed to be the Ambient
	* temperature and there is a register to retrieve that
	* value (AMBTEMP), but none of our UPS's support that.
	*
	* All the Smart UPS's and up at least support the internal
	* temperature (ITEMP), so I'm using that instead.
	*/

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (temp + 0.5);

   return (0);
}

static int input_transfers (snmp_value_t *value,char *str)
{
   int transfers;

   if (sscanf (str,"%d",&transfers) != 1 || transfers < 0)
	 {
		abz_set_error ("invalid number of transfers: %s",str);
		return (-1);
	 }

   value->type = BER_Counter32;
   value->data.Counter32 = transfers;

   return (0);
}

static int input_frequency (snmp_value_t *value,char *str)
{
   float hertz;

   if (sscanf (str,"%f Hz",&hertz) != 1 || hertz < 0)
	 {
		abz_set_error ("invalid input frequency: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (hertz * 10.0 + 0.5);

   return (0);
}

static int input_voltage (snmp_value_t *value,char *str)
{
   float volts;

   if (sscanf (str,"%f Volts",&volts) != 1 || volts < 0)
	 {
		abz_set_error ("invalid input voltage: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (volts + 0.5);

   return (0);
}

static int output_status (snmp_value_t *value,char *str)
{
   unsigned int status;

   if (getstats (&status,str))
	 return (-1);

   /*
	* Possible Values:
	*
	* other(1)
	* none(2)
	* normal(3)
	* bypass(4)
	* battery(5)
	* booster(6)
	* reducer(7)
	*/

   value->type = BER_INTEGER;
   value->data.INTEGER = 1;

   if (status & (UPS_ONLINE | UPS_ONBATT | UPS_SMARTBOOST | UPS_SMARTTRIM))
	 {
		value->data.INTEGER = 3;

		if (status & UPS_SMARTBOOST)
		  value->data.INTEGER = 6;

		if (status & UPS_SMARTTRIM)
		  value->data.INTEGER = 7;

		if (status & UPS_ONBATT)
		  value->data.INTEGER = 5;
	 }

   return (0);
}

static int output_voltage (snmp_value_t *value,char *str)
{
   float volts;

   if (sscanf (str,"%f Volts",&volts) != 1 || volts < 0)
	 {
		abz_set_error ("invalid output voltage: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (volts + 0.5);

   return (0);
}

static int output_load (snmp_value_t *value,char *str)
{
   float percent;

   if (sscanf (str,"%f Percent Load Capacity",&percent) != 1 || percent < 0 || percent > 200)
	 {
		abz_set_error ("invalid output voltage: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (percent + 0.5);

   return (0);
}

static int config_outvoltage (snmp_value_t *value,char *str)
{
   int volts;

   if (sscanf (str,"%d",&volts) != 1 || volts < 0)
	 {
		abz_set_error ("invalid nominal output voltage: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = volts;

   return (0);
}

static int config_lowtime (snmp_value_t *value,char *str)
{
   int minutes;

   if (sscanf (str,"%d Minutes",&minutes) != 1 || minutes < 0)
	 {
		abz_set_error ("invalid low-batt time: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = minutes;

   return (0);
}

static int config_audio (snmp_value_t *value,char *null)
{
   /*
	* Possible Values:
	*
	* disabled(1)
	* enabled(2)
	* muted(3)
	*/

   value->type = BER_INTEGER;
   value->data.INTEGER = 2;

   return (0);
}

static int config_lowvoltage (snmp_value_t *value,char *str)
{
   float volts;

   if (sscanf (str,"%f Volts",&volts) != 1 || volts < 0)
	 {
		abz_set_error ("invalid minimum line voltage: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (volts + 0.5);

   return (0);
}

static int config_highvoltage (snmp_value_t *value,char *str)
{
   float volts;

   if (sscanf (str,"%f Volts",&volts) != 1 || volts < 0)
	 {
		abz_set_error ("invalid maximum line voltage: %s",str);
		return (-1);
	 }

   value->type = BER_INTEGER;
   value->data.INTEGER = (uint32_t) (volts + 0.5);

   return (0);
}

static int dummy_index (snmp_value_t *value,char *null)
{
   value->type = BER_INTEGER;
   value->data.INTEGER = 1;

   return (0);
}

static int update_static (struct odb **odb)
{
   snmp_value_t value;
   size_t i;

   for (i = 0; i < ARRAYSIZE (scalars); i++)
	 if (scalars[i].name == NULL && scalars[i].once >= 0)
	   {
		  if (scalars[i].update (&value,NULL) || odb_add (odb,scalars[i].oid,&value))
			return (-1);

		  scalars[i].once = -scalars[i].once;
	   }

   return (0);
}

static int update_volatile (struct odb **odb,char *cmd,char *arg)
{
   snmp_value_t value;
   size_t i;

   for (i = 0; i < ARRAYSIZE (scalars); i++)
	 if (scalars[i].name != NULL && scalars[i].once >= 0 && !strcmp (scalars[i].name,cmd))
	   {
		  if (scalars[i].update (&value,arg) || odb_add (odb,scalars[i].oid,&value))
			return (-1);

		  scalars[i].once = -scalars[i].once;
	   }

   return (0);
}

static int update_alarms (struct odb **odb,unsigned int status)
{
   snmp_value_t value;
   size_t i;

   for (i = 0; i < ARRAYSIZE (alarms); i++)
	 if (status & alarms[i].mask)
	   {
		  upsAlarmId[12] = upsAlarmDescr[12] = i + 1;

		  value.type = BER_INTEGER;
		  value.data.INTEGER = i + 1;

		  if (odb_add (odb,upsAlarmId,&value))
			return (-1);

		  value.type = BER_OID;
		  value.data.OID = alarms[i].oid;

		  if (odb_add (odb,upsAlarmDescr,&value))
			return (-1);
	   }

   return (0);
}

static int ups_update (struct odb **odb)
{
   static char buf[BUFFER_SIZE];
   char *arg;
   int fd,result;
   unsigned int s1 = 0,s2 = 0;

   if (update_static (odb))
	 return (-1);

   if ((fd = apc_open (&apcupsd)) < 0)
	 return (-1);

   if (apc_query (fd,"status"))
	 {
		apc_close (fd);
		return (-1);
	 }

   while ((result = apc_poll (fd,buf,ARRAYSIZE (buf))) > 0)
	 {
		trim (buf);

		if ((arg = strchr (buf,':')) == NULL)
		  {
			 abz_set_error ("invalid apc data: %s",buf);
			 result = -1;
			 break;
		  }

		*arg++ = '\0';
		rtrim (buf);
		ltrim (arg);

		if (update_volatile (odb,buf,arg))
		  {
			 result = -1;
			 break;
		  }

		if (!strcmp (buf,"STATFLAG") && getstats (&s1,arg))
		  {
			 result = -1;
			 break;
		  }

		if (!strcmp (buf,"SELFTEST") && (!strcmp (arg,"BT") || !strcmp (arg,"NG")))
		  s2 = UPS_SELFTEST;
	 }

   apc_close (fd);

   if (!result)
	 result = update_alarms (odb,s1 | s2);

   return (result);
}

/* iso.org.dod.internet.mgmt.mib-2.upsMIB.upsObjects */
static const uint32_t upsObjects[8] = { 7, 43, 6, 1, 2, 1, 33, 1 };

/* iso.org.dod.internet.mgmt.mib-2.upsMIB */
static const uint32_t upsMIB[7] = { 6, 43, 6, 1, 2, 1, 33 };

struct module module =
{
   .name	= "ups",
   .descr	= "The MIB module to describe Uninterruptible Power Supplies",
   .mod_oid	= upsObjects,
   .con_oid	= upsMIB,
   .parse	= ups_parse,
   .open	= ups_open,
   .update	= ups_update,
   .close	= ups_close
};

