
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
#include <debug/log.h>
#include <ber/ber.h>
#include <abz/typedefs.h>
#include <tinysnmp/tinysnmp.h>

#include "show.h"

#define my_printf(fmt,args...) log_printf_stub(filename,line,function,level,fmt,##args)
#define my_puts(s) log_puts_stub(filename,line,function,level,s)
#define my_putc(c) log_putc_stub(filename,line,function,level,c)

static __inline__ int printable (int c)
{
   return ((c >= 32 && c <= 126) ||
		   (c >= 174 && c <= 223) ||
		   (c >= 242 && c <= 243) ||
		   (c >= 252 && c <= 253));
}

static void show_integer (const char *filename,int line,const char *function,
						  int level,const snmp_value_t *value)
{
   my_printf ("INTEGER %" PRId32,value->data.INTEGER);
}

static void show_counter32 (const char *filename,int line,const char *function,
							int level,const snmp_value_t *value)
{
   my_printf ("Counter32 %" PRIu32,value->data.Counter32);
}

static void show_gauge32 (const char *filename,int line,const char *function,
						  int level,const snmp_value_t *value)
{
   my_printf ("Gauge32 %" PRIu32,value->data.Gauge32);
}

static void show_timeticks (const char *filename,int line,const char *function,
							int level,const snmp_value_t *value)
{
   uint32_t day,ms,sec,min,hour;

   my_printf ("TimeTicks (%" PRIu32 ") ",value->data.TimeTicks);

   ms = value->data.TimeTicks % 100, day = (value->data.TimeTicks - ms) / 100;
   sec = day % 60, day = (day - sec) / 60;
   min = day % 60, day = (day - min) / 60;
   hour = day % 24, day = (day - hour) / 24;

   if (day)
	 my_printf ("%" PRIu32 " day%s, ",day,day > 1 ? "s" : "");

   my_printf ("%02" PRIu32 ":%02" PRIu32 ":%02" PRIu32 ".%02" PRIu32,hour,min,sec,ms);
}

static void show_counter64 (const char *filename,int line,const char *function,
							int level,const snmp_value_t *value)
{
   my_printf ("Counter64 %" PRIu64,value->data.Counter64);
}

static void show_oid (const char *filename,int line,const char *function,
					  int level,const snmp_value_t *value)
{
   uint32_t i;

   my_printf ("OBJECT IDENTIFIER %" PRIu32 ".%" PRIu32,
			  value->data.OID[1] / 40,
			  value->data.OID[1] % 40);

   for (i = 2; i <= value->data.OID[0]; i++)
	 my_printf (".%" PRIu32,value->data.OID[i]);
}

static void show_octet_string (const char *filename,int line,const char *function,
							   int level,const snmp_value_t *value)
{
   uint32_t i;
   int raw = 0;

   my_puts ("OCTET STRING");

   for (i = 0; i < value->data.OCTET_STRING.len && !raw; i++)
	 if (!printable (value->data.OCTET_STRING.buf[i]))
	   raw = 1;

   if (!raw)
	 {
		my_putc (' ');

		for (i = 0; i < value->data.OCTET_STRING.len; i++)
		  my_putc (value->data.OCTET_STRING.buf[i]);
	 }
   else
	 {
		for (i = 0; i < value->data.OCTET_STRING.len; i++)
		  my_printf (" %02" PRIx32,value->data.OCTET_STRING.buf[i]);
	 }
}

static void show_ipaddress (const char *filename,int line,const char *function,
							int level,const snmp_value_t *value)
{
   my_printf ("IpAddress %" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32,
			  NIPQUAD (value->data.IpAddress));
}

static void show_null (const char *filename,int line,const char *function,
					   int level,const snmp_value_t *value)
{
   my_puts ("No Such Name");
}

void show_stub (const char *filename,int line,const char *function,
				const uint32_t *oid,const snmp_value_t *value)
{
   int level = value->type == BER_NULL ? LOG_WARNING : LOG_NORMAL;
   static const struct
	 {
		uint8_t type;
		void (*show_type) (const char *,int,const char *,int,const snmp_value_t *);
	 } list[] =
	 {
		{ BER_INTEGER, show_integer },
		{ BER_Counter32, show_counter32 },
		{ BER_Gauge32, show_gauge32 },
		{ BER_TimeTicks, show_timeticks },
		{ BER_Counter64, show_counter64 },
		{ BER_OID, show_oid },
		{ BER_OCTET_STRING, show_octet_string },
		{ BER_IpAddress, show_ipaddress },
		{ BER_NULL, show_null }
	 };
   size_t i;

   my_printf ("%" PRIu32 ".%" PRIu32,oid[1] / 40,oid[1] % 40);

   for (i = 2; i <= oid[0]; i++)
	 my_printf (".%" PRIu32,oid[i]);

   my_puts (" = ");

   for (i = 0; i < ARRAYSIZE (list); i++)
	 if (value->type == list[i].type)
	   {
		  list[i].show_type (filename,line,function,level,value);
		  my_putc ('\n');
		  return;
	   }

   my_puts ("(unknown)\n");
}

