
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>

#include <debug/memory.h>
#include <debug/log.h>

#include <abz/getline.h>
#include <abz/trim.h>
#include <abz/atou64.h>
#include <abz/typedefs.h>
#include <abz/error.h>

#include "proc.h"

#define _PATH_PROC "/proc"
#define _PATH_PROCNET_DEV _PATH_PROC "/net/dev"

static int getifstats (struct devstats *dev,char *proc)
{
   uint64_t *var[] =
	 {
		&dev->rx_bytes,
		&dev->rx_packets,
		&dev->rx_errors,
		&dev->rx_dropped,
		&dev->rx_fifo_errors,
		&dev->rx_frame_errors,
		&dev->rx_compressed,
		&dev->multicast,
		&dev->tx_bytes,
		&dev->tx_packets,
		&dev->tx_errors,
		&dev->tx_dropped,
		&dev->tx_fifo_errors,
		&dev->collisions,
		&dev->tx_carrier_errors,
		&dev->tx_compressed
	 };
   char *d,*s = proc;
   int i;

   for (i = 0; i < ARRAYSIZE (var); i++)
	 {
		ltrim (s);

		if ((d = strchr (s,' ')) != NULL)
		  *d++ = '\0';

		if (atou64 (s,var[i]))
		  return (-1);

		s = d;
	 }

   return (s != NULL ? -1 : 0);
}

static void open_error (const char *filename)
{
   abz_set_error ("failed to open %s for reading: %m",filename);
}

static void parse_error (int line)
{
   abz_set_error ("while parsing %s: parse error on line %d",_PATH_PROCNET_DEV,line);
}

static void read_error (const char *filename)
{
   abz_set_error ("while parsing %s: %m",filename);
}

struct devstats *getdevstats_stub (const char *filename,int line,const char *function,size_t *n)
{
   static const char procnetfile[] = _PATH_PROCNET_DEV;
   int i,fd;
   char *s,*str;
   struct devstats *stats = NULL,*ptr;
   static const char *header[] =
	 {
		"Inter-|   Receive                                                |  Transmit",
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed"
	 };

   abz_clear_error ();

   if ((fd = open (procnetfile,O_RDONLY)) < 0)
	 {
		open_error (procnetfile);
		return (NULL);
	 }

   *n = 0;

   for (i = 0; (str = getline (fd)) != NULL; i++)
	 {
		if (i < 2)
		  {
			 if (strcmp (str,header[i]))
			   {
				  parse_error (i + 1);
				  close (fd);
				  mem_free (str);
				  return (NULL);
			   }
		  }
		else
		  {
			 ltrim (str);

			 if ((s = strchr (str,':')) == NULL)
			   {
				  parse_error (i + 1);
				  close (fd);
				  mem_free (str);
				  return (NULL);
			   }

			 *s++ = '\0';

			 if ((ptr = mem_realloc_stub (stats,(*n + 1) * sizeof (struct devstats),filename,line,function)) == NULL)
			   {
				  abz_set_error ("failed to allocate memory: %m");
				  if (stats != NULL) mem_free (stats);
				  close (fd);
				  mem_free (str);
				  return (NULL);
			   }

			 stats = ptr;

			 if (strlen (str) >= IFNAMSIZ || getifstats (stats + *n,s) < 0)
			   {
				  parse_error (i + 1);
				  if (stats != NULL) mem_free (stats);
				  close (fd);
				  mem_free (str);
				  return (NULL);
			   }

			 strcpy (stats[*n].dev,str);

			 (*n)++;
		  }

		mem_free (str);
	 }

   if (errno)
	 {
		read_error (procnetfile);
		if (stats != NULL) mem_free (stats);
		close (fd);
		return (NULL);
	 }

   close (fd);

   return (stats);
}

int getprocuptime (uint32_t *uptime)
{
   char filename[ARRAYSIZE (_PATH_PROC) + 32];
   int num,fd,ppid;
   char *str,*tmp;
   unsigned long start_time;
   char dummy_char;
   int dummy_int;
   int long dummy_ilong;
   unsigned long dummy_ulong;
   struct sysinfo info;

   abz_clear_error ();

   if (sysinfo (&info))
	 {
		abz_set_error ("failed to get overall system statistics");
		return (-1);
	 }

   sprintf (filename,"%s/%u/stat",_PATH_PROC,getpid ());

   if ((fd = open (filename,O_RDONLY)) < 0)
	 {
		open_error (filename);
		return (-1);
	 }

   if ((str = getline (fd)) == NULL)
	 {
		read_error (filename);
		close (fd);
		return (-1);
	 }

   close (fd);

   if ((tmp = strrchr (str,')')) == NULL)
	 {
		parse_error (1);
		mem_free (str);
		return (-1);
	 }

   num = sscanf (tmp,
				 ") %c "				/* state										*/
				 "%d %d %d %d %d "		/* ppid pgrp session tty_nr tty_pgrp			*/
				 "%lu "					/* flags										*/
				 "%lu %lu %lu %lu "		/* min_flt cmin_flt maj_flt cmaj_flt			*/
				 "%lu %lu %lu %lu "		/* tms_utime tms_stime tms_cutime tms_cstime	*/
				 "%ld %ld %ld %ld "		/* priority nice timeout it_real_value			*/
				 "%lu ",				/* start_time									*/
				 &dummy_char,
				 &ppid,&dummy_int,&dummy_int,&dummy_int,&dummy_int,
				 &dummy_ulong,
				 &dummy_ulong,&dummy_ulong,&dummy_ulong,&dummy_ulong,
				 &dummy_ulong,&dummy_ulong,&dummy_ulong,&dummy_ulong,
				 &dummy_ilong,&dummy_ilong,&dummy_ilong,&dummy_ilong,
				 &start_time);

   mem_free (str);

   if (num != 20 || ppid != getppid ())
	 {
		parse_error (1);
		return (-1);
	 }

   *uptime = info.uptime - start_time / 100;

   return (0);
}

#if 0
int main (void)
{
   struct devstats *stats;
   int i;
   size_t n;
   uint32_t uptime;

   mem_open (NULL);
   log_open (NULL,LOG_NOISY,LOG_HAVE_COLORS);
   atexit (log_close);
   atexit (mem_close);

   if (getprocuptime (&uptime))
	 {
		log_printf (LOG_ERROR,"%s\n",abz_get_error ());
		exit (EXIT_FAILURE);
	 }

   log_printf (LOG_NORMAL,"uptime %u seconds\n",uptime);

   if ((stats = getdevstats (&n)) == NULL)
	 {
		log_printf (LOG_ERROR,"%s\n",abz_get_error ());
		exit (EXIT_FAILURE);
	 }

   for (i = 0; i < n; i++)
	 log_printf (LOG_NORMAL,
				 "interface %s\n"
				 "   receive                   transmit\n"
				 "      bytes %-20" PRIu32 "bytes %" PRIu32 "\n"
				 "      packets %-18" PRIu32 "packets %" PRIu32 "\n"
				 "      errors %-19" PRIu32 "errors %" PRIu32 "\n"
				 "      dropped %-18" PRIu32 "dropped %" PRIu32 "\n"
				 "      fifo errors %-14" PRIu32 "fifo errors %" PRIu32 "\n"
				 "      frame errors %-13" PRIu32 "carrier errors %" PRIu32 "\n"
				 "      compressed %-15" PRIu32 "compressed %" PRIu32 "\n"
				 "      multicast %-16" PRIu32 "collisions %" PRIu32 "\n",
				 stats[i].dev,
				 stats[i].rx_bytes,stats[i].tx_bytes,
				 stats[i].rx_packets,stats[i].tx_packets,
				 stats[i].rx_errors,stats[i].tx_errors,
				 stats[i].rx_dropped,stats[i].tx_dropped,
				 stats[i].rx_fifo_errors,stats[i].tx_fifo_errors,
				 stats[i].rx_frame_errors,stats[i].tx_carrier_errors,
				 stats[i].rx_compressed,stats[i].tx_compressed,
				 stats[i].multicast,stats[i].collisions);

   mem_free (stats);

   exit (EXIT_SUCCESS);
}
#endif

