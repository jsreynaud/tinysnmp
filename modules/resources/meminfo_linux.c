
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

#define _ISOC99_SOURCE

#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <abz/trim.h>
#include <abz/getline.h>
#include <abz/typedefs.h>
#include <abz/error.h>

#include <debug/memory.h>

#include "meminfo.h"

/*
 * This should work on Linux systems with a sysinfo() system call
 * implementation. From the sysinfo(2) manpage:
 *
 *        The Linux kernel has a sysinfo system call since 0.98.pl6.
 *        Linux  libc  contains a sysinfo() routine since 5.3.5, and
 *        glibc has one since 1.90.
 *
 * To actually get a valid value for cached memory, you'll need a
 * valid Linux /proc file system as well. If /proc/meminfo can
 * be parsed and looks correct, it's values override the values
 * returned by the sysinfo() call.
 */

static int procinfo (int args,const char *fmt, ...)
{
   static const char filename[] = "/proc/meminfo";
   va_list ap;
   char *buf;
   int fd;

   abz_clear_error ();

   if ((fd = open (filename,O_RDONLY)) < 0)
	 {
		abz_set_error ("failed to open %s for reading: %m",filename);
		return (-1);
	 }

   va_start (ap,fmt);

   while ((buf = getline (fd)) != NULL)
	 {
		trim (buf);

		if (args == vsscanf (buf,fmt,ap))
		  {
			 close (fd);
			 mem_free (buf);
			 return (0);
		  }

		mem_free (buf);
	 }

   va_end (ap);

   abz_set_error ("while reading from %s: %m",filename);

   close (fd);

   return (-1);
}

static void sysinfo_failed (void)
{
   abz_set_error ("failed to get overall system statistics: %m");
}

int getmeminfo (struct meminfo *info)
{
   struct sysinfo si;
   uint64_t mem_unit;

   abz_clear_error ();

   memset (info,0L,sizeof (struct meminfo));

   /* 2.4.x - 2.6.x */

   if (!procinfo (2,"MemTotal: %" SCNu64 " kB",&info->mem_total) &&
	   !procinfo (2,"MemFree: %" SCNu64 " kB",&info->mem_free) &&
	   !procinfo (2,"Buffers: %" SCNu64 " kB",&info->mem_buffer) &&
	   !procinfo (2,"Cached: %" SCNu64 " kB",&info->mem_cache))
	 {
		mem_unit = 1024;
		return (0);
	 }

   /* 2.2.x */

   if (!procinfo (4,
				  "Mem: %" SCNu64 " %*" SCNu64 " %" SCNu64 " %*" SCNu64 " %" SCNu64 " %" SCNu64,
				  &info->mem_total,
				  &info->mem_free,
				  &info->mem_buffer,
				  &info->mem_cache))
	 {
		mem_unit = 1;
		return (0);
	 }

   /* anything else */

   if (sysinfo (&si))
	 {
		sysinfo_failed ();
		return (-1);
	 }

   mem_unit = si.mem_unit ? si.mem_unit : 1;
   info->mem_total = si.totalram * mem_unit;
   info->mem_free = si.freeram * mem_unit;
   info->mem_buffer = si.bufferram * mem_unit;

   return (0);
}

int getswapinfo (struct swapinfo *info)
{
   struct sysinfo si;
   uint64_t mem_unit;

   abz_clear_error ();

   memset (info,0L,sizeof (struct swapinfo));

   /* 2.4.x - 2.6.x */

   if (!procinfo (2,"SwapTotal: %" SCNu64 " kB",&info->swap_total) &&
	   !procinfo (2,"SwapFree: %" SCNu64 " kB",&info->swap_free))
	 {
		mem_unit = 1024;
		return (0);
	 }

   /* 2.2.x */

   if (!procinfo (2,
				  "Swap: %" SCNu64 " %*" SCNu64 " %" SCNu64,
				  &info->swap_total,
				  &info->swap_free))
	 {
		mem_unit = 1;
		return (0);
	 }

   /* anything else */

   if (sysinfo (&si))
	 {
		sysinfo_failed ();
		return (-1);
	 }

   mem_unit = si.mem_unit ? si.mem_unit : 1;
   info->swap_total = si.totalswap * mem_unit;
   info->swap_free = si.freeswap * mem_unit;

   return (0);
}

