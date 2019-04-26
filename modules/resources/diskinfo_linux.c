
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <mntent.h>
#include <sys/vfs.h>

#include <debug/memory.h>
#include <abz/typedefs.h>
#include <abz/error.h>
#include <tinysnmp/unaligned.h>

#include "diskinfo.h"

struct fstype
{
   long stat;
   int snmp;
};

static const struct fstype types[] =
{
   { 0x0000adf5, 1 },			/* Acorn Advanced Disc Filing System				*/
   { 0x0000adff, 2 },			/* Amiga Fast File System							*/
   { 0x73757245, 3 },			/* CODA File System									*/
   { 0x012ff7b7, 19 },			/* Coherent File System								*/
   { 0x28cd3d45, 4 },			/* cram File System for small storage (ROMs etc)	*/
   { 0x00001373, -1 },			/* Device File System								*/
   { 0x0000ef51, 5 },			/* Old Ext2 File System								*/
   { 0x0000ef53, 5 },			/* Ext2/Ext3 File System							*/
   { 0xf995e849, 6 },			/* OS/2 HPFS File System							*/
   { 0x958458f6, -1 },			/* Huge TLB File System								*/
   { 0x00009660, 7 },			/* ISO 9660 (CDROM) File System						*/
   { 0x000072b6, 8 },			/* Journalling Flash File System					*/
   { 0x3153464a, 9 },			/* JFS File System									*/
   { 0x0000137f, 10 },			/* Original Minix File System						*/
   { 0x0000138f, 10 },			/* 30 Character Minix File System					*/
   { 0x00002468, 10 },			/* Minix V2 File System								*/
   { 0x00002478, 10 },			/* 30 Character Minix V2 File System				*/
   { 0x00004d44, 11 },			/* FAT-based File Systems							*/
   { 0x0000564c, 12 },			/* Novell Netware(tm) File System					*/
   { 0x00006969, 13 },			/* Network File Sharing Protocol					*/
   { 0x5346544e, 14 },			/* NTFS File System (Windows NT)					*/
   { 0x00009fa1, -1 },			/* Sun SPARC PROM device tree						*/
   { 0x00009fa0, -1 },			/* Proc File System									*/
   { 0x0000002f, 15 },			/* QNX4 File System									*/
   { 0x52654973, 16 },			/* ReiserFS Journalling File System					*/
   { 0x00007275, 17 },			/* ROM File System									*/
   { 0x0000517b, 18 },			/* Server Message Block (SMB) Protocol				*/
   { 0x012ff7b6, 19 },			/* SysV2 File System								*/
   { 0x012ff7b5, 19 },			/* SysV4 File System								*/
   { 0x01021994, 20 },			/* Virtual Memory File System						*/
   { 0x15013346, 21 },			/* UDF (DVD, CDRW, etc) File System					*/
   { 0x00011954, 22 },			/* UFS File System (SunOS, FreeBSD, etc)			*/
   { 0x00009fa2, -1 },			/* USB Device File System							*/
   { 0xa501fcf5, 23 },			/* VERITAS VxFS(TM) File System						*/
   { 0x012ff7b4, 19 },			/* Xenix File System								*/
   { 0x58465342, 24 }			/* XFS (SGI) Journalling File System				*/
};

void disk_destroy (struct diskinfo **list)
{
   struct diskinfo *a;

   while (*list != NULL)
	 {
		a = *list, *list = (*list)->next;

		mem_free (a->d_dev);
		mem_free (a->d_dir);
		mem_free (a);
	 }
}

static __inline__ void disk_insert (struct diskinfo **list,struct diskinfo *pt)
{
   struct diskinfo *a,*b;
   static int index = 1;

   for (a = b = *list; a != NULL; b = a, a = a->next)
	 if (!strcmp (a->d_dir,pt->d_dir))
	   {
		  mem_free (a->d_dev);
		  mem_free (a->d_dir);

		  a->d_dev = pt->d_dev;
		  a->d_dir = pt->d_dir;
		  a->d_type = pt->d_type;
		  a->d_total = pt->d_total;
		  a->d_free = pt->d_free;

		  mem_free (pt);

		  return;
	   }

   pt->d_index = index++;
   pt->next = NULL;

   if (*list != NULL)
	 b->next = pt;
   else
	 *list = pt;
}

int disk_update (struct diskinfo **list)
{
   static const char filename[] = _PATH_MOUNTED;
   int i,type,result = 0;
   struct statfs fs;
   struct mntent *entry;
   struct diskinfo *pt;
   FILE *fp;

   abz_clear_error ();

   if ((fp = setmntent (filename,"r")) == NULL)
	 {
		abz_set_error ("failed to open %s for reading: %m",filename);
		return (-1);
	 }

   while ((entry = getmntent (fp)) != NULL)
	 {
		if (statfs (entry->mnt_dir,&fs))
		  {
			 abz_set_error ("statfs(%s) failed: %m",entry->mnt_dir);
			 result = -1;
			 continue;
		  }

		for (i = 0; i < ARRAYSIZE (types); i++)
		  if (fs.f_type == types[i].stat)
			break;

		if (i < ARRAYSIZE (types))
		  {
			 if (types[i].snmp < 0)
			   continue;

			 type = types[i].snmp;
		  }
		else
		  {
			 if (!fs.f_blocks)
			   continue;

			 type = 0;
		  }

		if ((pt = mem_alloc (sizeof (struct diskinfo))) == NULL ||
			(pt->d_dev = mem_alloc (strlen (entry->mnt_fsname) + 1)) == NULL ||
			(pt->d_dir = mem_alloc (strlen (entry->mnt_dir) + 1)) == NULL)
		  {
			 abz_set_error ("failed to allocate memory: %m");
			 result = -1;

			 if (pt->d_dev != NULL)
			   mem_free (pt->d_dev);

			 if (pt != NULL)
			   mem_free (pt);

			 continue;
		  }

		strcpy (pt->d_dev,entry->mnt_fsname);
		strcpy (pt->d_dir,entry->mnt_dir);
		pt->d_type = type;
		put_unaligned (((uint64_t) fs.f_bsize * (uint64_t) fs.f_blocks) >> 20,&pt->d_total);
		put_unaligned (((uint64_t) fs.f_bsize * (uint64_t) fs.f_bavail) >> 20,&pt->d_free);

		disk_insert (list,pt);
	 }

   endmntent (fp);

   return (result);
}

