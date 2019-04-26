
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

#include <time.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/types.h>

#include <debug/log.h>
#include <debug/memory.h>

#include <abz/typedefs.h>
#include <abz/error.h>
#include <abz/tokens.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/odb.h>
#include <tinysnmp/agent/module.h>

#include "module.h"

static const char *library = NULL;
static struct module *modules = NULL;

static void save_dl_error (const char *function)
{
   const char *str = dlerror ();

   if (str != NULL)
	 abz_set_error ("%s",str);
   else
	 abz_set_error ("%s failed",function);
}

static __inline__ char *pathcat (const char *path,const char *name)
{
   char *filename;
   size_t length = strlen (path);

   if ((filename = mem_alloc (length + strlen (name) + 2)) == NULL)
	 return (NULL);

   strcpy (filename,path);

   if (path[length - 1] != '/')
	 strcpy (filename + length++,"/");

   strcpy (filename + length,name);

   return (filename);
}

static int oidsub (const uint32_t *base,const uint32_t *oid)
{
   uint32_t len = *base;

   if (*base > *oid)
	 return (0);

   while (len && *++base == *++oid)
	 len--;

   return (len ? 0 : 1);
}

static int oidcmp (const uint32_t *base,const uint32_t *oid)
{
   uint32_t saved = *base - *oid,len = *base < *oid ? *base : *oid;

   while (len && *++base == *++oid)
	 len--;

   return (len ? *base - *oid : saved);
}

static int module_register (struct module *module,int ext)
{
   int failed = 1;

   abz_clear_error ();

   odb_create (&module->cache);
   module->timestamp = 0;
   module->parsing = 0;
   module->next = NULL;

   do
	 {
		if (module->name == NULL)
		  {
			 abz_set_error ("name is null");
			 break;
		  }

		if (module->update == NULL)
		  {
			 abz_set_error ("update callbacks is missing");
			 break;
		  }

		if (module->mod_oid == NULL || (ext && module->con_oid == NULL))
		  {
			 abz_set_error ("exported oid range is null");
			 break;
		  }

		if (!ext && module->con_oid != NULL)
		  {
			 abz_set_error ("internal module defines a conformance oid");
			 break;
		  }

		if (module->open != NULL && module->open ())
		  break;

		if (ext && module_extend (module->con_oid,module->descr))
		  {
			 if (module->close != NULL)
			   module->close ();

			 break;
		  }

		failed = 0;
	 }
   while (0);

   if (failed)
	 {
		log_printf (LOG_WARNING,
					"while loading module %s:\n"
					"    %s\n"
					"    not loading module %s\n",
					library,abz_get_error (),module->name);
		return (-1);
	 }

   if (modules != NULL)
	 {
		struct module *cur,*prev;

		for (cur = modules, prev = NULL; cur != NULL; prev = cur, cur = cur->next)
		  if (oidcmp (cur->mod_oid,module->mod_oid) > 0)
			break;

		if (cur != NULL)
		  {
			 module->next = cur;
			 if (prev != NULL)
			   prev->next = module;
			 else
			   modules = module;
		  }
		else prev->next = module;
	 }
   else modules = module;

   log_printf (LOG_VERBOSE,"registered module %s\n",module->name);

   return (0);
}

static __inline__ void module_load (const char *filename)
{
   void *handle;
   struct module *module;

   abz_clear_error ();

   /*
	* WARNING:
	*
	* dlclose() should never be called after any of the module
	* functions have been called.
	*
	* The reason for this is that those functions might leak
	* memory and cause the server to crash when it discover
	* leaks right at the end.
	*
	* We therefore silently ignore the open modules and let
	* the operating system close it for us when the server
	* terminates.
	*/

   library = filename;

   if ((handle = dlopen (filename,RTLD_NOW)) == NULL)
	 {
		save_dl_error ("dlopen");
		log_printf (LOG_WARNING,
					"failed to load module %s: %s\n",
					filename,abz_get_error ());
		return;
	 }

   if ((module = dlsym (handle,"module")) == NULL)
	 {
		save_dl_error ("dlsym");
		log_printf (LOG_WARNING,
					"failed to load module %s: %s\n",
					filename,abz_get_error ());
		return;
	 }

   module_register (module,1);
}

int module_open (const char *path)
{
   static const uint32_t snmpMIB[7] = { 6, 43, 6, 1, 6, 3, 1 };
   DIR *dir;
   struct dirent *entry;
   struct module *module[] = { &module_system, &module_snmp };
   size_t i;

   for (i = 0; i < ARRAYSIZE (module); i++)
	 if (module_register (module[i],0))
	   return (-1);

   if (module_extend (snmpMIB,"The MIB module for SNMP entities"))
	 {
		log_printf (LOG_ERROR,"failed to register internal modules: %s\n",abz_get_error ());
		return (-1);
	 }

   if ((dir = opendir (path)) == NULL)
	 {
		log_printf (LOG_ERROR,"failed to open directory %s: %m\n",path);
		return (-1);
	 }

   while ((entry = readdir (dir)) != NULL)
	 if (!strcmp (entry->d_name + strlen (entry->d_name) - 3,".so"))
	   {
		  char *filename;

		  abz_clear_error ();

		  if ((filename = pathcat (path,entry->d_name)) == NULL)
			{
			   log_printf (LOG_WARNING,"failed to allocate memory: %m\n");
			   continue;
			}

		  module_load (filename);

		  mem_free (filename);
	   }

   closedir (dir);

   if (modules == NULL)
	 {
		log_printf (LOG_NORMAL,"no libraries found\n");
		return (-1);
	 }

   return (0);
}

void module_close (void)
{
   struct module *node;

   while (modules != NULL)
	 {
		if (modules->close != NULL)
		  modules->close ();

		odb_destroy (&modules->cache);

		node = modules, modules = modules->next;
	 }
}

static void module_update (struct module *module,time_t timeout)
{
   static const char system[] = "system";
   time_t now = time (NULL);

   if (now - module->timestamp >= timeout)
	 {
		module->timestamp = now;

		/*
		 * We can't delete the system module's object identifiers
		 * automatically since it exports the sysORID's which is
		 * not added by its update() callback.
		 */

		if (module->con_oid != NULL || strcmp (module->name,system))
		  odb_remove (&module->cache,module->mod_oid);

		if (module->update != NULL && module->update (&module->cache))
		  {
			 log_printf (LOG_WARNING,
						 "failed to update module %s: %s\n",
						 module->name,abz_get_error ());

			 if (module->con_oid != NULL || strcmp (module->name,system))
			   odb_remove (&module->cache,module->mod_oid);
		  }
	 }
}

const snmp_value_t *module_find (const uint32_t *oid,time_t timeout)
{
   struct module *node;

   for (node = modules; node != NULL; node = node->next)
	 if (oidsub (node->mod_oid,oid))
	   {
		  module_update (node,timeout);
		  return (odb_find (node->cache,oid));
	   }

   return (NULL);
}

snmp_next_value_t *module_find_next (const uint32_t *oid,time_t timeout)
{
   struct module *node;
   snmp_next_value_t *next;

   for (node = modules; node != NULL; node = node->next)
	 if (oidsub (node->mod_oid,oid) || oidcmp (node->mod_oid,oid) >= 0)
	   break;

   while (node != NULL)
	 {
		module_update (node,timeout);

		if ((next = odb_find_next (node->cache,oid)) != NULL)
		  return (next);

		node = node->next;
	 }

   return (NULL);
}

module_parse_t module_parse (const char *name)
{
   struct module *node;

   abz_clear_error ();

   for (node = modules; node != NULL; node = node->next)
	 if (!strcmp (node->name,name))
	   {
		  if (node->parsing)
			{
			   abz_set_error ("module %s already defined",name);
			   return (NULL);
			}

		  if (node->parse == NULL)
			{
			   abz_set_error ("module %s does not have any configuration",name);
			   return (NULL);
			}

		  node->parsing = 1;

		  return (node->parse);
	   }

   abz_set_error ("no such module");

   return (NULL);
}

int module_parse_end (void)
{
   const struct module *node;

   abz_clear_error ();

   for (node = modules; node != NULL; node = node->next)
	 if (node->parse != NULL && node->parse (NULL))
	   return (-1);

   return (0);
}

int module_present (const char *name)
{
   const struct module *node;

   for (node = modules; node != NULL; node = node->next)
	 if (!strcmp (node->name,name))
	   return (1);

   return (0);
}

#ifdef DEBUG
void module_print_stub (const char *filename,int line,const char *function,int level)
{
   struct module *node;
   uint32_t i;

   for (node = modules; node != NULL; node = node->next)
	 {
		log_printf_stub (filename,line,function,level,
						 "module %s\n"
						 " callbacks",
						 node->name);

		if (node->parse != NULL)
		  log_puts_stub (filename,line,function,level," parse");

		if (node->open != NULL)
		  log_puts_stub (filename,line,function,level," open");

		if (node->update != NULL)
		  log_puts_stub (filename,line,function,level," update");

		if (node->close != NULL)
		  log_puts_stub (filename,line,function,level," close");

		log_printf_stub (filename,line,function,level,
						 "\n oid %" PRIu32 ".%" PRIu32,
						 node->mod_oid[1] / 40,node->mod_oid[1] % 40);

		for (i = 2; i <= node->mod_oid[0]; i++)
		  log_printf_stub (filename,line,function,level,".%" PRIu32,node->mod_oid[i]);

		log_putc_stub (filename,line,function,level,'\n');
	 }
}
#endif	/* #ifdef DEBUG */

