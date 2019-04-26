
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <debug/memory.h>

#include <abz/tokens.h>
#include <abz/error.h>
#include <abz/getline.h>
#include <abz/sanitize.h>

#include "config.h"
#include "agent.h"

int config_parse (struct agent *agent,const char *filename)
{
   int fd,result = 0,n = 0;
   char *line;
   struct tokens tokens;

   abz_clear_error ();

   if ((fd = open (filename,O_RDONLY)) < 0)
	 {
		abz_set_error ("failed to open %s for reading: %m",filename);
		return (-1);
	 }

   while ((line = getline (fd)) != NULL && !result)
	 {
		n++;

		sanitize (line);

		if (*line == '\0')
		  {
			 mem_free (line);
			 continue;
		  }

		result = tokens_parse (&tokens,line);

		mem_free (line);
		line = NULL;

		if (!result)
		  {
			 result = agent_parse (agent,&tokens);
			 tokens_destroy (&tokens);
		  }
	 }

   if (line == NULL)
	 n++;
   else
	 mem_free (line);

   if (result || (result = agent_parse (agent,NULL)) || module_parse_end ())
	 {
		char buf[256];
		strncpy (buf,abz_get_error (),sizeof (buf));
		buf[sizeof (buf) - 1] = '\0';
		abz_clear_error ();
		abz_set_error ("parse error on line %d: %s",n,buf);
		result = -1;
	 }

   close (fd);

   return (result);
}

