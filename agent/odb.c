
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
#include <stdint.h>
#include <string.h>

#include <abz/error.h>
#include <debug/memory.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/unaligned.h>
#include <tinysnmp/agent/odb.h>

struct node
{
   uint32_t n;
   const uint32_t *oid;
   snmp_value_t value;
};

struct branch
{
   uint32_t *oid;
   const snmp_value_t *value;
};

static void out_of_memory (void)
{
   abz_set_error ("failed to allocate memory: %m");
}

static void oid_exist (void)
{
   abz_set_error ("object identifier (or superset of) already exist");
}

static void oid_missing (void)
{
   abz_set_error ("object identifier not found");
}

void odb_create (struct odb **odb)
{
   *odb = NULL;
}

static void snmp_free_value (snmp_value_t *value)
{
   if (value->type == BER_OID)
	 mem_free (value->data.OID);
   else if (value->type == BER_OCTET_STRING && value->data.OCTET_STRING.len)
	 mem_free (value->data.OCTET_STRING.buf);
}

static int snmp_copy_value (snmp_value_t *dest,const snmp_value_t *src)
{
   copy_unaligned (dest,src);

   if (src->type == BER_OCTET_STRING)
	 {
		uint32_t len = src->data.OCTET_STRING.len;

		if (len)
		  {
			 if ((dest->data.OCTET_STRING.buf = mem_alloc (len)) == NULL)
			   {
				  out_of_memory ();
				  return (-1);
			   }

			 memcpy (dest->data.OCTET_STRING.buf,src->data.OCTET_STRING.buf,len);
		  }
	 }
   else if (src->type == BER_OID)
	 {
		uint32_t len = (src->data.OID[0] + 1) * sizeof (uint32_t);

		if ((dest->data.OID = mem_alloc (len)) == NULL)
		  {
			 out_of_memory ();
			 return (-1);
		  }

		memcpy (dest->data.OID,src->data.OID,len);
	 }

   return (0);
}

void odb_destroy (struct odb **odb)
{
   if (*odb != NULL)
	 {
		if ((*odb)->sibling != NULL)
		  odb_destroy (&(*odb)->sibling);

		if ((*odb)->child != NULL)
		  odb_destroy (&(*odb)->child);

		if ((*odb)->type == VALUE)
		  snmp_free_value (&(*odb)->data.value);

		mem_free (*odb);
		*odb = NULL;
	 }
}

static struct odb *tree_create (node_t type,const struct node *node)
{
   struct odb *odb;

   if ((odb = mem_alloc (sizeof (struct odb))) == NULL)
	 {
		out_of_memory ();
		return (NULL);
	 }

   odb->type = type;
   odb->parent = odb->sibling = odb->child = NULL;

   if (type == VALUE)
	 copy_unaligned (&odb->data.value,&node->value);
   else
	 odb->data.node = node->oid[0];

   return (odb);
}

/* declaration needed by tree_add_sibling() and tree_add_child() */
static int tree_add (struct odb **,const struct node *);

static int tree_add_sibling (struct odb **odb,const struct node *node)
{
   if (tree_add (&(*odb)->sibling,node))
	 {
		if ((*odb)->sibling != NULL && (*odb)->sibling->child == NULL)
		  {
			 struct odb *sibling = (*odb)->sibling;
			 (*odb)->sibling = (*odb)->sibling->sibling;
			 mem_free (sibling);
		  }

		return (-1);
	 }

   if ((*odb)->sibling != NULL)
	 (*odb)->sibling->parent = (*odb)->parent;

   return (0);
}

static int tree_add_child (struct odb **odb,const struct node *node)
{
   struct node next =
	 {
		.n		= node->n - 1,
		.oid	= node->oid + 1
	 };

   memcpy (&next.value,&node->value,sizeof (snmp_value_t));

   if (tree_add (&(*odb)->child,&next))
	 {
		if ((*odb)->child == NULL && (*odb)->sibling == NULL)
		  {
			 mem_free (*odb);
			 *odb = NULL;
		  }

		return (-1);
	 }

   if ((*odb)->child != NULL)
	 (*odb)->child->parent = *odb;

   return (0);
}

static int tree_add (struct odb **odb,const struct node *node)
{
   if (!node->n)
	 {
		if (*odb != NULL)
		  {
			 oid_exist ();
			 return (-1);
		  }

		return ((*odb = tree_create (VALUE,node)) != NULL ? 0 : -1);
	 }

   if (*odb == NULL)
	 {
		if ((*odb = tree_create (NODE,node)) == NULL)
		  return (-1);

		return (tree_add_child (odb,node));
	 }

   if ((*odb)->type == NODE)
	 {
		if ((*odb)->data.node > node->oid[0])
		  {
			 struct odb *tmp;

			 if ((tmp = tree_create (NODE,node)) == NULL)
			   return (-1);

			 tmp->sibling = *odb;
			 tmp->parent = (*odb)->parent;
			 *odb = tmp;

			 return (tree_add_child (odb,node));
		  }

		if ((*odb)->data.node < node->oid[0])
		  return (tree_add_sibling (odb,node));

		if (node->n > 1)
		  return (tree_add_child (odb,node));
	 }

   oid_exist ();
   return (-1);
}

int odb_add (struct odb **odb,const uint32_t *oid,const snmp_value_t *value)
{
   struct node node =
	 {
		.n		= oid[0],
		.oid	= oid + 1
	 };

   abz_clear_error ();

   if (snmp_copy_value (&node.value,value))
	 return (-1);

   if (tree_add (odb,&node))
	 {
		snmp_free_value (&node.value);
		return (-1);
	 }

   return (0);
}

static int tree_remove (struct odb **odb,struct node *node)
{
   if (*odb == NULL ||
	   (*odb)->child == NULL ||
	   (*odb)->type != NODE ||
	   !node->n ||
	   (*odb)->data.node > node->oid[0])
	 return (-1);

   if ((*odb)->data.node < node->oid[0])
	 {
		if ((*odb)->sibling != NULL)
		  {
			 struct odb *sibling = (*odb)->sibling->sibling;

			 if (tree_remove (&(*odb)->sibling,node))
			   return (-1);

			 if ((*odb)->sibling == NULL)
			   (*odb)->sibling = sibling;

			 return (0);
		  }

		return (-1);
	 }

   if (node->n == 1)
	 {
		struct odb *sibling = (*odb)->sibling;

		(*odb)->sibling = NULL;
		odb_destroy (odb);
		*odb = sibling;

		return (0);
	 }

   if ((*odb)->child->type == NODE)
	 {
		struct node next =
		  {
			 .n		= node->n - 1,
			 .oid	= node->oid + 1
		  };
		struct odb *child = (*odb)->child->sibling;

		if (tree_remove (&(*odb)->child,&next))
		  return (-1);

		if ((*odb)->child == NULL)
		  (*odb)->child = child;

		if ((*odb)->child == NULL)
		  {
			 struct odb *sibling = (*odb)->sibling;

			 mem_free (*odb);
			 *odb = sibling;
		  }

		return (0);
	 }

   return (-1);
}

void odb_remove (struct odb **odb,const uint32_t *oid)
{
   struct node node =
	 {
		.n		= oid[0],
		.oid	= oid + 1
	 };

   tree_remove (odb,&node);
}

static const snmp_value_t *tree_find (const struct odb *odb,struct node *node)
{
   struct node next;

   if (odb == NULL || odb->child == NULL || !node->n || odb->data.node > node->oid[0])
	 {
		oid_missing ();
		return (NULL);
	 }

   if (odb->data.node < node->oid[0])
	 return (tree_find (odb->sibling,node));

   if (odb->child->child == NULL && node->n == 1)
	 return (&odb->child->data.value);

   next.oid = node->oid + 1;
   next.n = node->n - 1;

   return (tree_find (odb->child,&next));
}

const snmp_value_t *odb_find (const struct odb *odb,const uint32_t *oid)
{
   struct node node =
	 {
		.n		= oid[0],
		.oid	= oid + 1
	 };

   abz_clear_error ();

   return (tree_find (odb,&node));
}

static struct branch *tree_find_first (const struct odb *odb)
{
   struct branch *branch;
   const struct odb *tmp;
   uint32_t i,n = 1;

   if ((branch = mem_alloc (sizeof (struct branch))) == NULL)
	 {
		out_of_memory ();
		return (NULL);
	 }

   while (odb->child->type != VALUE)
	 odb = odb->child;

   for (tmp = odb->parent; tmp != NULL; tmp = tmp->parent)
	 n++;

   if ((branch->oid = mem_alloc ((n + 1) * sizeof (uint32_t))) == NULL)
	 {
		out_of_memory ();
		mem_free (branch);
		return (NULL);
	 }

   branch->oid[0] = n;

   for (tmp = odb, i = n; tmp != NULL; tmp = tmp->parent)
	 branch->oid[i--] = tmp->data.node;

   branch->value = &odb->child->data.value;

   return (branch);
}

static struct branch *tree_find_next (const struct odb *odb,const struct node *node)
{
   if (odb == NULL ||
	   odb->child == NULL ||
	   odb->type == VALUE ||
	   !node->n)
	 {
		oid_missing ();
		return (NULL);
	 }

   if (odb->data.node > node->oid[0])
	 return (tree_find_first (odb));

   if (odb->data.node == node->oid[0])
	 {
		if (node->n != 1)
		  {
			 struct branch *branch;
			 struct node next =
			   {
				  .n	= node->n - 1,
				  .oid	= node->oid + 1
			   };

			 if ((branch = tree_find_next (odb->child,&next)) != NULL)
			   return (branch);
		  }
		else if (odb->child->child != NULL)
		  return (tree_find_first (odb));
	 }

   return (tree_find_next (odb->sibling,node));
}

snmp_next_value_t *odb_find_next (const struct odb *odb,const uint32_t *oid)
{
   struct branch *branch;
   snmp_next_value_t *next;
   struct node node =
	 {
		.n		= oid[0],
		.oid	= oid + 1
	 };

   abz_clear_error ();

   if ((branch = tree_find_next (odb,&node)) == NULL)
	 return (NULL);

   if ((next = mem_alloc (sizeof (snmp_next_value_t))) == NULL)
	 {
		out_of_memory ();
		mem_free (branch->oid);
		mem_free (branch);
		return (NULL);
	 }

   next->oid = branch->oid;

   if (snmp_copy_value (&next->value,branch->value))
	 {
		mem_free (branch->oid);
		mem_free (branch);
		return (NULL);
	 }

   mem_free (branch);

   return (next);
}

#ifdef DEBUG

#include <debug/log.h>

static uint32_t tree_get_depth (const struct odb *odb,uint32_t depth)
{
   if (odb != NULL && odb->child != NULL)
	 {
		uint32_t child = 0,sibling = 0;

		if (odb->child->child != NULL)
		  child = tree_get_depth (odb->child,depth + 1);

		if (odb->sibling != NULL)
		  sibling = tree_get_depth (odb->sibling,depth);

		if (depth < child)
		  depth = child;

		if (depth < sibling)
		  depth = sibling;
	 }

   return (depth);
}

static void tree_show_integer (const char *filename,int line,const char *function,
							   int level,const snmp_value_t *value)
{
   log_printf_stub (filename,line,function,level,
					"INTEGER %" PRId32,
					value->data.INTEGER);
}

static void tree_show_counter32 (const char *filename,int line,const char *function,
								 int level,const snmp_value_t *value)
{
   log_printf_stub (filename,line,function,level,
					"Counter32 %" PRIu32,
					value->data.Counter32);
}

static void tree_show_gauge32 (const char *filename,int line,const char *function,
							   int level,const snmp_value_t *value)
{
   log_printf_stub (filename,line,function,level,
					"Gauge32 %" PRIu32,
					value->data.Gauge32);
}

static void tree_show_timeticks (const char *filename,int line,const char *function,
								 int level,const snmp_value_t *value)
{
   uint32_t day,ms,sec,min,hour;

   log_printf_stub (filename,line,function,level,
					"TimeTicks (%" PRIu32 ") ",
					value->data.TimeTicks);

   ms = value->data.TimeTicks % 100, day = (value->data.TimeTicks - ms) / 100;
   sec = day % 60, day = (day - sec) / 60;
   min = day % 60, day = (day - min) / 60;
   hour = day % 24, day = (day - hour) / 24;

   if (day)
	 log_printf_stub (filename,line,function,level,
					  "%" PRIu32 " day%s, ",
					  day,day > 1 ? "s" : "");

   log_printf_stub (filename,line,function,level,
					"%02" PRIu32 ":%02" PRIu32 ":%02" PRIu32 ".%02" PRIu32,
					hour,min,sec,ms);
}

static void tree_show_counter64 (const char *filename,int line,const char *function,
								 int level,const snmp_value_t *value)
{
   log_printf_stub (filename,line,function,level,
					"Counter64 %" PRIu64,
					value->data.Counter64);
}

static void tree_show_oid (const char *filename,int line,const char *function,
						   int level,const snmp_value_t *value)
{
   uint32_t i;

   log_printf_stub (filename,line,function,level,
					"OBJECT IDENTIFIER %" PRIu32 ".%" PRIu32,
					value->data.OID[1] / 40,value->data.OID[1] % 40);

   for (i = 2; i <= value->data.OID[0]; i++)
	 log_printf_stub (filename,line,function,level,
					  ".%" PRIu32,
					  value->data.OID[i]);
}

static __inline__ int printable (int c)
{
   return ((c >= 32 && c <= 126) ||
		   (c >= 174 && c <= 223) ||
		   (c >= 242 && c <= 243) ||
		   (c >= 252 && c <= 253));
}

static void tree_show_octet_string (const char *filename,int line,const char *function,
									int level,const snmp_value_t *value)
{
   uint32_t i;
   int raw = 0;

   log_puts_stub (filename,line,function,level,"OCTET STRING");

   for (i = 0; i < value->data.OCTET_STRING.len && !raw; i++)
	 if (!printable (value->data.OCTET_STRING.buf[i]))
	   raw = 1;

   if (!raw)
	 {
		log_putc_stub (filename,line,function,level,' ');

		for (i = 0; i < value->data.OCTET_STRING.len; i++)
		  log_putc_stub (filename,line,function,level,value->data.OCTET_STRING.buf[i]);
	 }
   else
	 {
		for (i = 0; i < value->data.OCTET_STRING.len; i++)
		  log_printf_stub (filename,line,function,level,
						   " %02x",
						   value->data.OCTET_STRING.buf[i]);
	 }
}

static void tree_show_ipaddress (const char *filename,int line,const char *function,
								 int level,const snmp_value_t *value)
{
   log_printf_stub (filename,line,function,level,
					"IpAddress %u.%u.%u.%u",
					NIPQUAD (value->data.IpAddress));
}

static void tree_show_null (const char *filename,int line,const char *function,
							int level,const snmp_value_t *value)
{
   log_puts_stub (filename,line,function,level,"No Such Name");
}

static void tree_show_value (const char *filename,int line,const char *function,
							 int level,const snmp_value_t *value)
{
   static const struct
	 {
		uint8_t type;
		void (*show) (const char *,int,const char *,int,const snmp_value_t *);
	 } list[] =
	 {
		{ BER_INTEGER, tree_show_integer },
		{ BER_Counter32, tree_show_counter32 },
		{ BER_Gauge32, tree_show_gauge32 },
		{ BER_TimeTicks, tree_show_timeticks },
		{ BER_Counter64, tree_show_counter64 },
		{ BER_OID, tree_show_oid },
		{ BER_OCTET_STRING, tree_show_octet_string },
		{ BER_IpAddress, tree_show_ipaddress },
		{ BER_NULL, tree_show_null }
	 };
   size_t i;

   for (i = 0; i < ARRAYSIZE (list); i++)
	 if (value->type == list[i].type)
	   {
		  list[i].show (filename,line,function,level,value);
		  return;
	   }

   log_puts_stub (filename,line,function,level,"(unknown)");
}

static void tree_show (const char *filename,int line,const char *function,
					   int level,const struct odb *odb,char *prev,uint32_t depth)
{
   if (odb != NULL && odb->child != NULL)
	 {
		uint32_t i;

		for (i = 0; i < depth; i++)
		  log_printf_stub (filename,line,function,level,"  %c",prev[i]);

		log_printf_stub (filename,line,function,level,
						 "  %cÄ %" PRIu32,
						 odb->sibling != NULL ? 'Ã' : 'À',
						 odb->data.node);

		if (odb->child->child == NULL)
		  {
			 log_puts_stub (filename,line,function,level," :: ");
			 tree_show_value (filename,line,function,level,&odb->child->data.value);
		  }

		log_putc_stub (filename,line,function,level,'\n');

		prev[depth] = odb->sibling != NULL ? '³' : ' ';

		if (odb->child->child != NULL)
		  tree_show (filename,line,function,level,odb->child,prev,depth + 1);

		if (odb->sibling != NULL)
		  tree_show (filename,line,function,level,odb->sibling,prev,depth);
	 }
}

int odb_show_stub (const char *filename,int line,const char *function,
				   int level,const struct odb *odb)
{
   abz_clear_error ();

   if (odb != NULL)
	 {
		char *prev;

		if ((prev = mem_alloc (tree_get_depth (odb,1))) == NULL)
		  {
			 out_of_memory ();
			 return (-1);
		  }

		tree_show (filename,line,function,level,odb,prev,0);

		mem_free (prev);
	 }

   return (0);
}

#endif	/* #ifdef DEBUG */

