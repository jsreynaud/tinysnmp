
struct sensor
{
   char *name;
   int32_t cur;
   int32_t min,max,hyst;
   int32_t status;
   time_t timestamp;
   struct sensor *next;
};

struct chip
{
   char *ident;
   struct sensor *sensor;
   struct chip *next;
};

struct driver
{
   const char *name;
   int (*open) (void);
   int (*update) (struct chip *);
   int (*close) (void);
   void *data;
   struct driver *next;
};

static int lm77_open (struct driver *driver)
{
}

static int lm77_update (struct driver *driver)
{
}

static int lm77_destroy (struct driver *driver)
{
}

struct driver lm77
{
   .name	= "lm77",
   .open	= lm77_open,
   .update	= lm77_update,
   .close	= lm77_close
};

