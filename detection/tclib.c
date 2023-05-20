#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <zzlib.h>

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

typedef struct {
	size_t	size;
} chunk_t;


void *
zz_malloc(size_t size)
{
	return( kmalloc((unsigned long) size, 1) );
}

void
zz_free(void *ptr)
{
	if (NULL == ptr) {
		return;
	}
	kfree( ptr );
	return;
}

void
zz_printf(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	printk( fmt, ap );
	va_end(ap);
}

void *
zz_getsym(char *sym_name)
{
	return(NULL);
}

int
zz_no_init(unsigned int id)
{
	return (0);
}

int
zz_no_fini(void)
{
	return (0);
}

void
zz_no_recv(kmsg_t *kp)
{
	return;
}
