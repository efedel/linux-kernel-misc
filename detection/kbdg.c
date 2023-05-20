/*
gcc -c -o /tmp/zz_mod -I../../unix/include  -I/usr/src/linux kbdg.c
*/

/* Linux kernel module req includes */
/* ------------------------ */
#if CONFIG_MODVERSIONS==1
 #define MODVERSIONS
 #include <linux/modversions.h>
#endif
#include <linux/kernel.h>
#include <linux/module.h>  		/* module junk */
#include <linux/init.h>    		/* more module junk */
#include <linux/unistd.h>  		/* syscall table */
#include <linux/sched.h>   		/* task struct, current() */
#include <linux/string.h>  		/* in-kernel strncmp */
#include <linux/fs.h>      		/* file operations */
#include <linux/personality.h>      	/* file operations */
#include <linux/poll.h>
#include <linux/wait.h>
#include <asm/uaccess.h>   		/* getuser, putuser */
/* ------------------------ */

#include <kmod.h>
#include <kmsg.h>
#include <mman.h>

/* change this to test chains */
#define USE_CHAINS 0

#if USE_CHAINS
#include <chains.h>
#endif


#ifndef	 TRUE
#define	 TRUE 1
#endif
#ifndef	 FALSE
#define	 FALSE 0
#endif


#define	ZZ_NAME		"debugx"
#define	CIRCULAR_BUF_SIZE    	256


/* kmsg protos for internal use */
extern kmsg_t * kmsg_alloc(unsigned int len);
extern void kmsg_free(kmsg_t *kp);
extern kmsg_t * kmsg_realloc(kmsg_t *kp, unsigned int len);


struct cir_buf {
	void    * buf[CIRCULAR_BUF_SIZE];
	int       next; /* where we add */
	int       curr;      /* where we get */
};

static struct cir_buf   cir;
static spinlock_t cir_mutex;
static wait_queue_head_t cir_waitqueue;	/* used to poll on cir_buf */

/* circular buffer helper functions */
static void cbuf_add(void * ptr);
static void * cbuf_get(void);
static int cbuf_any(void);


/* kernel bridge module routines */
static int kbdg_fini(void);
static int kbdg_init(unsigned int id);
static void kbdg_recv(kmsg_t *kp);

struct zz_kmod kcomm_kmod = {
	kbdg_init,
	kbdg_fini,
	kbdg_recv,
	"KCOMM",
	ZZ_VERSION
};

struct zz_kmod bcom_kmod = {
	kbdg_init,
	kbdg_fini,
	kbdg_recv,
	"BCOM",
	ZZ_VERSION
};


static int
kbdg_release( struct inode *inode, struct file *f)
{
	MOD_DEC_USE_COUNT;
	printk("DETACH!\n");
	return(0);
}

static int
kbdg_open(struct inode *inode, struct file *f)
{
	MOD_INC_USE_COUNT;
	printk("OPEN\n");
	return(0);
}


static unsigned int
kbdg_poll(struct file * f, struct poll_table_struct * pt)
{
	printk("POLL\n");
	/* wait_table zz_wait */

	poll_wait(f, &cir_waitqueue, pt);
	/* TODO -- do we want to do a blocking write as well? */

	if (cbuf_any()) {
		/* TODO -- check poll_table for POLLIN etc */
		/*         Also: global mask set int read/write? */
		return( POLLIN | POLLRDNORM );
	}

	return(0);
}

static ssize_t
kbdg_read(struct file *f, char * buf, size_t len, loff_t * offset)
{
	kmsg_t	* kp;
	int	  error = 0;

	kp = cbuf_get();
	if (kp == NULL) {
		/* no kmsg_t in queue */
		return (EINVAL);
	}

	if ( copy_to_user((char *)kp, buf, sizeof(kmsg_t) + kp->len) ) {
		printk("<7> : Unable to write kmsg_t to userland\n" );
		return(EFAULT);
	}
	return (error);
}

static ssize_t
kbdg_write(struct file * f, const char * buf, size_t len, loff_t * offset)
{
	kmsg_t	* kp, kmsg = {0};

	/* try to get kmsg_t from userspace */
	if ( copy_from_user((char *)&kmsg, buf, sizeof(kmsg_t)) ) {
		printk("<7> : Unable to read kmsg_t to userland\n" );
		return(EFAULT);
	}

	/* TODO: do we need to read more based on kmsg.len ? 
	 *       or are all incoming messages the same length? */

	kp = kmsg_alloc( sizeof(kmsg_t) );
	if (kp == NULL) {
		printk( "<7> %s: write: could not allocate kernel message.\n",
				ZZ_NAME );
		return (EFAULT);
	}

	memcpy( kp, &kmsg, sizeof(kmsg_t) );

	kmsg_send(kp);

	kmsg_free(kp);

	return (0);
}

/* CIRCULAR BUFFER ROUTINES */
static void
cbuf_add(void * ptr)
{
	spin_lock(&cir_mutex);

	cir.buf[cir.next] = ptr;

	if (CIRCULAR_BUF_SIZE <= ++cir.next) {
		cir.next = 0;
	}
	if (cir.next == cir.curr) {
		if (CIRCULAR_BUF_SIZE <= ++cir.curr) {
			cir.curr = 0;
		}
	}

	/* alert poll that there is data available */
	wake_up_interruptible(&cir_waitqueue);
	spin_unlock(&cir_mutex);
}

static void *
cbuf_get(void)
{
	char    * ptr;

	spin_lock(&cir_mutex);
	if (cir.next == cir.curr) {
		spin_unlock(&cir_mutex);
		return NULL;
	}

	ptr = cir.buf[cir.curr];
	cir.buf[cir.curr] = NULL;

	if (CIRCULAR_BUF_SIZE <= ++cir.curr) {
		cir.curr = 0;
	}
	spin_unlock(&cir_mutex);

	return ptr;
}

static int
cbuf_any(void)
{
	int any;
	spin_lock(&cir_mutex);
	any = cir.next != cir.curr ? TRUE : FALSE;
	spin_unlock(&cir_mutex);

	return (any);
}





static char *file = NULL, *modname = NULL;
static int major = 0, minor = 0;

MODULE_PARM(file, "s");
MODULE_PARM(modname, "s");
MODULE_PARM(major, "i");
MODULE_PARM(minor, "i");

MODULE_LICENSE("Propietary");

#define KBDG_DEFAULT_MAJOR	252
#define KBDG_DEFAULT_MINOR	0
#define KBDG_DEFAULT_DEVICE 	"/dev/debugx0"
#define KBDG_MODULE		"debugx"



/* Linux kernel module load/unload functions */
static struct file_operations kbdg_fops = {
	NULL,		/* struct module *owner */
	NULL,		/* lseek(i) */
	kbdg_read,	/* read() */
	kbdg_write,	/* write() */
	NULL,		/* readdir() */
	kbdg_poll,	/* poll() */
	NULL,		/* ioctl() */
	NULL,		/* mmap() */
	kbdg_open,	/* open() */
	NULL,		/* flush() */
	kbdg_release,	/* release() */
	NULL,		/* fsync() */
	NULL,		/* fasync() */
	NULL,		/* lock() */
	NULL,		/* readv() */
	NULL,		/* writev() */
	NULL,		/* sendpage() */
	NULL		/* get_unmapped_area() */
};


int __init
_init(void)
{
	int	rv;
	EXPORT_NO_SYMBOLS;

	/* set default values for device file name, major/minor dev #s */
	if ( ! file ) {
		file = KBDG_DEFAULT_DEVICE;
	}

	if ( ! modname ) {
		modname = KBDG_MODULE;
	}
	
        if ( ! major ) {
		major = KBDG_DEFAULT_MAJOR;
	}

        if ( ! minor ) {
		minor = KBDG_DEFAULT_MINOR;
	}

	rv = register_chrdev(major, KBDG_MODULE, &kbdg_fops);
	if (! rv && major ) {
		printk("ZZ MAJOR %d\n", major);
	} else if (! rv )  {
		printk("ZZ MAJOR %d\n", rv);
	} else {
		printk("UNABLE TO REGISTER ZZ DEVICE!\n");
	}

#if 0
	sys_mknod((const char *) file, S_IFCHR | 0666, MKDEV(major,minor));
#endif

#if USE_CHAINS
	rv = zz_attach_chains();
	if (rv) {
		return (rv);
	}
#endif

	spin_lock_init(&cir_mutex);
	init_waitqueue_head(&cir_waitqueue);

	return (0);
}

void __exit
_fini(void)
{
#if USE_CHAINS
	chains_fini();
	zz_detach_chains();
#endif
	zz_kmodules[MOD_MANAGER].mod->fini();	/* MMAN FINI cleans up */	


#if 0
	sys_unlink(file);
#endif

	unregister_chrdev(major, modname);

	return;
}

module_init(_init)
module_exit(_fini)


/* KERNEL BRIDGE FUNCTIONS */
static int
kbdg_init(unsigned int id)
{
	return (0);
}

static int
kbdg_fini(void)
{
	/* flush cbuf */
	while (cbuf_any()) {
		kmsg_t	* kp = cbuf_get();
		kmsg_free(kp);
	}
	return (0);
}

static void
kbdg_recv(kmsg_t *kp)
{
	kmsg_t	* kmsg;


	if ((kmsg = kmsg_dup(kp)) == NULL)
		return;
	cbuf_add(kmsg);

	return;
}


