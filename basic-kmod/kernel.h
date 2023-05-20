#ifndef TRUSHIELD_KERNEL_H
#define TRUSHIELD_KERNEL_H
#include <linux/config.h>

#if 1 || defined(MODVERSIONS)
#include <linux/modversions.h>
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include "log.h"


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#error not supported yet
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
#error not supported yet
#endif

typedef struct {
	char *	desc;

	int	syscall_number;

	void *	old_address;
	void *	new_address;

	int	set;
} redirect_t;

#define NR_SYSCALLS 225

extern redirect_t	redirects[];
extern int		redirect_sz;

int redirect_disable (redirect_t *redir);
int redirect_enable (redirect_t *redir);
int redirect_cnt (void);
int redirect_init (void);
int redirect_fini (void);	
#endif
