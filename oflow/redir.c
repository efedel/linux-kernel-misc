#include "kernel.h"
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/smp_lock.h>
#include "config.h"

struct idt_desc { 
	unsigned short	lo;
	unsigned short	seg_sel;
	unsigned char	rsvd;
	unsigned short	hi;
};

/*
 * = 1: if have redirected the system call table
 * = 0: otherwise
 */
static int redirect_flag = 0;

void asmlinkage my_system (void);

unsigned long old_system;
struct idt_desc *idt_table;

int asmlinkage
my_system2 (void)
{
	unsigned long	*esp;
	unsigned char	tmp[4];
	unsigned int	sys_nr;
	
	__asm__ ("movl %%ebx, %0" : "=r"(esp));		/* saved stack ptr */
	__asm__ ("movl %%ecx, %0" : "=r"(sys_nr));	/* saved syscall # */

	if (esp[1] >= 0xc0000000)			/* in kernel mem */
		return (0);				

	if (copy_from_user (tmp, (void *)(esp[1]), 4)) { /* cannot read */
		return (0);
	}

	if (copy_to_user ((void *)(esp[1]), tmp, 4)) {	/* cannot write */
		return (0);
	}

	log_current (556);

	return (-1);
}

void 
sidt (void)
{
	unsigned char idtr[8]; 

	__asm__ __volatile__ ("sidt %0": "=m" (idtr)); 
	idt_table = (void *)*((unsigned long *)&idtr[2]);
}


int
redirect_cnt (void)
{
	return (redirect_sz);
}

/*
 * disables an individual syscall redirection
 */

int
redirect_disable (redirect_t *redir)
{
	if (!redir || !redir->set)
		return (0);

	redir->set = 0;
	sys_call_table[redir->syscall_number] = redir->old_address;

	return (0);
}

/*
 * enables an individual syscall redirection
 */

int
redirect_enable (redirect_t *redir)
{
	if (!redir || redir->set)
		return (0);

	printk ("enabling %s\n", redir->desc);
	redir->set = 1;
	redir->old_address = sys_call_table[redir->syscall_number];
	sys_call_table[redir->syscall_number] = redir->new_address;

	return (0);
}

/*
 * turns on the syscall redirection so that we can detect stack
 * overflows etc and also redirect arbitrary system calls
 */

int
redirect_init (void)
{
	int			i;

	EXPORT_NO_SYMBOLS;

	if (redirect_flag)
		return (0);

	sidt();
	old_system = (idt_table[0x80].hi << 16) | idt_table[0x80].lo; 
	idt_table[0x80].hi = (short)(((unsigned long)my_system)>>16);
	idt_table[0x80].lo = (short)(((unsigned long)my_system)&0xffff);
	
	for (i = 0; i < redirect_sz; ++i)
		redirect_enable (&redirects[i]);
	
	redirect_flag = 1;

	return (0);
}

int
redirect_fini (void)
{
	int			i;

	if (!redirect_flag)
		return (0);
	
	idt_table[0x80].hi = (short)(((unsigned long)old_system)>>16);
	idt_table[0x80].lo = (short)(((unsigned long)old_system)&0xffff);

	for (i = 0; i < redirect_sz; ++i)
		redirect_disable (&redirects[i]);

	redirect_flag = 0;

	return (0);
}
