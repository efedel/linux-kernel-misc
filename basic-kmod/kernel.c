#include "kernel.h"
#include "config.h"
#include <asm/processor.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/fs.h>	/* getname, putname, IS_ERR, PTR_ERR */
#include <linux/compatmac.h>
#include <linux/file.h>
#include <linux/irq.h>
#include <linux/mm.h>
#include <asm/ptrace.h>		/* pt_regs */


static asmlinkage int dude_execve(struct pt_regs regs);

#define _redir_exec 0

redirect_t redirects[]={
	{"sys_execve",__NR_execve,0,dude_execve,0},
	/*
	{"sys_fork",,0,,0},
	{"sys_brk",,0,,0},
	{"sys_clone",,0,,0},
	*/
	{NULL,-1,0,0,0}
};


/* IDT entries :
	ENTRY(bounds)
	ENTRY(segment_not_present) 
	ENTRY(stack_segment) 
	ENTRY(general_protection) 
	ENTRY(page_fault) 
*/

int redirect_sz = sizeof(redirects)/sizeof(redirect_t) - 1;

static asmlinkage int dude_execve(struct pt_regs regs) {
	int error;
	char * filename;

	filename = getname((char *) regs.ebx);
	error = PTR_ERR(filename);

	if (IS_ERR(filename)) {
		return( error );
	}

	printk("ATTEMPT EXEC %s EIP %08lX\n", filename, regs.eip );

	error = do_execve(filename, (char **) regs.ecx, (char **) regs.edx,
			&regs);

	if (error == 0) {
		current->ptrace &= ~PT_DTRACE;
	}
	printk("EXEC %s EIP %08lX\n", filename, regs.eip );

	putname(filename);


	return( error );
}

int init_module (void) {	
	EXPORT_NO_SYMBOLS;

	if (redirect_init())
		return (-1);

	return (0);
}

int cleanup_module (void) {
	redirect_fini();

	return (0);
}

MODULE_LICENSE("GPL");
