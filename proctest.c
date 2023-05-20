#define NULL 0
#define MODULE
#define __KERNEL__
// #define __GENKSYMS__
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
int ReadThisProcFile( char *buf, char **start, off_t offset, int len, int naught)
{
	len = sprintf(buf, "\nThisProcFile went to the market,\nThisProcFile stayed home.\n");
	return len;
}
struct proc_dir_entry ThisProcFile = {
	0,	//low_ino
	12, //name length
	"ThisProcFile", //name
	S_IFREG | S_IRUGO, //mode
	1, 0, 0,	// nlinks, owner, group
	0,	//size
	NULL,		//operations
	&ReadThisProcFile, //read function
};

int init_module(void) 
{ 
	proc_register(&proc_root, &ThisProcFile); 
	return 0; 
}
int cleanup_module(void) { 
	proc_unregister(&proc_root, ThisProcFile.low_ino);
	return 0; 
}
