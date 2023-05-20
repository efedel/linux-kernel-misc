#include "kernel.h"
#include "log.h"

void
log_current (int code)
{
	printk ("Tru %d %s %d %d %d %d\n", code, current->comm, current->uid, current->euid, current->gid, current->egid);

	return;
}
