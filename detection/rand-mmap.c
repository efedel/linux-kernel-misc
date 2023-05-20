#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#define	_SYSCALL32
#include <sys/dirent.h>
#undef	_SYSCALL32

#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/thread.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/vmsystm.h>
#include <sys/vmparam.h>
#include <sys/kobj.h>

#include <sys/socket.h>
#include <sys/privregs.h>
#include <sys/mman.h>
#include <sys/watchpoint.h>

#include <sys/modctl.h>
#include <vm/as.h>
#include <vm/seg.h>

#include <magic.h>
#include <kernel_utils.h>

#ifdef DEBUG
#define	dcmn_err(X)	cmn_err X
#else
#define	dcmn_err(X)	
#endif

#define	MAX_TRIES	20

static unsigned short (*tcp_random)(void);
extern int64_t smmap32();
extern int64_t smmap64();

static caddr_t
random_addr(void)
{
	unsigned long	addr = 0;

	addr = tcp_random() << 16;
	addr <<=  32;
	return (caddr_t)(addr|(tcp_random()<<16));
}

static caddr32_t
random_addr32(void)
{
	return ((caddr32_t)(tcp_random()<<16));
}

static caddr_t
get_rand_addr(size_t len, int prot)
{
	struct as	* as;
	caddr_t	addr;
	int	i;

	as = curproc->p_as;

	prot |= PROT_USER;

	for (i = 0; i < MAX_TRIES; i++) {
		int	ret;

		addr = get_udatamodel() == DATAMODEL_LP64 ?
			random_addr() : (caddr_t)random_addr32();
		ret = valid_usr_range(addr, len, prot, as,(caddr_t)USERLIMIT32);

		if (ret == RANGE_OKAY)
			return addr;
	}
	return (0);
}

static int64_t
(*old_mmap32)(caddr32_t addr,size32_t len,int prot,int flags,int fd,off32_t);
	
static int64_t
zz_mmap32(caddr32_t addr,size32_t len,int prot,int flags,int fd,off32_t pos)
{
	caddr32_t	naddr = 0;


#if 0
	dcmn_err((CE_NOTE, "%s[%d] o_mmap32(%lx, %d, %x, %x, %d, %d)", 
			PTOU(curproc)->u_comm, curproc->p_pidp->pid_id,
			addr, len, prot, flags, fd, pos));
#endif

	if (!addr || (flags & MAP_FIXED) == 0) {
		if ((naddr = (caddr32_t)get_rand_addr((size_t)len, prot))==0) {
			dcmn_err((CE_WARN, "%s[%d] no valid random address",
					PTOU(curproc)->u_comm,
					curproc->p_pidp->pid_id));
			/* need to set some sort of error condition here */
			/* return (0); */
		}
	}

	flags |= naddr ? MAP_FIXED : 0;
	naddr = naddr ? naddr : addr;

#if 0
	dcmn_err((CE_NOTE, "%s[%d] r_mmap32(%lx, %d, %x, %x, %d, %d)", 
			PTOU(curproc)->u_comm, curproc->p_pidp->pid_id,
			naddr, len, prot, flags, fd, pos));
#endif

	naddr = (caddr32_t)old_mmap32(naddr, len, prot, flags, fd, pos);

#if 0
	dcmn_err((CE_NOTE, "%s[%d] ret32: %x",
		PTOU(curproc)->u_comm, curproc->p_pidp->pid_id, naddr));
#endif
	return naddr;
}

static int64_t
(*old_mmap64)(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos);

static int64_t
zz_mmap64(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos)
{
	caddr_t	naddr = 0;


#if 0
	dcmn_err((CE_NOTE, "%s[%d] o_mmap64(%lx, %d, %x, %x, %d, %d)", 
			PTOU(curproc)->u_comm, curproc->p_pidp->pid_id,
			addr, len, prot, flags, fd, pos));
#endif

	if (!addr || (flags & MAP_FIXED) == 0) {
		if ((naddr = get_rand_addr(len, prot)) == 0) {
			dcmn_err((CE_WARN, "%s[%d] no valid random address",
					PTOU(curproc)->u_comm,
					curproc->p_pidp->pid_id));
			/* need to set some sort of error condition here */
	/*		return (set_errno(ENOMEM));*/
		}
	}

	/* we need to pass in the orignal address if we were given one
	 * and we didnt' create a new address .. */
	flags |= naddr ? MAP_FIXED : 0;
	naddr = naddr ? naddr : addr;

#if 0
	dcmn_err((CE_NOTE, "%s[%d] r_mmap64(%lx, %d, %x, %x, %d, %d)", 
			PTOU(curproc)->u_comm, curproc->p_pidp->pid_id,
			naddr, len, prot, flags, fd, pos));
#endif

	naddr = (caddr_t)old_mmap64(naddr, len, prot, flags, fd, pos);

#if 0
	dcmn_err((CE_NOTE, "%s[%d] ret: %x",
		PTOU(curproc)->u_comm, curproc->p_pidp->pid_id, naddr));
#endif
	return (int64_t) naddr;
}

void
zz_rand_addr(void)
{
	if (0==(tcp_random=(unsigned short (*)())
				kobj_getsymvalue("tcp_random", 0))) {
		cmn_err(CE_NOTE,
		"ZZ: address space protection initialization failed");
		return;
	}

	old_mmap32 = sysent32[ SYS_mmap ].sy_callc;
	sysent32[ SYS_mmap ].sy_callc = zz_mmap32;
	/* sysent32[ SYS_mmap64 ].sy_callc = zz_mmap64; */

	/* trap the 64bit syscalls */
	old_mmap64 = sysent[ SYS_mmap ].sy_callc;
	sysent[ SYS_mmap ].sy_callc = zz_mmap64;

	return;
}

void
zz_restore_addr(void)
{
	sysent32[ SYS_mmap ].sy_callc = old_mmap32;
	/* sysent32[ SYS_mmap64 ].sy_callc = old_mmap64; */
	sysent[ SYS_mmap ].sy_callc = old_mmap64;

	dcmn_err((CE_NOTE, "ZZ: restoring mmap"));

	return;
}
