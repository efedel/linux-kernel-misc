#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/dirent.h>

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

#include <sys/socket.h>
#include <sys/privregs.h>
#include <sys/mman.h>
#include <sys/watchpoint.h>

#include <sys/modctl.h>
#include <vm/as.h>
#include <vm/seg.h>

#include <kmod.h>
#include <chains.h>
#include <zzlib.h>

static int memcheck_init(unsigned int id);
static int memcheck_fini(void);
static void memcheck_recv(kmsg_t *kp);

struct zz_kmod memcheck_kmod = {
	memcheck_init,
	memcheck_fini,
	zz_no_recv,
	"BOVERFLOW",
	ZZ_VERSION,
};

static int vuln_calls[] = {
	/* execution */
	SYS_exec,
	SYS_execve,

	/* file descriptor controls, used for shellcode environments */
	SYS_dup,
	SYS_fcntl,
	SYS_signal,

	/* socket manipulation/creation */
	SYS_so_socket,
	SYS_send,
	SYS_sendto,
	SYS_sendmsg,
	SYS_recv,
	SYS_recvfrom,
	SYS_recvmsg,
	SYS_bind,
	SYS_accept,
	SYS_listen,

	/* file manipulation/creation */
	SYS_open,
	SYS_creat,
	SYS_write,
	SYS_read,
	SYS_chmod,
	SYS_fchmod,
	SYS_chown,
	SYS_lchown,
	SYS_fchown,

	/* file system alteration */
	SYS_chroot,
	SYS_chdir,
	SYS_fchdir,
	SYS_fchroot,
	SYS_mknod,
	SYS_xmknod,
	SYS_mount,
	SYS_link,
	SYS_unlink,

	/* memory alteration (allocation, protection) */
	SYS_mmap,
	SYS_munmap,
	SYS_mprotect,
	SYS_brk,
	
	/* uid manipulation */
	SYS_setuid,
	SYS_seteuid,
	SYS_setgid,
	SYS_setegid,
	
	/* process manipulation */
	SYS_getpid,
	SYS_kill,
	SYS_fork,

	/* kernel module manipulation */
	SYS_modctl,
};

static int vuln_calls32[] = {
	SYS_open64,
	SYS_mmap64
};

#define	MAX_VULN_CALLS		(sizeof(vuln_calls) / sizeof(vuln_calls[0]))
#define	MAX_VULN_CALLS32	(sizeof(vuln_calls32) / sizeof(vuln_calls32[0]))

static unsigned int	My_Id;
#define	set_my_id(id)	(My_Id = id)
#define	get_my_id()	(My_Id)

#define get_user_pc()   (lwptoregs(ttolwp(curthread))->r_pc)
#define is_writable_mem(addr)   \
	((0 == as_checkprot(curproc->p_as, (caddr_t)(addr), 4, PROT_WRITE))?1:0)

extern void rexit(int val);

static int64_t
memcheck(void)
{
	if (is_writable_mem(get_user_pc())) {
		kmsg_t	* kp = kmsg_new_event(BUFFER_OVERFLOW);

		if (kp) {
			kp->to = BCOM;
			kp->from = get_my_id();
			
			kmsg_send(kp);
			kmsg_free(kp);
		}
		rexit(123);
	}
	return (0);
}

static int (*orig_mmap3264)(void *arg1, void *arg2);
static int
zz_mmap3264(void *arg1, void *arg2)
{
	memcheck();
	return (orig_mmap3264(arg1, arg2));
}

static int
memcheck_init(unsigned int id)
{
	int	i;

	set_my_id(id);

	for (i = 0; i < MAX_VULN_CALLS; i++) {
		int	syscall = vuln_calls[i];

		zz_add_link(syscall, memcheck, get_my_id(), BEFORE);
		zz_add_link32(syscall, memcheck, get_my_id(), BEFORE);
	}

	for (i = 0; i < MAX_VULN_CALLS32; i++) {
		int	syscall = vuln_calls32[i];

		zz_add_link32(syscall, memcheck, get_my_id(), BEFORE);
	}

	orig_mmap3264 = sysent32[ SYS_mmap64 ].sy_call;
	sysent32[ SYS_mmap64 ].sy_call = zz_mmap3264;

	return (0);
}

static int
memcheck_fini(void)
{
	int	i;


	for (i = 0; i < MAX_VULN_CALLS; i++) {
		int	syscall = vuln_calls[i];

		zz_rem_link(syscall, get_my_id());
		zz_rem_link32(syscall, get_my_id());
	}

	for (i = 0; i < MAX_VULN_CALLS32; i++) {
		int	syscall = vuln_calls32[i];

		zz_rem_link32(syscall, get_my_id());
	}

	sysent32[ SYS_mmap64 ].sy_call = orig_mmap3264;

	return (0);
}
