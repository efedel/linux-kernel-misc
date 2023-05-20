
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
#include <zzlib.h>

#define ALIGN(k, v) ( ((k) + ((v)-1)) & (~((v)-1)) )

#define get_user_pc()   (lwptoregs(ttolwp(curthread))->r_pc)
#define is_writable_mem(addr)   \
	((0 == as_checkprot(curproc->p_as, (caddr_t)(addr), 4, PROT_WRITE))?1:0)

#define	IF_PC_FROM_WR_MEM_EXIT() zz_memcheck()

#define	IF_CHROOT_RETURN_EPERM() enforce_chroot()

/* hijack / restore calls */
#define HIJACK(call, sysent, syscall) 					\
{									\
	orig_##call = (int (*)()) sysent [ SYS_##syscall ].sy_callc;	\
	sysent [ SYS_##syscall ].sy_callc = (int64_t (*)()) zz_##call;	\
}

#define RELEASE(call, sysent, syscall)					\
{									\
	sysent [ SYS_##syscall ].sy_callc = (int64_t (*)()) orig_##call;	\
}

#define HIJACK32(call)  	HIJACK(call, sysent32, call)
#define RELEASE32(call)		RELEASE(call, sysent32, call)

#define	HIJACK64(call)		HIJACK(call, sysent, call)
#define	RELEASE64(call)		RELEASE(call, sysent, call)

#define	HIJACK32T(call, syscall)	HIJACK(call, sysent32, syscall)
#define	RELEASE32T(call, syscall)	RELEASE(call, sysent32, syscall)

#define	HIJACK64T(call, syscall)	HIJACK(call, sysent, syscall)
#define	RELEASE64T(call, syscall)	RELEASE(call, sysent, syscall)

static int memcheck_init(unsigned int id);
static int memcheck_fini(void);

struct zz_kmod memcheck_kmod = {
	memcheck_init,
	memcheck_fini,
	zz_no_recv,
	"BOVERFLOW",
	ZZ_VERSION,
};

struct zz_kmod chroot_kmod = {
	zz_no_init,
	zz_no_fini,
	zz_no_recv,
	"CHROOT",
	ZZ_VERSION,
};

static void (*orig_exit)(int);

static int
zz_memcheck(void)
{
	if (is_writable_mem(get_user_pc())) {
		kmsg_t	* kp = kmsg_new_event(BUFFER_OVERFLOW);

		if (kp) {
			kp->to = BCOM;
			kp->from = 6; /* fugly hack. */
			
			kmsg_send(kp);
			kmsg_free(kp);
		}
		orig_exit(123);
	}
	return (0);
}

static int
is_chroot(void)
{
	int	ret;


	mutex_enter(&curproc->p_lock);
	ret = u.u_rdir == NULL ? 0 : 1;
	mutex_exit(&curproc->p_lock);

	return (ret);
}

static int
enforce_chroot(void)
{
	if (is_chroot()) {
		kmsg_t	* kp = kmsg_new_event(CHROOT_BREAK);

		if (kp) {
			kp->to = BCOM;
			kp->from = 5; /* fugly hack */
	
			kmsg_send(kp);
			kmsg_free(kp);
		}
		return set_errno(EPERM);
	}
	return (0);
}

/*
 * PROCESS creation calls
 */

static int (*orig_exec)(const char *path, const char **argp, const char **envp);
static int
zz_exec(const char *path, const char **argp, const char **envp)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_exec(path, argp, envp));
}

/*
 * ENVIRONMENT creation calls
 */
static int (*orig_dup)(int oldfd);
static int
zz_dup(int oldfd)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_dup(oldfd));
}

static int (*orig_fcntl)(int fdes, int cmd, intptr_t arg);
static int
zz_fcntl(int fdes, int cmd, intptr_t arg)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_fcntl(fdes, cmd, arg));
}

static int (*orig_signal)(int signo, void (*func)());
static int
zz_signal(int signo, void (*func)())
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_signal(signo, func));
}

/*
 * NETWORK calls
 */

static int (*orig_so_socket)(int domain, int type, int protocol, char *devpath,
		int version);
static int
zz_so_socket(int domain, int type, int protocol, char *devpath, int version)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_so_socket(domain, type, protocol, devpath, version));
}

static int (*orig_send)(int sock, void *buffer, size_t len, int flags);
static int
zz_send(int sock, void *buffer, size_t len, int flags)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_send(sock, buffer, len, flags));
}

static int (*orig_sendto)(int sock, void *buffer, size_t len, int flags,
		const struct sockaddr *name, socklen_t namelen);
static int
zz_sendto(int sock, void *buffer, size_t len, int flags,
		const struct sockaddr *name, socklen_t namelen)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_sendto(sock, buffer, len, flags, name, namelen));
}

static int (*orig_sendmsg)(int sock, const struct nmsghdr *msg, int flags);
static int
zz_sendmsg(int sock, const struct nmsghdr *msg, int flags)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_sendmsg(sock, msg, flags));
}

static int (*orig_recv)(int sock, void *buf, size_t len, int flags);
static int
zz_recv(int sock, void *buf, size_t len, int flags)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_recv(sock, buf, len, flags));
}

static int (*orig_recvfrom)(int sock, void *buffer, size_t len, int flags,
		struct sockaddr *name, socklen_t namelen);
static int
zz_recvfrom(int sock, void *buffer, size_t len, int flags,
		struct sockaddr *name, socklen_t namelen)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_recvfrom(sock, buffer, len, flags, name, namelen));
}

static int (*orig_recvmsg)(int sock, struct nmsghdr *msg, int flags);
static int
zz_recvmsg(int sock, struct nmsghdr *msg, int flags)
{
	IF_PC_FROM_WR_MEM_EXIT();
	
	return (orig_recvmsg(sock, msg, flags));
}

static int (*orig_bind)(int sock, struct sockaddr *name, socklen_t namelen,
		int version);
static int
zz_bind(int sock, struct sockaddr *name, socklen_t namelen, int version)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_bind(sock, name, namelen, version));
}

static int (*orig_accept)(int sock, struct sockaddr *name, socklen_t *namelenp,
		int version);
static int
zz_accept(int sock, struct sockaddr *name, socklen_t *namelenp, int version)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_accept(sock, name, namelenp, version));
}

static int (*orig_listen)(int sock, int backlog, int version);
static int
zz_listen(int sock, int backlog, int version)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_listen(sock, backlog, version));
}

/*
 * SOCKET finding calls
 *
 * XXX: do later.
 *
 * getsockotp
 * setsockopt
 * getpeername
 * getsockname
 * poll
 * select
 */

static int (*orig_open32)(const char *fname, int fmode, int mode);
static int
zz_open32(const char *fname, int fmode, int mode)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return ((*orig_open32)(fname, fmode, mode));
}

static int (*orig_open64)(const char *fname, int fmode, int mode);
static int
zz_open64(const char *fname, int fmode, int mode)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (*orig_open64)(fname, fmode, mode);
}

static int (*orig_creat)(const char *fname, int cmode);
static int
zz_creat(const char *fname, int cmode)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_creat(fname, cmode));
}

static int (*orig_write)(int fd, void *cbuf, size_t count);
static int
zz_write(int fdes, void *cbuf, size_t count)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_write(fdes, cbuf, count));
}

static int (*orig_read)(int fd, void *cbuf, size_t count);
static int
zz_read(int fdes, void *cbuf, size_t count)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_read(fdes, cbuf, count));
}

/*
 * FILE SYSTEM alteration codes
 */

static int (*orig_chown)(char *fname, uid_t uid, gid_t gid);
static int
zz_chown(char *fname, uid_t uid, gid_t gid)
{
	IF_PC_FROM_WR_MEM_EXIT();

        return ((*orig_chown)(fname, uid, gid));
}

static int (*orig_lchown)(char *fname, uid_t uid, gid_t gid);
static int
zz_lchown(char *fname, uid_t uid, gid_t gid)
{
	IF_PC_FROM_WR_MEM_EXIT();

        return ((*orig_lchown)(fname, uid, gid));
}

static int (*orig_fchown)(int fdes, uid_t uid, gid_t gid);
static int
zz_fchown(int fdes, uid_t uid, gid_t gid)
{
	IF_PC_FROM_WR_MEM_EXIT();

        return ((*orig_fchown)(fdes, uid, gid));
}

static int (*orig_chmod)(const char *fname, int fmode);
static int
zz_chmod(const char *fname, int fmode)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_chmod(fname, fmode));
}

static int (*orig_fchmod)(int fdes, int fmode);
static int
zz_fchmod(int fdes, int fmode)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_fchmod(fdes, fmode));
}

static int (*orig_chroot)(char *fname);
static int
zz_chroot(char *fname)
{
	IF_PC_FROM_WR_MEM_EXIT();

	IF_CHROOT_RETURN_EPERM();

	return (orig_chroot(fname));
}

static int (*orig_chdir)(char *fname);
static int
zz_chdir(char *fname)
{
	IF_PC_FROM_WR_MEM_EXIT();

        return ((*orig_chdir)(fname));
}

static int (*orig_fchdir)(int fdes);
static int
zz_fchdir(int fdes)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_fchdir(fdes));
}

static int (*orig_fchroot)(int fdes);
static int
zz_fchroot(int fdes)
{
	IF_PC_FROM_WR_MEM_EXIT();

	IF_CHROOT_RETURN_EPERM();

	return (orig_fchroot(fdes));
}

static int (*orig_mknod)(const char *fname, mode_t fmode, dev_t dev);
static int
zz_mknod(const char *fname, mode_t fmode, dev_t dev)
{
	IF_PC_FROM_WR_MEM_EXIT();

	IF_CHROOT_RETURN_EPERM();

	return (orig_mknod(fname, fmode, dev));
}

static int (*orig_xmknod)(int version, char *fname, mode_t fmode, dev_t dev);
static int
zz_xmknod(int version, char *fname, mode_t fmode, dev_t dev)
{
	IF_PC_FROM_WR_MEM_EXIT();

	IF_CHROOT_RETURN_EPERM();

	return (orig_xmknod(version, fname, fmode, dev));
}

static int (*orig_mount)(const char *spec, const char *dir, int mflag,
        char *fstype, char *dataptr, int datalen, char *optptr, int optlen);
static int
zz_mount(const char *spec, const char *dir, int mflag, char *fstype,
                char *dataptr, int datalen, char *optptr, int optlen)
{
        IF_PC_FROM_WR_MEM_EXIT();

	IF_CHROOT_RETURN_EPERM();

        return (orig_mount(spec, dir, mflag, fstype, dataptr, datalen,
                                optptr, optlen));
}

static int (*orig_link)(const char *existing, const char *new);
static int
zz_link(const char *existing, const char *new)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_link(existing, new));
}

static int (*orig_unlink)(char *path);
static int 
zz_unlink(char *path)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_unlink(path));
}

/*
 * MEMORY MANIPULATION calls
 */

static int
(*orig_mmap64)(caddr_t addr,size_t len, int prot, int flags, int fd, off_t off);
static int
zz_mmap64(caddr_t addr, size_t len, int prot, int flags, int fd, off_t off)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_mmap64(addr, len, prot, flags, fd, off));
}

static int
(*orig_mmap32)(caddr_t addr,size_t len, int prot, int flags, int fd, off_t off);
static int
zz_mmap32(caddr_t addr, size_t len, int prot, int flags, int fd, off_t off)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_mmap32(addr, len, prot, flags, fd, off));
}

static int
(*orig_mmap3264)(caddr_t uap, caddr_t rvp);
static int
zz_mmap3264(caddr_t uap, caddr_t rvp)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_mmap3264(uap, rvp));

}

static int (*orig_munmap)(void *addr, size_t len);
static int
zz_munmap(void *addr, size_t len)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_munmap(addr, len));
}

static int (*orig_mprotect)(void *addr, size_t len, int prot);
static int
zz_mprotect(void *addr, size_t len, int prot)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_mprotect(addr, len, prot));
}

static int (*orig_brk)(void *endds);
static int
zz_brk(void *endds)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_brk(endds));
}

static int
(*orig_modctl)(int a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
		uintptr_t a5);
static int
zz_modctl(int a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
		uintptr_t a5)
{
        IF_PC_FROM_WR_MEM_EXIT();

	IF_CHROOT_RETURN_EPERM();

	return (orig_modctl(a0, a1, a2, a3, a4, a5));
}

/*
 * PRIVILEDGES CALLS
 */

static int (*orig_setuid)(uid_t uid);
static int
zz_setuid(uid_t uid)
{
        IF_PC_FROM_WR_MEM_EXIT();

        return (orig_setuid(uid));
}

static int (*orig_seteuid)(uid_t euid);
static int
zz_seteuid(uid_t euid)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_seteuid(euid));
}

static int (*orig_setgid)(gid_t gid);
static int
zz_setgid(gid_t gid)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_setgid(gid));
}

static int (*orig_setegid)(gid_t egid);
static int
zz_setegid(gid_t egid)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_setegid(egid));
}

/*
 * PROCESS MANIPULATION
 */

static int (*orig_getpid)(void);
static int
zz_getpid(void)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_getpid());
}

static int (*orig_kill)(pid_t pid, int sig);
static int
zz_kill(pid_t pid, int sig)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_kill(pid, sig));
}

static int (*orig_fork)(void);
static int
zz_fork(void)
{
	IF_PC_FROM_WR_MEM_EXIT();

	return (orig_fork());
}

static void
zz_interpose_syscalls(void)
{
	HIJACK32(exec);
	HIJACK32(dup);
	HIJACK32(fcntl);
	HIJACK32(signal);
	HIJACK32(so_socket);
	HIJACK32(send);
	HIJACK32(sendto);
	HIJACK32(sendmsg);
	HIJACK32(recv);
	HIJACK32(recvfrom);
	HIJACK32(recvmsg);
	HIJACK32(bind);
	HIJACK32(accept);
	HIJACK32(listen);
	HIJACK32(creat);
	HIJACK32(write);
	HIJACK32(read);
	HIJACK32(chmod);
	HIJACK32(fchmod);
	HIJACK32(chroot);
	HIJACK32(chdir);
	HIJACK32(fchdir);
	HIJACK32(fchroot);
	HIJACK32(mknod);
	HIJACK32(xmknod);
	HIJACK32(mount);
	HIJACK32(link);
	HIJACK32(unlink);
	HIJACK32(munmap);
	HIJACK32(mprotect);
	HIJACK32(brk);
	HIJACK32(setuid);
	HIJACK32(seteuid);
	HIJACK32(setgid);
	HIJACK32(setegid);
	HIJACK32(getpid);
	HIJACK32(kill);
	HIJACK32(fork);
	HIJACK32(modctl);

	HIJACK32(chown);
	HIJACK32(lchown);
	HIJACK32(fchown);

	HIJACK32T(open32, open);
	/*
	orig_open32 = (int (*)()) sysent32[ SYS_open ].sy_callc;
	sysent32[ SYS_open ].sy_callc = (int64_t (*)()) zz_open32;
	*/

	HIJACK32T(mmap32, mmap);
	/*
	orig_mmap32 = (int (*)()) sysent32[ SYS_mmap ].sy_callc;
	sysent32[ SYS_mmap ].sy_callc = (int64_t (*)()) zz_mmap32;
	*/

	/* HIJACK32T(mmap3264, mmap64); */
	orig_mmap3264 = sysent32[ SYS_mmap64 ].sy_call;
	sysent32[ SYS_mmap64 ].sy_call = zz_mmap3264;

	/*
	orig_mmap3264= (int (*)()) sysent32[ SYS_mmap64 ].sy_callc;
	sysent32[ SYS_mmap64 ].sy_callc = (int64_t (*)())zz_mmap3264;
	*/

	/* real sysent table hijacking */
	HIJACK64(exec);
	HIJACK64(dup);
	HIJACK64(fcntl);
	HIJACK64(signal);
	HIJACK64(so_socket);
	HIJACK64(send);
	HIJACK64(sendto);
	HIJACK64(sendmsg);
	HIJACK64(recv);
	HIJACK64(recvfrom);
	HIJACK64(recvmsg);
	HIJACK64(bind);
	HIJACK64(accept);
	HIJACK64(listen);
	HIJACK64(creat);
	HIJACK64(write);
	HIJACK64(read);
	HIJACK64(chmod);
	HIJACK64(fchmod);
	HIJACK64(chroot);
	HIJACK64(chdir);
	HIJACK64(fchdir);
	HIJACK64(fchroot);
	HIJACK64(mknod);
	HIJACK64(xmknod);
	HIJACK64(mount);
	HIJACK64(link);
	HIJACK64(unlink);
	HIJACK64(munmap);
	HIJACK64(mprotect);
	HIJACK64(brk);
	HIJACK64(setuid);
	HIJACK64(seteuid);
	HIJACK64(setgid);
	HIJACK64(setegid);
	HIJACK64(getpid);
	HIJACK64(kill);
	HIJACK64(fork);
	HIJACK64(modctl);

	HIJACK64T(open64, open);
	/*
	orig_open64 = (int (*)()) sysent[ SYS_open ].sy_callc;
	sysent[ SYS_open ].sy_callc = (int64_t (*)()) zz_open64;
	*/

	HIJACK64T(mmap64, mmap);
	/*
	orig_mmap64 = (int (*)()) sysent[ SYS_mmap ].sy_callc;
	sysent[ SYS_mmap ].sy_callc = (int64_t (*)()) zz_mmap64;
	*/

	HIJACK64(chown);
	HIJACK64(lchown);
	HIJACK64(fchown);

	orig_exit = (void (*)()) sysent[ SYS_exit ].sy_callc;
}

static void
zz_retrieve_syscalls(void)
{
	RELEASE32(exec);
	RELEASE32(dup);
	RELEASE32(fcntl);
	RELEASE32(signal);
	RELEASE32(so_socket);
	RELEASE32(send);
	RELEASE32(sendto);
	RELEASE32(sendmsg);
	RELEASE32(recv);
	RELEASE32(recvfrom);
	RELEASE32(recvmsg);
	RELEASE32(bind);
	RELEASE32(accept);
	RELEASE32(listen);
	RELEASE32(creat);
	RELEASE32(write);
	RELEASE32(read);
	RELEASE32(chmod);
	RELEASE32(fchmod);
	RELEASE32(chroot);
	RELEASE32(chdir);
	RELEASE32(fchdir);
	RELEASE32(fchroot);
	RELEASE32(mknod);
	RELEASE32(xmknod);
	RELEASE32(mount);
	RELEASE32(link);
	RELEASE32(unlink);
	RELEASE32(munmap);
	RELEASE32(mprotect);
	RELEASE32(brk);
	RELEASE32(setuid);
	RELEASE32(seteuid);
	RELEASE32(setgid);
	RELEASE32(setegid);
	RELEASE32(getpid);
	RELEASE32(kill);
	RELEASE32(fork);
	RELEASE32(modctl);

	RELEASE32(chown);
	RELEASE32(lchown);
	RELEASE32(fchown);

	RELEASE32T(open32, open);
	RELEASE32(open64);
	RELEASE32T(mmap32, mmap);

	/* RELEASE32T(mmap3264, mmap64); */
	sysent32[ SYS_mmap64 ].sy_call = orig_mmap3264;

	/*
	sysent32[ SYS_open ].sy_callc = (int64_t (*)()) orig_open32;
	sysent32[ SYS_open64 ].sy_callc = (int64_t (*)()) orig_open64;
	sysent32[ SYS_mmap ].sy_callc = (int64_t (*)())orig_mmap32;
	sysent32[ SYS_mmap64 ].sy_callc = (int64_t (*)())orig_mmap3264;
	*/

	/* release 64bit codes */
	RELEASE64(exec);
	RELEASE64(dup);
	RELEASE64(fcntl);
	RELEASE64(signal);
	RELEASE64(so_socket);
	RELEASE64(send);
	RELEASE64(sendto);
	RELEASE64(sendmsg);
	RELEASE64(recv);
	RELEASE64(recvfrom);
	RELEASE64(recvmsg);
	RELEASE64(bind);
	RELEASE64(accept);
	RELEASE64(listen);
	RELEASE64(creat);
	RELEASE64(write);
	RELEASE64(read);
	RELEASE64(chmod);
	RELEASE64(fchmod);
	RELEASE64(chroot);
	RELEASE64(chdir);
	RELEASE64(fchdir);
	RELEASE64(fchroot);
	RELEASE64(mknod);
	RELEASE64(xmknod);
	RELEASE64(mount);
	RELEASE64(link);
	RELEASE64(unlink);
	RELEASE64(munmap);
	RELEASE64(mprotect);
	RELEASE64(brk);
	RELEASE64(setuid);
	RELEASE64(seteuid);
	RELEASE64(setgid);
	RELEASE64(setegid);
	RELEASE64(getpid);
	RELEASE64(kill);
	RELEASE64(fork);
	RELEASE64(modctl);

	RELEASE64T(open64, open);
	RELEASE64T(mmap64, mmap);
	/*
	sysent[ SYS_open ].sy_callc = (int64_t (*)())orig_open64;
	sysent[ SYS_mmap ].sy_callc = (int64_t (*)())orig_mmap;
	*/

	RELEASE64(chown);
	RELEASE64(lchown);
	RELEASE64(fchown);
}

static int
memcheck_init(unsigned int id)
{
	zz_interpose_syscalls();

	return (0);
}

static int
memcheck_fini(void)
{
	zz_retrieve_syscalls();
	return (0);
}
